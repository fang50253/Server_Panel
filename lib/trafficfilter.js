'use strict';

/**
 * Firewall-level traffic filter.
 *
 * The panel lets an operator write an ordered list of rules. A rule matches a
 * source (one IP, one CIDR, or a country from the ipdeny zone files) on a set
 * of destination ports and gives a terminal verdict: `block` or `allow`. The
 * list is rendered into its own nftables table and evaluated top to bottom, so
 * the first matching rule wins.
 *
 * Scope: the rule's port set decides what is matched. Presets cover the common
 * services (HTTP/HTTPS, SSH, mail, …); "all" drops the port match entirely and
 * answers for every protocol; the custom field accepts a port list, port
 * ranges, or a regular expression over the decimal port number (expanded to
 * ranges here, because nft has no regex). Port rules match both TCP and UDP so
 * QUIC/HTTP-3 cannot slip past a plain "HTTPS" block.
 *
 * Enforcement happens in the kernel (not nginx). Safety model: the chain has
 * `policy accept`, so an empty rule list changes nothing, and `block` rules are
 * refused upstream if they would cover a protected/known/self/client address —
 * see server.js. This module stays pure (except nft calls) so ordering, parsing
 * and regex expansion can be unit tested without a firewall.
 */

const net = require('net');
const { spawn } = require('child_process');

const TABLE = 'traffic_filter';
const DEFAULT_PORT_SPEC = '80,443';
const MAX_RULES = 200;
// Refuse absurdly broad ranges. /0 is "block everyone" and /1-/7 are close
// enough that a typo would take the whole site down.
const MIN_PREFIX_V4 = 8;
const MIN_PREFIX_V6 = 16;
// A regex over 65535 port strings is cheap to evaluate once; a 100-char cap keeps
// a hostile pattern from being a problem at all.
const MAX_PORT_SPEC_LEN = 100;
// Merge limit: an adversarial regex can yield tens of thousands of 1-port
// ranges. nft would accept it but the ruleset becomes huge, so refuse.
const MAX_PORT_RANGES = 2048;

const ACTIONS = ['block', 'allow'];
const TYPES = ['ip', 'cidr', 'country'];

/* ----------------------------------------------------------------- helpers */

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

function intToIpv4(n) {
  return [24, 16, 8, 0].map((shift) => (n >>> shift) & 255).join('.');
}

/** Expand an IPv6 address to a 128-bit BigInt. Returns null when invalid. */
function ipv6ToBigInt(raw) {
  const ip = String(raw || '').trim().toLowerCase().split('%')[0];
  if (!net.isIPv6(ip)) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (fill < 0) return null;
  const groups = [...left, ...Array(fill).fill('0'), ...right];
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  return value;
}

/** Uncompressed IPv6 form; nft accepts it, and it sorts/dedupes predictably. */
function bigIntToIpv6(value) {
  const groups = [];
  for (let i = 7; i >= 0; i -= 1) {
    groups.push(((value >> BigInt(i * 16)) & 0xffffn).toString(16).padStart(4, '0'));
  }
  return groups.join(':');
}

/**
 * Parse and normalise a CIDR. Host bits are cleared, so 1.2.3.4/24 becomes
 * 1.2.3.0/24 instead of silently speaking about a different network.
 */
function parseCidr(raw) {
  const text = String(raw || '').trim();
  const slash = text.lastIndexOf('/');
  if (slash <= 0) return null;
  const addr = text.slice(0, slash).trim();
  const bitsText = text.slice(slash + 1).trim();
  if (!/^\d{1,3}$/.test(bitsText)) return null;
  const bits = Number(bitsText);

  if (net.isIPv4(addr)) {
    if (bits > 32) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const network = (ipv4ToInt(addr) & mask) >>> 0;
    const size = 2 ** (32 - bits);
    return {
      family: 4,
      bits,
      cidr: `${intToIpv4(network)}/${bits}`,
      start: network,
      end: network + size - 1,
      value: network,
    };
  }

  if (net.isIPv6(addr)) {
    if (bits > 128) return null;
    const value = ipv6ToBigInt(addr);
    if (value === null) return null;
    const hostBits = BigInt(128 - bits);
    const hostMask = hostBits === 128n ? (1n << 128n) - 1n : (1n << hostBits) - 1n;
    const network = value & ~hostMask;
    return {
      family: 6,
      bits,
      cidr: `${bigIntToIpv6(network)}/${bits}`,
      start: network,
      end: network + hostMask,
      value: network,
    };
  }

  return null;
}

/** True when `ip` falls inside the parsed CIDR. */
function cidrContains(cidr, ip) {
  const clean = String(ip || '').trim();
  if (cidr.family === 4) {
    if (!net.isIPv4(clean)) return false;
    const n = ipv4ToInt(clean);
    return n >= Number(cidr.start) && n <= Number(cidr.end);
  }
  if (!net.isIPv6(clean)) return false;
  const n = ipv6ToBigInt(clean);
  return n !== null && n >= cidr.start && n <= cidr.end;
}

function normalizePriority(value, fallback = 100) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(100000, Math.max(1, Math.round(n)));
}

/* ------------------------------------------------------- cidr set algebra */

// Ports whose answer nginx can produce (404 / redirect) instead of a silent
// drop. `webAnswer` in buildRuleset takes 80/443 out of the nft match so the
// packet survives long enough for nginx to reply.
const WEB_PORTS = [80, 443];
const MODES = ['drop', '404', 'redirect'];
const FAILED_URL = 'https://blocked.example.com/';

const V4_ALL = 0xffffffff;

function one(value) {
  return typeof value === 'bigint' ? 1n : 1;
}

/** Parse a CIDR or a bare address into `{ family, start, end }`. */
function cidrRange(text) {
  const clean = String(text == null ? '' : text).trim();
  const parsed = parseCidr(clean);
  if (parsed) return { family: parsed.family, start: parsed.start, end: parsed.end };
  if (net.isIPv4(clean)) {
    const n = ipv4ToInt(clean);
    return { family: 4, start: n, end: n };
  }
  if (net.isIPv6(clean)) {
    const n = ipv6ToBigInt(clean);
    return n === null ? null : { family: 6, start: n, end: n };
  }
  return null;
}

/** Sort and coalesce `[start, end]` ranges. Adjacent ranges are merged. */
function mergeRangeList(list) {
  const sorted = list
    .filter(Boolean)
    .map(([a, b]) => [a, b])
    .sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
  const out = [];
  for (const [a, b] of sorted) {
    const last = out[out.length - 1];
    if (last && a <= last[1] + one(last[1])) {
      if (b > last[1]) last[1] = b;
    } else {
      out.push([a, b]);
    }
  }
  return out;
}

/** `base - remove`, both merged range lists. */
function subtractRangeList(base, remove) {
  let result = base;
  for (const [ra, rb] of remove) {
    if (!result.length) break;
    const next = [];
    for (const [ba, bb] of result) {
      if (rb < ba || ra > bb) { // no overlap
        next.push([ba, bb]);
        continue;
      }
      if (ra > ba) next.push([ba, ra - one(ra)]);
      if (rb < bb) next.push([rb + one(rb), bb]);
    }
    result = next;
  }
  return result;
}

/**
 * Split a range into the fewest CIDRs that cover exactly it.
 *
 * `start`/`end` are numbers for IPv4 and BigInts for IPv6. Greedy: at each step
 * take the largest aligned block that still fits, which is the classic optimal
 * range-to-prefix decomposition.
 */
function rangeToPrefixes(start, end, family) {
  const out = [];
  let s = start;
  const last = end;
  while (s <= last) {
    if (family === 4) {
      const low = s === 0 ? 4294967296 : (s & -s);
      const fit = last - s + 1;
      let size = 1;
      while (size * 2 <= low && size * 2 <= fit) size *= 2;
      out.push(`${intToIpv4(s)}/${32 - Math.log2(size)}`);
      s += size;
    } else {
      let low = 1n;
      if (s === 0n) {
        low = 1n << 128n;
      } else {
        let probe = s;
        while ((probe & 1n) === 0n) { low <<= 1n; probe >>= 1n; }
      }
      const fit = last - s + 1n;
      let size = 1n;
      while (size * 2n <= low && size * 2n <= fit) size *= 2n;
      let bits = 128;
      let probe = size;
      while (probe > 1n) { probe >>= 1n; bits -= 1; }
      out.push(`${bigIntToIpv6(s)}/${bits}`);
      s += size;
    }
  }
  return out;
}

/** CIDR strings -> merged ranges of one family. */
function cidrsToRanges(cidrs, family) {
  return mergeRangeList(
    (cidrs || [])
      .map(cidrRange)
      .filter((r) => r && r.family === family)
      .map((r) => [r.start, r.end]),
  );
}

/** Ranges -> CIDR strings, still without merging redundant neighbours. */
function rangesToCidrs(ranges, family) {
  const out = [];
  for (const [a, b] of ranges) out.push(...rangeToPrefixes(a, b, family));
  return out;
}

/** Does the rule's port selector include `port`? */
function ruleMatchesPort(rule, port) {
  const spec = normalizePortSpec(rule.port === undefined ? DEFAULT_PORT_SPEC : rule.port);
  if (spec.all) return true;
  return spec.ranges.some(([a, b]) => port >= a && port <= b);
}

/**
 * Flat "blocked on this port" CIDR list for nginx.
 *
 * nginx has no rule order, so the ordered rule list has to be collapsed into
 * one set. Walk the rules top to bottom: an `allow` records its addresses, a
 * later `block` adds only what no earlier allow claimed, and an `allow` after a
 * block cannot undo it (first match wins). Exempt addresses are removed last —
 * they are accepted before the chain in nft and must stay reachable here too.
 */
function webBlockCidrs(rules, zoneFor, { port, exempt = null } = {}) {
  const active = sortRules((rules || []).filter((r) => r && r.enabled !== false));
  const result = { v4: [], v6: [] };

  for (const family of [4, 6]) {
    let blocked = [];
    let allowed = [];
    for (const rule of active) {
      if (!ruleMatchesPort(rule, port)) continue;
      const elems = ruleElements(rule, zoneFor);
      const ranges = cidrsToRanges(family === 4 ? elems.v4 : elems.v6, family);
      if (!ranges.length) continue;
      if (rule.action === 'block') {
        blocked = mergeRangeList([...blocked, ...subtractRangeList(ranges, allowed)]);
      } else {
        allowed = mergeRangeList([...allowed, ...ranges]);
      }
    }

    const exemptRanges = cidrsToRanges(
      family === 4 ? (exempt && exempt.v4) || [] : (exempt && exempt.v6) || [],
      family,
    );
    blocked = subtractRangeList(blocked, exemptRanges);
    result[family === 4 ? 'v4' : 'v6'] = rangesToCidrs(blocked, family);
  }

  return result;
}

/** Both web ports, as `{ '80': {v4,v6}, '443': {v4,v6} }`. */
function webBlockList(rules, zoneFor, { exempt = null } = {}) {
  const out = {};
  for (const port of WEB_PORTS) out[String(port)] = webBlockCidrs(rules, zoneFor, { port, exempt });
  return out;
}

/**
 * Addresses whose first matching web rule is `allow`.
 *
 * The nginx tree also uses Cloudflare's country header as a fallback for
 * addresses missing from the ipdeny zone. That fallback must not override an
 * explicit allow rule, so these addresses are added to the nginx exemption
 * map. They are not blanket exemptions: an earlier block still wins, exactly
 * like the nft chain.
 */
function webAllowCidrs(rules, zoneFor, { port } = {}) {
  const active = sortRules((rules || []).filter((r) => r && r.enabled !== false));
  const result = { v4: [], v6: [] };

  for (const family of [4, 6]) {
    let blocked = [];
    let allowed = [];
    for (const rule of active) {
      if (!ruleMatchesPort(rule, port)) continue;
      const elems = ruleElements(rule, zoneFor);
      const ranges = cidrsToRanges(family === 4 ? elems.v4 : elems.v6, family);
      if (!ranges.length) continue;
      if (rule.action === 'block') {
        blocked = mergeRangeList([...blocked, ...subtractRangeList(ranges, allowed)]);
      } else {
        allowed = mergeRangeList([...allowed, ...ranges]);
      }
    }
    const effective = subtractRangeList(allowed, blocked);
    result[family === 4 ? 'v4' : 'v6'] = rangesToCidrs(effective, family);
  }

  return result;
}

/** Both web ports, same shape as webBlockList, for allow rules. */
function webAllowList(rules, zoneFor) {
  const out = {};
  for (const port of WEB_PORTS) out[String(port)] = webAllowCidrs(rules, zoneFor, { port });
  return out;
}

/* ------------------------------------------------------------------- ports */

/** Sort and coalesce [start, end] pairs; adjacent ranges are merged. */
function mergeRanges(list) {
  const sorted = list.map(([a, b]) => [a, b]).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const out = [];
  for (const [a, b] of sorted) {
    const last = out[out.length - 1];
    if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
    else out.push([a, b]);
  }
  return out;
}

/** nft set literal for a port range list: `{ 80, 443, 8000-8100 }`. */
function formatRangeSet(ranges) {
  return `{ ${ranges.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(', ')} }`;
}

function formatRanges(ranges) {
  return ranges.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(',');
}

/** Parse `80,443 53 8000-8100` into ranges. Returns null if malformed. */
function parsePlainPorts(text) {
  const tokens = String(text || '').split(/[\s,，]+/).filter(Boolean);
  if (!tokens.length) return null;
  const ranges = [];
  for (const tok of tokens) {
    let m = /^(\d{1,5})$/.exec(tok);
    if (m) {
      const p = Number(m[1]);
      if (p < 1 || p > 65535) return null;
      ranges.push([p, p]);
      continue;
    }
    m = /^(\d{1,5})-(\d{1,5})$/.exec(tok);
    if (m) {
      const a = Number(m[1]);
      const b = Number(m[2]);
      if (a < 1 || b > 65535 || a > b) return null;
      ranges.push([a, b]);
      continue;
    }
    return null;
  }
  return ranges;
}

/**
 * Expand a regex over the decimal port number into port ranges.
 *
 * The pattern is anchored to the whole port (`^(?:pat)$`), so `8\d{3}` means
 * 8000-8999 and not "contains 8 three digits". Enumerating 65535 short strings
 * is instant and sidesteps nft, which has no regex support.
 */
function expandRegexPorts(source) {
  let re;
  try {
    re = new RegExp(`^(?:${source})$`);
  } catch {
    return null;
  }
  const ranges = [];
  for (let p = 1; p <= 65535; p += 1) {
    if (re.test(String(p))) ranges.push([p, p]);
  }
  return ranges.length ? mergeRanges(ranges) : null;
}

/**
 * Normalise the port selector of a rule into `{ all, spec, ranges, label }`.
 *
 * `spec` is the canonical stored form: `all`, a range list (`80,443`), or a
 * regex prefixed with `re:` (`re:8\d{3}`). `ranges` is what actually goes into
 * the nft set. Errors are user-facing Chinese with a stable `code`.
 */
function normalizePortSpec(raw) {
  const text = String(raw == null ? '' : raw).trim();
  if (!text) throw ruleError('empty_ports', '请填写要匹配的端口');
  if (text.toLowerCase() === 'all' || text === '*') {
    return { all: true, spec: 'all', ranges: [], label: '所有端口 / 所有协议' };
  }

  const lower = text.toLowerCase();
  const plain = /^[0-9,\-\s，]+$/.test(text);
  const isRegex = lower.startsWith('re:') || !plain;
  const source = lower.startsWith('re:') ? text.slice(3).trim() : text;

  let ranges;
  if (isRegex) {
    if (!source) throw ruleError('empty_ports', '请填写正则表达式');
    if (source.length > MAX_PORT_SPEC_LEN) {
      throw ruleError('ports_too_long', `正则太长，最多 ${MAX_PORT_SPEC_LEN} 个字符`);
    }
    ranges = expandRegexPorts(source);
    if (!ranges) throw ruleError('bad_ports', `正则「${source}」语法有误，或匹配不到任何端口`);
    if (ranges.length > MAX_PORT_RANGES) {
      throw ruleError('ports_too_fragmented', `正则命中的端口范围太碎（${ranges.length} 段），请换一种写法`);
    }
    return {
      all: false,
      spec: `re:${source}`,
      ranges,
      label: `正则 /${source}/ → ${formatRanges(ranges)}`,
    };
  }

  const parsed = parsePlainPorts(text);
  if (!parsed) throw ruleError('bad_ports', `「${text}」不是合法端口，请写成 80,443 或 8000-8100`);
  ranges = mergeRanges(parsed);
  return { all: false, spec: formatRanges(ranges), ranges, label: formatRanges(ranges) };
}

/**
 * Coerce user input into a valid rule, or throw a message the panel can show.
 *
 * The thrown errors are the whole validation surface for API clients, so they
 * are written as user-facing Chinese with a stable `code`.
 */
function normalizeRule(input = {}, { id = null } = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const type = TYPES.includes(src.type) ? src.type : 'ip';
  const action = ACTIONS.includes(src.action) ? src.action : 'block';
  const value = String(src.value == null ? '' : src.value).trim();
  const enabled = src.enabled === undefined ? true : Boolean(src.enabled);
  const priority = normalizePriority(src.priority);
  const ruleId = id || (typeof src.id === 'string' && src.id) || null;
  const port = normalizePortSpec(src.port === undefined ? DEFAULT_PORT_SPEC : src.port);

  if (!value) throw ruleError('empty_value', '请填写要匹配的 IP、IP 段或国家/地区');

  if (type === 'ip') {
    const clean = value.toLowerCase().startsWith('::ffff:') ? value.slice(7) : value;
    if (!net.isIPv4(clean) && !net.isIPv6(clean)) {
      throw ruleError('bad_ip', `「${value}」不是合法 IP`);
    }
    return { id: ruleId, type, value: clean, action, priority, enabled, port: port.spec, portLabel: port.label };
  }

  if (type === 'cidr') {
    const parsed = parseCidr(value);
    if (!parsed) throw ruleError('bad_cidr', `「${value}」不是合法 IP 段，请写成 1.2.3.0/24 这样`);
    const min = parsed.family === 4 ? MIN_PREFIX_V4 : MIN_PREFIX_V6;
    if (parsed.bits < min) {
      throw ruleError(
        'cidr_too_broad',
        `IP 段范围太大（/${parsed.bits}），最宽只允许 IPv4 /${MIN_PREFIX_V4}、IPv6 /${MIN_PREFIX_V6}`,
      );
    }
    return { id: ruleId, type, value: parsed.cidr, action, priority, enabled, port: port.spec, portLabel: port.label };
  }

  const cc = value.toLowerCase();
  if (!/^[a-z]{2}$/.test(cc)) {
    throw ruleError('bad_country', `「${value}」不是两位的国家/地区代码`);
  }
  return { id: ruleId, type, value: cc, action, priority, enabled, port: port.spec, portLabel: port.label };
}

function ruleError(code, message) {
  const err = new Error(message);
  err.code = code;
  err.status = 400;
  return err;
}

function sortRules(rules) {
  // Stable ordering: priority first, then the order the operator created them.
  return rules
    .map((rule, index) => ({ rule, index }))
    .sort((a, b) => a.rule.priority - b.rule.priority || a.index - b.index)
    .map((entry) => entry.rule);
}

/**
 * The CIDRs one rule expands to, split by family.
 *
 * `zoneFor(cc)` returns `{ v4: [], v6: [] }` from the cached ipdeny files; the
 * caller fetches when the cache is cold. Country rules are the only ones that
 * can span both families.
 */
function ruleElements(rule, zoneFor) {
  if (rule.type === 'country') {
    const zone = zoneFor(rule.value);
    if (!zone || (!zone.v4.length && !zone.v6.length)) {
      throw ruleError('zone_missing', `没有 ${rule.value} 的国家/地区网段数据`);
    }
    return { v4: zone.v4.slice(), v6: zone.v6.slice() };
  }
  const single = rule.type === 'cidr' ? parseCidr(rule.value) : null;
  if (single) {
    return single.family === 4 ? { v4: [single.cidr], v6: [] } : { v4: [], v6: [single.cidr] };
  }
  return net.isIPv6(rule.value) ? { v4: [], v6: [rule.value] } : { v4: [rule.value], v6: [] };
}

/**
 * Render the whole ordered rule list into one nft transaction.
 *
 * Every rule gets its own set (country rules hold thousands of ranges, so one
 * rule per CIDR would be unusable). The chain has `policy accept`, and both
 * verdicts are terminal in a filter chain — so "first matching rule wins" is
 * exactly how the rules are written out.
 */
function buildRuleset(rules, zoneFor, { table = TABLE, exempt = null, webAnswer = null } = {}) {
  const active = sortRules(rules.filter((r) => r && r.enabled !== false));
  if (!active.length) {
    throw ruleError('no_rules', '没有启用的规则');
  }
  if (active.length > MAX_RULES) {
    throw ruleError('too_many_rules', `规则最多 ${MAX_RULES} 条`);
  }

  const sets = [];
  const exemptChain = [];
  const ruleChain = [];

  // Ports nginx answers for. Removing them from the nft match is what turns a
  // silent drop into a 404/redirect: the packet must reach the web server.
  const strip = Array.isArray(webAnswer) ? webAnswer.filter((p) => Number.isInteger(p)) : [];

  // Antilockout: addresses we must always stay reachable from get an `accept`
  // at the very top of the chain, so no later `drop` can ever match them. This
  // is what makes a "block a whole country" rule safe even when the operator
  // lives in that country. Only worth emitting when something can drop.
  const exemptV4 = exempt && Array.isArray(exempt.v4) ? [...new Set(exempt.v4)] : [];
  const exemptV6 = exempt && Array.isArray(exempt.v6) ? [...new Set(exempt.v6)] : [];
  const hasBlock = active.some((r) => r.action === 'block');
  if (hasBlock && exemptV4.length) {
    sets.push(setBlock('exemptv4', 'ipv4_addr', exemptV4));
    exemptChain.push('\t\tip  saddr @exemptv4 counter accept');
  }
  if (hasBlock && exemptV6.length) {
    sets.push(setBlock('exemptv6', 'ipv6_addr', exemptV6));
    exemptChain.push('\t\tip6 saddr @exemptv6 counter accept');
  }

  active.forEach((rule, index) => {
    const { v4, v6 } = ruleElements(rule, zoneFor);
    if (!v4.length && !v6.length) throw ruleError('empty_match', '规则没有匹配到任何网段');

    // Resolve the port selector once per rule. `all` means no l4 match at all;
    // otherwise the rule answers for both TCP and UDP so a UDP-only protocol
    // (QUIC on 443, DNS on 53) cannot slip past.
    const port = normalizePortSpec(rule.port === undefined ? DEFAULT_PORT_SPEC : rule.port);
    const isAll = port.all;
    const ranges = strip.length
      ? subtractPortRanges(isAll ? [[1, 65535]] : port.ranges, strip)
      : port.ranges;

    // A rule that only covered 80/443 is now entirely nginx's business; if it
    // is the only rule, buildRuleset returns null and the caller removes the
    // table instead of installing an empty chain.
    if (!isAll && !ranges.length) return;

    const verdict = rule.action === 'allow' ? 'accept' : 'drop';
    const portMatch = isAll
      ? ''
      : `meta l4proto { tcp, udp } th dport ${formatRangeSet(ranges)} `;

    // nft set names are identifiers: letters, digits, underscore only.
    const base = `w${index}`;
    const emit = (family, set) => {
      sets.push(setBlock(set, family === 4 ? 'ipv4_addr' : 'ipv6_addr', family === 4 ? v4 : v6));
      const proto = family === 4 ? 'ip ' : 'ip6';
      if (strip.length && isAll) {
        // "All ports" must still cover ICMP and friends, which have no port.
        // Only the TCP/UDP part loses 80/443 to nginx.
        ruleChain.push(`\t\tmeta l4proto != { tcp, udp } ${proto} saddr @${set} counter ${verdict}`);
        ruleChain.push(`\t\tmeta l4proto { tcp, udp } th dport ${formatRangeSet(ranges)} ${proto} saddr @${set} counter ${verdict}`);
      } else {
        ruleChain.push(`\t\t${portMatch}${proto} saddr @${set} counter ${verdict}`);
      }
    };
    if (v4.length) emit(4, `${base}v4`);
    if (v6.length) emit(6, `${base}v6`);
  });

  if (!ruleChain.length) return null;

  return `add table inet ${table}
delete table inet ${table}
table inet ${table} {
${sets.join('\n')}
	chain filter {
		type filter hook input priority 10; policy accept;
${[...exemptChain, ...ruleChain].join('\n')}
	}
}
`;
}

/** Remove individual ports from a merged range list. */
function subtractPortRanges(ranges, ports) {
  let result = ranges;
  for (const port of ports) {
    const next = [];
    for (const [a, b] of result) {
      if (port < a || port > b) { next.push([a, b]); continue; }
      if (port > a) next.push([a, port - 1]);
      if (port < b) next.push([port + 1, b]);
    }
    result = next;
  }
  return mergeRanges(result);
}

function setBlock(name, type, items) {
  const unique = [...new Set(items)].sort();
  return `\tset ${name} {
\t\ttype ${type}
\t\tflags interval
\t\tauto-merge
\t\telements = {
${unique.map((cidr) => `\t\t\t${cidr},`).join('\n').replace(/,$/, '')}
\t\t}
\t}`;
}

/* -------------------------------------------------------------------- nft */

function nft(args, { timeoutMs = 15000, stdin = '' } = {}) {
  return new Promise((resolve) => {
    const child = spawn('nft', args, {
      stdio: [stdin ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      timeout: timeoutMs,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('error', (err) => resolve({ ok: false, stdout, stderr: String(err.message), error: err }));
    child.on('close', (code) => {
      resolve({ ok: code === 0, stdout, stderr, error: code === 0 ? null : new Error(stderr.trim()) });
    });
    if (stdin) child.stdin.end(stdin);
  });
}

/** Validate a rendered ruleset without touching the live table. */
async function check(ruleset) {
  return nft(['-c', '-f', '-'], { stdin: ruleset });
}

/** Install a rendered ruleset atomically (add + delete + rebuild in one go). */
async function apply(ruleset, table = TABLE) {
  return nft(['-f', '-'], { stdin: ruleset });
}

/** Remove the filter entirely (the panel switch, or no enabled rules). */
async function removeTable(table = TABLE) {
  const res = await nft(['delete', 'table', 'inet', table]);
  if (!res.ok && /does not exist|No such file/i.test(res.stderr)) return { ok: true, removed: false };
  return { ...res, removed: res.ok };
}

/**
 * Live state of the table: set sizes and how many packets each verdict took.
 * Counters are anonymous, so they are attributed by the verdict expression
 * that follows them in the same rule.
 */
async function tableStatus(table = TABLE) {
  const res = await nft(['-j', 'list', 'table', 'inet', table]);
  if (!res.ok) {
    if (/does not exist|No such file/i.test(res.stderr)) return { ok: true, active: false };
    return { ok: false, error: res.stderr.trim() };
  }
  let doc;
  try {
    doc = JSON.parse(res.stdout);
  } catch {
    return { ok: false, error: 'cannot parse nft json' };
  }

  const status = {
    ok: true,
    active: true,
    v4Count: 0,
    v6Count: 0,
    dropRules: 0,
    allowRules: 0,
    exemptRules: 0,
    droppedPackets: 0,
    allowedPackets: 0,
    exemptPackets: 0,
  };
  for (const node of (doc && doc.nftables) || []) {
    const set = node.set;
    if (set && Array.isArray(set.elem)) {
      // The antilockout set is not a rule set; keep it out of the range totals.
      if (set.name === 'exemptv4') continue;
      if (set.name === 'exemptv6') continue;
      if (set.name.endsWith('v4')) status.v4Count += set.elem.length;
      if (set.name.endsWith('v6')) status.v6Count += set.elem.length;
    }
    const exprs = node.rule && Array.isArray(node.rule.expr) ? node.rule.expr : null;
    if (!exprs) continue;
    let verdict = null;
    let packets = 0;
    for (const e of exprs) {
      if (e && e.counter) packets += Number(e.counter.pkts || 0);
      if (e && e.drop) verdict = 'drop';
      if (e && e.accept) verdict = 'accept';
    }
    // Rule expressions reference their match set by name; the antilockout
    // accepts are counter-only noise in the "放行" total, so keep them apart.
    const isExempt = JSON.stringify(exprs).includes('@exemptv');
    if (verdict === 'drop') {
      status.dropRules += 1;
      status.droppedPackets += packets;
    } else if (verdict === 'accept' && isExempt) {
      status.exemptRules += 1;
      status.exemptPackets += packets;
    } else if (verdict === 'accept') {
      status.allowRules += 1;
      status.allowedPackets += packets;
    }
  }
  return status;
}

module.exports = {
  TABLE,
  DEFAULT_PORT_SPEC,
  MAX_RULES,
  MAX_PORT_SPEC_LEN,
  MAX_PORT_RANGES,
  MIN_PREFIX_V4,
  MIN_PREFIX_V6,
  WEB_PORTS,
  MODES,
  FAILED_URL,
  ACTIONS,
  TYPES,
  ipv4ToInt,
  intToIpv4,
  ipv6ToBigInt,
  bigIntToIpv6,
  parseCidr,
  cidrContains,
  normalizePriority,
  cidrRange,
  mergeRangeList,
  subtractRangeList,
  rangeToPrefixes,
  cidrsToRanges,
  rangesToCidrs,
  ruleMatchesPort,
  webBlockCidrs,
  webBlockList,
  webAllowCidrs,
  webAllowList,
  mergeRanges,
  formatRangeSet,
  formatRanges,
  parsePlainPorts,
  expandRegexPorts,
  normalizePortSpec,
  subtractPortRanges,
  normalizeRule,
  sortRules,
  ruleElements,
  buildRuleset,
  check,
  apply,
  removeTable,
  tableStatus,
};
