'use strict';

/**
 * Manual SSH blocking via nftables.
 *
 * The box had no firewall at all when this was added, so the rule set is
 * deliberately tiny and additive: it can only *drop* traffic to one port from
 * IPs an operator explicitly listed. Nothing else is filtered, so adding this
 * feature cannot change how any existing site or service behaves.
 *
 * The safety model matters more than the mechanism. Locking yourself out of
 * SSH on a box that is only reachable over SSH is unrecoverable without a
 * console, so `evaluateBlockRequest` refuses every dangerous target, and it is
 * a pure function so the refusals are unit tested rather than trusted.
 */

const { execFile, spawn } = require('child_process');
const net = require('net');

const TABLE = 'monitor_block';
const SET4 = 'ssh4';
const SET6 = 'ssh6';
const SSH_PORTS = [22];

/**
 * IPv4 ranges that must never be blocked. Blocking a private/loopback range
 * would either do nothing useful or cut local health checks and the host's own
 * `127.0.0.1` traffic.
 */
const V4_BLOCKED_RANGES = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16],
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
];

function v4ToInt(ip) {
  return ip.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

function inV4Range(ip, base, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(base) & mask);
}

/** Strip IPv6 wrap and the `::ffff:` IPv4-mapped prefix journald/ss may emit. */
function normalizeIp(raw) {
  let ip = String(raw || '').trim();
  ip = ip.replace(/^\[|\]$/g, '');
  if (ip.toLowerCase().startsWith('::ffff:') && net.isIPv4(ip.slice(7))) return ip.slice(7);
  return ip;
}

/**
 * True only for addresses that are meaningful to block: globally routable
 * unicast. Used both for validation and to keep the UI honest.
 */
function isPublicIp(raw) {
  const ip = normalizeIp(raw);
  if (net.isIPv4(ip)) {
    if (V4_BLOCKED_RANGES.some(([base, bits]) => inV4Range(ip, base, bits))) return false;
    return true;
  }
  if (net.isIPv6(ip)) {
    const low = ip.toLowerCase();
    if (low === '::' || low === '::1') return false;
    if (low.startsWith('fe8') || low.startsWith('fe9') || low.startsWith('fea') || low.startsWith('feb')) return false; // link-local
    if (low.startsWith('fc') || low.startsWith('fd')) return false; // unique local
    if (/^ff/.test(low)) return false; // multicast
    if (low.startsWith('2001:db8')) return false; // documentation
    if (low.startsWith('64:ff9b')) return false; // NAT64
    return true;
  }
  return false;
}

/**
 * Decide whether an IP may be blocked.
 *
 * Every rule here exists to prevent a specific way of losing SSH access:
 *
 *   invalid        — not an address, nothing to block
 *   not_public     — private/loopback/reserved; blocking it is wrong or useless
 *   self           — the server's own address
 *   protected      — explicitly allowlisted (for example an admin's fixed IP)
 *   no_failures    — "没有登录失败过的 IP 不允许封锁"
 *   has_logged_in  — it has a successful login: that is how you got in, so
 *                    blocking it is how you lock yourself out
 *   active_session — someone is *logged in* from it right now (an established
 *                    TCP connection still in preauth does NOT count: a
 *                    brute-force attempt is not a session, and treating it as
 *                    one made active attackers impossible to block)
 *   already_blocked
 *
 * @param {object} input
 * @param {string} input.ip
 * @param {object} input.failures       ip -> {count, ...} from ssh-failures.json
 * @param {object} input.knownIps       ip -> {...} from known-ips.json
 * @param {string[]} [input.protectedIps] always refused
 * @param {string[]} [input.activeIps]  peers with an authenticated session now
 * @param {string[]} [input.selfIps]    this host's own addresses
 * @param {string[]} [input.blockedIps] already in the nft set
 * @returns {{ok: true} | {ok: false, code: string, reason: string}}
 */
function evaluateBlockRequest({
  ip: raw,
  failures = {},
  knownIps = {},
  protectedIps = [],
  activeIps = [],
  selfIps = [],
  blockedIps = [],
} = {}) {
  const ip = normalizeIp(raw);

  if (!ip) return { ok: false, code: 'no_ip', reason: '没有提供 IP' };
  if (!net.isIP(ip)) return { ok: false, code: 'invalid_ip', reason: `${raw} 不是合法 IP 地址` };
  if (!isPublicIp(ip)) {
    return { ok: false, code: 'not_public', reason: `${ip} 是内网、回环或保留地址，不需要（也不应该）封锁` };
  }
  if (selfIps.map(normalizeIp).includes(ip)) {
    return { ok: false, code: 'self', reason: `${ip} 是服务器自己的地址，封锁会切断对外连接` };
  }
  if (protectedIps.map(normalizeIp).includes(ip)) {
    return { ok: false, code: 'protected', reason: `${ip} 在受保护名单里，不允许封锁` };
  }
  if (blockedIps.map(normalizeIp).includes(ip)) {
    return { ok: false, code: 'already_blocked', reason: `${ip} 已经在封锁列表中` };
  }
  if (activeIps.map(normalizeIp).includes(ip)) {
    return { ok: false, code: 'active_session', reason: `${ip} 当前有一个已登录的 SSH 会话，封锁会把它踢下线` };
  }
  if (knownIps[ip]) {
    return {
      ok: false,
      code: 'has_logged_in',
      reason: `${ip} 成功登录过（${knownIps[ip].user || '未知用户'}），封锁它可能导致你自己无法登录`,
    };
  }
  const rec = failures[ip];
  if (!rec || !rec.count) {
    return { ok: false, code: 'no_failures', reason: `${ip} 没有登录失败记录，不允许封锁` };
  }

  return { ok: true };
}

/**
 * Decide whether an IP should be blocked *automatically*.
 *
 * Different question from `evaluateBlockRequest`, and deliberately so:
 *
 * The automatic path counts failures from the **permanent history** (ip ->
 * times), not from the alerting window: the alert window can be an hour while
 * the block window is a day, and the tracker prunes to the alert window — so an
 * IP that failed 100 times over 6 hours would look innocent if we counted the
 * pruned list. The caller passes `times` explicitly so that mismatch cannot
 * happen by accident.
 *
 * Everything that protects against locking yourself out is shared, by
 * delegating to `evaluateBlockRequest`. Automation must be *more* careful than
 * a human, never less.
 *
 * @param {object} input
 * @param {string} input.ip
 * @param {number[]} input.times  every recorded failure timestamp for this IP
 * @param {number} input.count    failures needed
 * @param {number} input.windowMs how far back to look
 * @param {object} input.failures rolling-window failures, for the shared guard
 * @param {number} [input.now]
 * @returns {{ok: true, count: number} | {ok: false, code: string, reason: string}}
 */
function evaluateAutoBlock({ ip, times = [], count, windowMs, failures = {}, now = Date.now(), ...rest }) {
  if (!times || !times.length) {
    return { ok: false, code: 'no_record', reason: `${ip} 没有失败记录` };
  }

  // Count only failures inside the configured window.
  const cutoff = now - windowMs;
  const inWindow = times.filter((t) => t >= cutoff).length;

  if (inWindow < count) {
    return {
      ok: false,
      code: 'below_threshold',
      reason: `${ip} 在窗口内只有 ${inWindow} 次失败，未达到 ${count} 次`,
    };
  }

  // Same safety checks as the manual path, minus the "no failures" rule which
  // the threshold above already answers.
  const verdict = evaluateBlockRequest({ ip, failures, ...rest });
  if (verdict.ok) return { ok: true, count: inWindow };

  // The only refusal the auto path may override is "no failures", because it
  // has already proven failures exist. Every other refusal stands.
  if (verdict.code === 'no_failures') return { ok: true, count: inWindow };
  return { ok: false, code: verdict.code, reason: verdict.reason };
}

/* --------------------------------------------------------------- nft layer */

function nft(args, { timeoutMs = 10000, stdin = '' } = {}) {
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
    if (stdin) {
      child.stdin.end(stdin);
    }
  });
}

/**
 * Create the table/sets/chain if they are missing.
 *
 * Check-then-create rather than "delete then add": deleting first would leave a
 * window where an already-blocked attacker is allowed back in, and an
 * unconditional delete fails on a fresh box where the table does not exist yet.
 */
async function ensureTable() {
  const existing = await nft(['list', 'table', 'inet', TABLE]);
  if (existing.ok) return { ok: true, created: false };

  const script = `
table inet ${TABLE} {
  set ${SET4} {
    type ipv4_addr
    counter
  }
  set ${SET6} {
    type ipv6_addr
    counter
  }
  chain input {
    type filter hook input priority -10; policy accept;
    ip  saddr @${SET4} tcp dport { ${SSH_PORTS.join(', ')} } log prefix "MONITOR_BLOCK " level info counter drop
    ip6 saddr @${SET6} tcp dport { ${SSH_PORTS.join(', ')} } log prefix "MONITOR_BLOCK " level info counter drop
  }
}
`;
  const res = await nft(['-f', '-'], { stdin: script });
  return { ...res, created: res.ok };
}

/** Adds a single IP to the correct family set. */
async function addBlock(ip) {
  const clean = normalizeIp(ip);
  const set = net.isIPv6(clean) ? SET6 : SET4;
  return nft(['add', 'element', 'inet', TABLE, set, `{ ${clean} }`]);
}

async function removeBlock(ip) {
  const clean = normalizeIp(ip);
  const set = net.isIPv6(clean) ? SET6 : SET4;
  return nft(['delete', 'element', 'inet', TABLE, set, `{ ${clean} }`]);
}

/**
 * Current set contents with per-IP packet counters.
 *
 * @returns {Promise<{ok: boolean, entries: Array<{ip: string, packets: number, bytes: number}>, error?: string}>}
 */
async function listBlocked() {
  const entries = [];

  for (const set of [SET4, SET6]) {
    const res = await nft(['-j', 'list', 'set', 'inet', TABLE, set]);
    if (!res.ok) {
      // A missing table means "nothing blocked yet" for the API, but a real
      // error must not be silently reported as an empty list.
      if (/No such file or directory|does not exist/i.test(res.stderr)) continue;
      return { ok: false, entries, error: res.stderr.trim() };
    }

    let parsed;
    try {
      parsed = JSON.parse(res.stdout);
    } catch (err) {
      return { ok: false, entries, error: `bad nft json: ${err.message}` };
    }

    for (const item of parsed.nftables || []) {
      const elem = item.set && item.set.elem;
      if (!Array.isArray(elem)) continue;
      for (const raw of elem) {
        const val = raw && raw.elem;
        if (!val) continue;
        const counter = val.counter || {};
        entries.push({
          ip: normalizeIp(val.val),
          packets: Number(counter.packets || 0),
          bytes: Number(counter.bytes || 0),
        });
      }
    }
  }

  return { ok: true, entries };
}

/* ------------------------------------------------------- peer discovery */

/**
 * Established SSH peers from `ss -tn` output.
 *
 * The column count varies: `ss -tn` prints four fields, `ss -tnp` adds a
 * `users:(("sshd",...))` field that itself contains no spaces but can follow
 * either. Rather than count columns, match address tokens directly and take the
 * peer — that survives both shapes and both address families.
 */
function parseSsPeers(text) {
  const out = new Set();
  for (const line of String(text || '').split('\n')) {
    if (!line.trim() || /^Recv-Q/.test(line)) continue;

    // local and peer, e.g. "1.2.3.4:22" or "[2001:db8::1]:22"
    const matches = line.match(/(\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}):\d+/g);
    if (!matches || matches.length < 2) continue;

    const peer = matches[1];
    const ip = normalizeIp(peer.slice(0, peer.lastIndexOf(':')));
    if (net.isIP(ip)) out.add(ip);
  }
  return [...out];
}

function execFileP(cmd, args, timeoutMs = 8000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
      resolve({ ok: !err, stdout: String(stdout || '') });
    });
  });
}

function execFileP(cmd, args, timeoutMs = 8000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
      resolve({ ok: !err, stdout: String(stdout || '') });
    });
  });
}

/**
 * Decide which connected peers have a logged-in session, from three cheap
 * observations. Pure and exported so the decision is tested rather than trusted.
 *
 * @param {object} input
 * @param {string[]} input.connected  IPs with an established :22 connection
 * @param {string}   input.psOutput   `ps -eo args` output
 * @param {string}   input.journalOutput  `journalctl -u ssh` output
 * @param {boolean}  [input.psOk]     false when `ps` failed
 * @param {boolean}  [input.journalOk] false when journald failed
 * @returns {string[]} peers that are genuinely logged in
 */
function liveSessionPeers({ connected = [], psOutput = '', journalOutput = '',
                            psOk = true, journalOk = true } = {}) {
  // `ps -eo args` prefixes each line with the pid, so match the sshd label
  // anywhere in the line rather than anchoring to the start.
  const authedChildren = String(psOutput || '')
    .split('\n')
    .filter((l) => /sshd: [^\s(][^\s]*@/.test(l) && !/unknown/.test(l)).length;

  // The process list could not be read at all. We cannot prove nobody is
  // logged in, so every connected peer is treated as live. Failing open here
  // would silently disable the self-lockout guard.
  if (!psOk) return connected;

  // Nobody is past authentication -> no connection can be a live session.
  if (!authedChildren) return [];

  // A login exists but the log is unreadable: we cannot tell whose it is, so
  // treat every connected peer as live. Failing closed only costs a refusal.
  if (!journalOk) return connected;

  const recentLogins = new Set();
  for (const line of String(journalOutput || '').split('\n')) {
    const m = /Accepted \S+ for \S+ from (\S+) port \d+/.exec(line);
    if (m) recentLogins.add(normalizeIp(m[1]));
  }

  return connected.filter((ip) => recentLogins.has(normalizeIp(ip)));
}

/**
 * Peers with a *logged-in* SSH session right now.
 *
 * This is the guard that must not lie in either direction, and getting it wrong
 * was a real bug. `ss` reports a TCP connection as `established` the moment the
 * handshake lands — long before any password is checked. Treating that as a
 * live session meant **the harder an IP attacked, the less blockable it
 * became**: 198.51.100.35 was refused with `active_session` six times in a row
 * while throwing 427 failures, because it always had a pending preauth socket.
 *
 * The obvious fix — read the socket owner's pid from `ss -p` — does not work
 * for this service: `ss -p` needs CAP_SYS_PTRACE to map sockets to processes,
 * and `monsvc` deliberately does not have it. Verified on the box: as `monsvc`,
 * `ss -tnp` shows an empty Process column, so a pid-based guard returned `[]`
 * and would have failed *open* for an administrator's own session.
 *
 * So three observations are combined instead, none needing extra privilege.
 *
 * @returns {Promise<string[]>} IPs with an authenticated session right now
 */
async function activeSshPeers({ loginWindowMs = 24 * 60 * 60 * 1000 } = {}) {
  const [sockRes, psRes, logRes] = await Promise.all([
    execFileP('ss', ['-tn', 'state', 'established', '( sport = :22 )']),
    execFileP('ps', ['-eo', 'args']),
    execFileP('journalctl', ['-u', 'ssh', '-o', 'cat', '--no-pager',
                             '--since', `@${Math.floor((Date.now() - loginWindowMs) / 1000)}`]),
  ]);

  return liveSessionPeers({
    connected: sockRes.ok ? parseSsPeers(sockRes.stdout) : [],
    psOutput: psRes.stdout,
    psOk: psRes.ok,
    journalOutput: logRes.stdout,
    journalOk: logRes.ok,
  });
}

/**
 * Peers with a *logged-in* SSH session right now.
 *
 * This is the guard that must not lie in either direction, and getting it wrong
 * was a real bug. `ss` reports a TCP connection as `established` the moment the
 * handshake lands — long before any password is checked. Treating that as a
 * live session meant **the harder an IP attacked, the less blockable it
 * became**: 198.51.100.35 was refused with `active_session` six times in a row
 * while throwing 427 failures, because it always had a pending preauth socket.
 *
 * The obvious fix — read the socket owner's pid from `ss -p` — does not work
 * for this service: `ss -p` needs CAP_SYS_PTRACE to map sockets to processes,
 * and `monsvc` deliberately does not have it. Verified on the box: as `monsvc`,
 * `ss -tnp` shows an empty Process column and the guard silently returned `[]`,
 * i.e. it would have failed *open* for an admin's own session. So the decision
 * is made from three sources, none of which needs extra privilege:
 *
 *   1. `ss`         — which peer IPs have an established connection to :22
 *   2. `ps`         — how many sshd children are past authentication
 *                     (`sshd: root@notty` / `sshd: user@pts/0`); preauth
 *                     children are `sshd: [accepted]` and `sshd: [net]`
 *   3. journald     — which of those IPs actually completed a login recently
 *
 * An IP with a connection *and* a login *and* an authenticated child counts as
 * live. Anything unreadable counts as live too: failing closed keeps the
 * self-lockout guard working, and the cost of a false positive is only that a
 * block is refused and must be retried.
 *
 * @returns {Promise<string[]>} IPs with an authenticated session right now
 */
/* ------------------------------------------------------- country allow-list */

const GEO_TABLE = 'ssh_geoip';
const GEO_SET4 = 'allow4';
const GEO_SET6 = 'allow6';

// Sanity floors for downloaded zone data. A truncated or mis-parsed download
// would otherwise load a nearly-empty allow-list — which rejects *everything*,
// including the operator. Real per-country files are far above these numbers
// (CN ≈ 8800 IPv4 ranges), so the floor only trips on broken data.
const ZONE_MIN_V4 = 200;
const ZONE_MIN_V6 = 50;

/**
 * Parse one ipdeny zone file into a de-duplicated CIDR list.
 *
 * Only a shape check, not a full IP parser: the files come from a known source,
 * and the point is to reject an error page or an HTML redirect loudly instead
 * of feeding it to nft.
 */
function parseZone(text, family) {
  const out = [];
  const seen = new Set();
  for (const rawLine of String(text || '').split('\n')) {
    const line = rawLine.trim().toLowerCase();
    if (!line || line.startsWith('#')) continue;
    if (line.includes('<') || line.includes(' ')) continue; // HTML error page
    if (family === 6) {
      if (!/^[0-9a-f:]+\/\d{1,3}$/.test(line) || !line.includes('::') && (line.match(/:/g) || []).length < 2) continue;
    } else {
      if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(line)) continue;
    }
    if (seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}

/**
 * Render the nftables ruleset that enforces "only these ranges may open an SSH
 * connection". Pure: given the same inputs it always produces the same file, so
 * the anti-lockout expectations are unit-testable.
 *
 * Everything runs in one `nft -f` transaction, so an apply either replaces the
 * old table completely or leaves it untouched — there is never a moment with
 * an empty allow-list in place.
 *
 * Chain order relative to monitor_block is load-bearing: monitor_block hooks at
 * priority -10 and this table at 0, so an already-blocked IP is dropped (and
 * logged, and counted) before the country filter ever sees it. Reversing that
 * would freeze the "封锁后尝试" counters on every foreign blocked IP.
 */
function buildGeoipRuleset({ v4, v6, table = GEO_TABLE }) {
  if (!Array.isArray(v4) || !v4.length) {
    throw new Error('allow-list v4 is empty — refusing to build a ruleset that rejects everything');
  }
  if (!Array.isArray(v6) || !v6.length) {
    throw new Error('allow-list v6 is empty — refusing to build a ruleset that rejects everything');
  }

  const fmt = (items) => items
    .slice()
    .sort()
    .map((cidr) => `    ${cidr},`)
    .join('\n')
    .replace(/,$/, '');

  return `add table inet ${table}
delete table inet ${table}
table inet ${table} {
	set ${GEO_SET4} {
		type ipv4_addr
		flags interval
		auto-merge
		elements = {
${fmt(v4)}
		}
	}
	set ${GEO_SET6} {
		type ipv6_addr
		flags interval
		auto-merge
		elements = {
${fmt(v6)}
		}
	}
	chain filter {
		type filter hook input priority 0; policy accept;
		tcp dport { ${SSH_PORTS.join(', ')} } ct state new ip  saddr @${GEO_SET4} counter accept
		tcp dport { ${SSH_PORTS.join(', ')} } ct state new ip6 saddr @${GEO_SET6} counter accept
		tcp dport { ${SSH_PORTS.join(', ')} } ct state new counter reject with tcp reset
	}
}
`;
}

/** Install a rendered ruleset atomically. */
async function applyGeoip(ruleset, table = GEO_TABLE) {
  const res = await nft(['-f', '-'], { stdin: ruleset });
  return { ...res, table };
}

/** Remove the filter entirely (the panel "off" switch). */
async function removeGeoipTable(table = GEO_TABLE) {
  const res = await nft(['delete', 'table', 'inet', table]);
  if (!res.ok && /does not exist|No such file/i.test(res.stderr)) return { ok: true, removed: false };
  return { ...res, removed: res.ok };
}

/**
 * Live state of the filter: does the table exist, how many ranges does each
 * set hold, and how many connection attempts has the reject rule answered.
 *
 * Counters are best-effort; the set sizes come from the same JSON nft emits.
 */
async function geoipTableStatus(table = GEO_TABLE) {
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

  const status = { ok: true, active: true, v4Count: 0, v6Count: 0, acceptedPackets: 0, rejectedPackets: 0 };
  const nodes = (doc && doc.nftables) || [];
  for (const node of nodes) {
    const set = node.set;
    if (set && set.name === GEO_SET4 && Array.isArray(set.elem)) status.v4Count = set.elem.length;
    if (set && set.name === GEO_SET6 && Array.isArray(set.elem)) status.v6Count = set.elem.length;

    // Anonymous counters live in the rule expressions; the third and last
    // counter belongs to the reject rule.
    const exprs = node.rule && Array.isArray(node.rule.expr) ? node.rule.expr : null;
    if (exprs) {
      for (const e of exprs) {
        if (e && e.counter) {
          if (e.reject) status.rejectedPackets += Number(e.counter.pkts || 0);
          else status.acceptedPackets += Number(e.counter.pkts || 0);
        }
      }
    }
  }
  return status;
}

module.exports = {
  TABLE,
  SET4,
  SET6,
  GEO_TABLE,
  GEO_SET4,
  GEO_SET6,
  ZONE_MIN_V4,
  ZONE_MIN_V6,
  normalizeIp,
  isPublicIp,
  evaluateBlockRequest,
  evaluateAutoBlock,
  parseSsPeers,
  liveSessionPeers,
  ensureTable,
  addBlock,
  removeBlock,
  listBlocked,
  activeSshPeers,
  parseZone,
  buildGeoipRuleset,
  applyGeoip,
  removeGeoipTable,
  geoipTableStatus,
};
