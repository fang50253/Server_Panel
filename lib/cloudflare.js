'use strict';

/**
 * Cloudflare edge ranges, used to restore the visitor's real address.
 *
 * The public sites are behind Cloudflare, so nginx otherwise sees a Cloudflare
 * edge IP and every source-based rule matches the CDN, not the visitor. The
 * generated nginx snippet trusts `CF-Connecting-IP` only from the networks
 * below, then `$remote_addr` becomes the real client — the existing country /
 * CIDR maps work unchanged and direct (non-proxied) requests are unaffected.
 *
 * The list is public and changes rarely. It is refreshed once a day and cached
 * in /var/lib/monitor; if the fetch fails the previous cache (or the built-in
 * copy) is used, so an offline box never loses its configuration.
 */

const fs = require('fs');
const https = require('https');
const { parseCidr } = require('./trafficfilter');

const V4_URL = 'https://www.cloudflare.com/ips-v4';
const V6_URL = 'https://www.cloudflare.com/ips-v6';
const MAX_RANGES = 64;
const MAX_BYTES = 16 * 1024;
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

// https://www.cloudflare.com/ips/ — keep in sync when the online copy is
// unavailable. Every entry is validated before use, so a bad edit fails closed
// to "no trusted proxy" rather than trusting the wrong network.
const BUILTIN_V4 = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
];

const BUILTIN_V6 = [
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

/** Parse one text list (one CIDR per line) into normalized CIDRs. */
function parseList(text, family) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parsed = parseCidr(line);
    if (!parsed || parsed.family !== family) continue;
    out.push(parsed.cidr);
  }
  return [...new Set(out)].slice(0, MAX_RANGES);
}

function normalizeRanges(input) {
  const asList = (value) => {
    if (Array.isArray(value)) return value;
    if (typeof value === 'string') return value.split(/\r?\n/);
    return [];
  };
  const v4 = parseList(asList(input && input.v4).join('\n'), 4);
  const v6 = parseList(asList(input && input.v6).join('\n'), 6);
  return {
    v4: v4.length ? v4 : BUILTIN_V4.slice(),
    v6: v6.length ? v6 : BUILTIN_V6.slice(),
    fetchedAt: Number(input && input.fetchedAt) || 0,
    source: (input && input.source) || 'builtin',
  };
}

function fetchText(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      let body = '';
      let size = 0;
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BYTES) {
          req.destroy(new Error('response too large'));
          return;
        }
        body += chunk;
      });
      res.on('end', () => resolve(body));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

async function fetchRanges() {
  const [v4Text, v6Text] = await Promise.all([fetchText(V4_URL), fetchText(V6_URL)]);
  const v4 = parseList(v4Text, 4);
  const v6 = parseList(v6Text, 6);
  if (!v4.length || !v6.length) throw new Error('empty or invalid Cloudflare range list');
  return { v4, v6, fetchedAt: Date.now(), source: 'cloudflare.com' };
}

function readCache(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    const ranges = normalizeRanges(parsed);
    // normalizeRanges substitutes the built-in list when a family is empty;
    // keep the cached timestamp only when the cache itself was usable.
    if (!Array.isArray(parsed.v4) || !parsed.v4.length || !Array.isArray(parsed.v6) || !parsed.v6.length) {
      return null;
    }
    return ranges;
  } catch {
    return null;
  }
}

function writeCache(file, ranges) {
  try {
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(ranges, null, 2)}\n`, { mode: 0o640 });
    fs.renameSync(tmp, file);
  } catch {
    // A read-only data dir must not break filtering; the fetch result is still used.
  }
}

/**
 * Current trusted ranges. Never throws: on a failed refresh it falls back to a
 * stale cache, then to the built-in list.
 */
async function currentRanges(file, { now = Date.now(), force = false } = {}) {
  const cached = readCache(file);
  if (!force && cached && now - cached.fetchedAt < MAX_AGE_MS) return cached;

  try {
    const fresh = await fetchRanges();
    writeCache(file, fresh);
    return fresh;
  } catch {
    if (cached) return { ...cached, source: `${cached.source} (cached)` };
    return normalizeRanges({ v4: BUILTIN_V4, v6: BUILTIN_V6, fetchedAt: 0, source: 'builtin' });
  }
}

module.exports = {
  BUILTIN_V4,
  BUILTIN_V6,
  MAX_RANGES,
  MAX_AGE_MS,
  parseList,
  normalizeRanges,
  currentRanges,
};
