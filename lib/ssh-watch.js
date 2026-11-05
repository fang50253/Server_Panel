'use strict';

/**
 * SSH authentication event tracking.
 *
 * Reads the ssh unit's journal for two kinds of lines:
 *
 *   Accepted ...  -> a successful login (used for "new IP" alerts)
 *   Failed ...    -> a failed attempt  (used for brute-force alerts)
 *
 * journald already handles rotation and persistence, so there is no file
 * tailing to get wrong. The cursor is the whole point: each line is processed
 * exactly once, across restarts.
 *
 * State that must survive a restart:
 *   journal.cursor   — how far we have read
 *   known-ips.json   — every IP that has ever logged in successfully
 *   failures.json    — per-IP attempt timestamps inside the current window
 */

const { execFile } = require('child_process');

const ACCEPTED_RE = /^Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/;

// sshd's exact wording, in the shapes Debian emits.
const FAILED_RES = [
  /^Failed\s+(\S+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/,
  /^Invalid\s+user\s+(\S+)\s+from\s+(\S+)/,
  /^Connection\s+closed\s+by\s+authenticating\s+user\s+(\S+)\s+(\S+)\s+port\s+(\d+)/,
];

/** Parse one journald message into a login event, or null. */
function parseAccepted(message) {
  const m = ACCEPTED_RE.exec(String(message || '').trim());
  if (!m) return null;
  return { method: m[1], user: m[2], ip: stripBrackets(m[3]), port: Number(m[4]) };
}

/**
 * Parse a failed authentication attempt.
 *
 * Returns `{ ip, user, method, invalidUser }`; `method` is the auth method when
 * sshd names it ("password", "publickey") and "unknown" otherwise.
 */
function parseFailed(message) {
  const text = String(message || '').trim();
  if (!text) return null;

  let m = FAILED_RES[0].exec(text);
  if (m) {
    return { ip: stripBrackets(m[3]), user: m[2], method: m[1], invalidUser: /invalid user/.test(text) };
  }

  m = FAILED_RES[1].exec(text);
  if (m) {
    return { ip: stripBrackets(m[2]), user: m[1], method: 'unknown', invalidUser: true };
  }

  m = FAILED_RES[2].exec(text);
  if (m) {
    return { ip: stripBrackets(m[2]), user: m[1], method: 'unknown', invalidUser: false };
  }

  return null;
}

function stripBrackets(ip) {
  return String(ip || '').replace(/^\[|\]$/g, '');
}

/** Private / loopback sources are never interesting as "new IP". */
function isPrivateIp(ip) {
  const raw = stripBrackets(ip);
  if (!raw) return true;
  if (raw === '::1') return true;
  if (raw.startsWith('fe80:') || raw.startsWith('fc') || raw.startsWith('fd')) return true;
  const parts = raw.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

function run(cmd, args, { timeoutMs = 15000 } = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

/**
 * Newest journal cursor for the ssh unit. Used to seed a fresh install so the
 * existing backlog is treated as history rather than as a login storm.
 */
async function currentCursor() {
  const res = await run('journalctl', ['-u', 'ssh', '-n', '0', '--show-cursor', '--no-pager', '-o', 'cat']);
  const m = /cursor:\s*(\S+)/.exec(res.stdout);
  return m ? m[1] : '';
}

/**
 * Read new journal entries since `cursor`, split into accepted and failed.
 *
 * An empty cursor reads the whole available journal. That is intentional: on a
 * fresh install the caller seeds its state from it instead of alerting.
 *
 * `--no-tail` matters more than it looks. Plain `journalctl -n N
 * --after-cursor=X` returns the *last* N entries after X, so a backlog larger
 * than N (for example after the service was down for a day) would silently drop
 * the oldest failures — exactly the ones an alert is supposed to catch. With
 * `--no-tail` the stream starts at the cursor and moves forward, so nothing can
 * be skipped. The cap below truncates the *end* instead, and the returned
 * cursor stays at the last entry actually read, so the next poll resumes from
 * there.
 *
 * @returns {Promise<{accepted: Array, failed: Array, cursor: string, ok: boolean, truncated?: boolean, error?: string}>}
 */
async function readEventsSince(cursor, { maxEvents = 20000 } = {}) {
  const args = ['-u', 'ssh', '-o', 'json', '--no-pager', '--no-tail'];
  if (cursor) args.push(`--after-cursor=${cursor}`);

  const res = await run('journalctl', args, { maxBuffer: 64 * 1024 * 1024, timeoutMs: 60000 });

  // journalctl exits non-zero on an invalid cursor; that must not wedge the
  // loop forever, so the caller resets the cursor when ok is false.
  if (!res.ok && !res.stdout.trim()) {
    return { accepted: [], failed: [], cursor, ok: false, error: res.stderr.trim() };
  }

  const accepted = [];
  const failed = [];
  let lastCursor = cursor;
  let seen = 0;
  let truncated = false;

  for (const line of res.stdout.split('\n')) {
    const text = line.trim();
    if (!text) continue;
    let rec;
    try {
      rec = JSON.parse(text);
    } catch {
      continue;
    }

    seen += 1;
    if (seen > maxEvents) {
      // Stop here rather than at the end: advancing the cursor past entries we
      // never parsed would lose them for good.
      truncated = true;
      break;
    }
    if (rec.__CURSOR) lastCursor = rec.__CURSOR;

    const base = {
      cursor: rec.__CURSOR || '',
      ts: Math.round(Number(rec.__REALTIME_TIMESTAMP || 0) / 1000),
      pid: rec._PID ? Number(rec._PID) : null,
      process: rec._COMM || 'sshd',
    };

    const ok = parseAccepted(rec.MESSAGE);
    if (ok) {
      accepted.push({ ...base, ...ok });
      continue;
    }

    const bad = parseFailed(rec.MESSAGE);
    if (bad) failed.push({ ...base, ...bad });
  }

  return { accepted, failed, cursor: lastCursor, ok: true, truncated };
}

/** Backwards-compatible wrapper used by older call sites and tests. */
async function readLoginsSince(cursor, options) {
  const res = await readEventsSince(cursor, options);
  return { entries: res.accepted, cursor: res.cursor, ok: res.ok, error: res.error };
}

/**
 * Parse a netfilter drop log line emitted by our own block chain.
 *
 * Our rule logs with the prefix `MONITOR_BLOCK`, so a line looks like:
 *
 *   MONITOR_BLOCK IN=eth0 OUT= MAC=... SRC=198.51.100.7 DST=203.0.113.10
 *                 LEN=60 ... PROTO=TCP SPT=51000 DPT=22 ...
 *
 * Only lines carrying that prefix are considered, so unrelated kernel drops
 * (docker, br_netfilter, ...) are never attributed to us.
 */
const BLOCK_LOG_RE = /MONITOR_BLOCK\b.*\bSRC=(\S+).*\bDPT=(\d+)/;

function parseBlocked(message) {
  const m = BLOCK_LOG_RE.exec(String(message || ''));
  if (!m) return null;
  return { ip: stripBrackets(m[1]), port: Number(m[2]) };
}

/**
 * Blocked attempts since `cursor`, newest-last.
 *
 * This is what makes "封锁之后还在尝试" visible: once an IP is in the nft set,
 * sshd never sees the connection again, so its attempts stop showing up in the
 * ssh unit's journal. The kernel log is the only place they still appear.
 *
 * @returns {Promise<{entries: Array<{ip: string, port: number, ts: number}>, cursor: string, ok: boolean, error?: string}>}
 */
async function readBlockedSince(cursor, { maxEvents = 20000 } = {}) {
  const args = ['-k', '-o', 'json', '--no-pager', '--no-tail', '--grep', 'MONITOR_BLOCK'];
  if (cursor) args.push(`--after-cursor=${cursor}`);

  const res = await run('journalctl', args, { maxBuffer: 64 * 1024 * 1024, timeoutMs: 60000 });
  if (!res.ok && !res.stdout.trim()) {
    return { entries: [], cursor, ok: false, error: res.stderr.trim() };
  }

  const entries = [];
  let lastCursor = cursor;
  let seen = 0;

  for (const line of res.stdout.split('\n')) {
    const text = line.trim();
    if (!text) continue;
    let rec;
    try {
      rec = JSON.parse(text);
    } catch {
      continue;
    }

    seen += 1;
    if (seen > maxEvents) break;
    if (rec.__CURSOR) lastCursor = rec.__CURSOR;

    const hit = parseBlocked(rec.MESSAGE);
    if (!hit) continue;
    entries.push({
      ...hit,
      ts: Math.round(Number(rec.__REALTIME_TIMESTAMP || 0) / 1000),
    });
  }

  return { entries, cursor: lastCursor, ok: true };
}

/** Newest kernel-log cursor, for seeding so old drops are not counted. */
async function currentKernelCursor() {
  const res = await run('journalctl', ['-k', '-n', '0', '--show-cursor', '--no-pager', '-o', 'cat']);
  const m = /cursor:\s*(\S+)/.exec(res.stdout);
  return m ? m[1] : '';
}

/**
 * The newest `limit` journal entries, oldest-first.
 *
 * Used once, at bootstrap. `readEventsSince('')` reads from the oldest retained
 * entry, which on a long-running box can be far too much data and — with the
 * maxEvents cap — would learn the *oldest* IPs rather than the recent ones.
 * Bootstrap wants the opposite: the recent past.
 */
async function readRecent({ limit = 5000 } = {}) {
  const res = await run(
    'journalctl',
    ['-u', 'ssh', '-o', 'json', '--no-pager', '-n', String(limit)],
    { maxBuffer: 64 * 1024 * 1024, timeoutMs: 60000 },
  );

  const accepted = [];
  const failed = [];

  for (const line of res.stdout.split('\n')) {
    const text = line.trim();
    if (!text) continue;
    let rec;
    try {
      rec = JSON.parse(text);
    } catch {
      continue;
    }

    const base = {
      cursor: rec.__CURSOR || '',
      ts: Math.round(Number(rec.__REALTIME_TIMESTAMP || 0) / 1000),
      pid: rec._PID ? Number(rec._PID) : null,
      process: rec._COMM || 'sshd',
    };

    const ok = parseAccepted(rec.MESSAGE);
    if (ok) {
      accepted.push({ ...base, ...ok });
      continue;
    }
    const bad = parseFailed(rec.MESSAGE);
    if (bad) failed.push({ ...base, ...bad });
  }

  return { accepted, failed, ok: res.ok, error: res.stderr.trim() };
}

/**
 * Decide which logins are worth an email.
 *
 * @param {Array} entries  login events, oldest first
 * @param {object} known   map ip -> { firstSeen, lastSeen, count, user, country }
 * @returns {{known: object, fresh: Array, skipped: Array}}
 */
function classify(entries, known = {}) {
  const next = { ...known };
  const fresh = [];
  const skipped = [];

  for (const entry of entries) {
    const ip = stripBrackets(entry.ip);
    if (!ip) continue;

    const record = next[ip];
    if (record) {
      next[ip] = {
        ...record,
        lastSeen: entry.ts,
        count: (record.count || 1) + 1,
        user: entry.user,
      };
      skipped.push({ ...entry, reason: 'known' });
      continue;
    }

    if (isPrivateIp(ip)) {
      next[ip] = {
        firstSeen: entry.ts,
        lastSeen: entry.ts,
        count: 1,
        user: entry.user,
        private: true,
      };
      skipped.push({ ...entry, reason: 'private' });
      continue;
    }

    next[ip] = {
      firstSeen: entry.ts,
      lastSeen: entry.ts,
      count: 1,
      user: entry.user,
      method: entry.method,
    };
    fresh.push({ ...entry, ip });
  }

  return { known: next, fresh, skipped };
}

/**
 * Sliding-window counter for failed attempts, per IP.
 *
 * Only timestamps are stored, not a running total, so the window genuinely
 * slides: an IP that failed twice an hour ago and once now is at 3, but the
 * same IP three hours later is back to 1.
 */
class FailureTracker {
  constructor({ state = {}, now = () => Date.now() } = {}) {
    this.state = state || {};
    this.now = now;
  }

  /** Drop timestamps older than the window and count what is left. */
  prune(windowMs, now = this.now()) {
    const cutoff = now - windowMs;
    for (const [ip, rec] of Object.entries(this.state)) {
      const kept = (rec.times || []).filter((t) => t >= cutoff);
      if (!kept.length) {
        delete this.state[ip];
        continue;
      }
      rec.times = kept;
      rec.count = kept.length;
    }
    return this.state;
  }

  /**
   * Record attempts for one IP and report the current window count.
   *
   * @returns {{ip: string, count: number, first: number, last: number, users: string[]}}
   */
  record(ip, attempts, windowMs, now = this.now()) {
    const cutoff = now - windowMs;
    const rec = this.state[ip] || { times: [], users: [], lastAlertAt: null };

    for (const attempt of attempts) {
      rec.times.push(attempt.ts || now);
      // Unique, not just de-duplicated against the previous entry: an attacker
      // cycling root/admin/root would otherwise fill the list with "root" and
      // hide the other names that were tried.
      if (attempt.user && !rec.users.includes(attempt.user)) {
        rec.users.push(attempt.user);
      }
    }
    rec.times = rec.times.filter((t) => t >= cutoff).sort((a, b) => a - b);
    rec.count = rec.times.length;
    rec.lastSeen = now;
    rec.users = rec.users.slice(-12);

    this.state[ip] = rec;
    return { ip, count: rec.count, first: rec.times[0], last: rec.times[rec.times.length - 1], users: rec.users };
  }

  /** True when the IP has not been alerted within the cooldown. */
  canAlert(ip, cooldownMs, now = this.now()) {
    const rec = this.state[ip];
    if (!rec) return false;
    if (rec.lastAlertAt === null || rec.lastAlertAt === undefined) return true;
    return now - rec.lastAlertAt >= cooldownMs;
  }

  markAlerted(ip, now = this.now()) {
    const rec = this.state[ip];
    if (rec) rec.lastAlertAt = now;
  }

  get size() {
    return Object.keys(this.state).length;
  }
}

/**
 * Group a flat list of failed events into per-IP buckets.
 * @returns {Map<string, Array>}
 */
function groupByIp(events) {
  const map = new Map();
  for (const event of events) {
    const ip = stripBrackets(event.ip);
    if (!ip) continue;
    if (!map.has(ip)) map.set(ip, []);
    map.get(ip).push(event);
  }
  return map;
}

module.exports = {
  parseAccepted,
  parseFailed,
  parseBlocked,
  isPrivateIp,
  stripBrackets,
  currentCursor,
  currentKernelCursor,
  readEventsSince,
  readBlockedSince,
  readLoginsSince,
  readRecent,
  classify,
  FailureTracker,
  groupByIp,
};
