'use strict';

/**
 * One-time migration: seed fail-history.json from the ssh journal.
 *
 * Run once on the server, with the service stopped (both processes must not
 * write fail-history.json at the same time):
 *
 *   systemctl stop monitor
 *   node /opt/monitor/deploy/backfill-fail-history.js
 *   systemctl start monitor
 *
 * The permanent history file was introduced long after the monitor started, so
 * without this the panel would show "—" for every IP that attacked before
 * today, even though the journal still holds the evidence.
 *
 * Parsing goes through the same `parseFailed` the live server uses, so the
 * backfilled history counts exactly what a running server would have counted.
 * Idempotent: re-running recomputes the whole file from the journal.
 */

const { execFileSync } = require('child_process');
const { Store } = require('../lib/store');
const { parseFailed, stripBrackets } = require('../lib/ssh-watch');

const KEEP_MS = 7 * 24 * 60 * 60 * 1000;
const HISTORY_CAP = 50000;

const store = new Store({ dir: process.env.DATA_DIR || '/var/lib/monitor' });

let out;
try {
  out = execFileSync('journalctl', ['-u', 'ssh', '-o', 'json', '--no-pager'], {
    maxBuffer: 512 * 1024 * 1024,
    timeout: 120000,
    encoding: 'utf8',
  });
} catch (err) {
  console.error('journalctl failed:', err.message);
  process.exit(1);
}

const history = {};
let lines = 0;
for (const line of out.split('\n')) {
  const text = line.trim();
  if (!text) continue;
  let rec;
  try {
    rec = JSON.parse(text);
  } catch {
    continue;
  }

  const bad = parseFailed(rec.MESSAGE);
  if (!bad) continue;
  const ip = stripBrackets(bad.ip);
  // Same clock the server records: journald's own timestamp, in ms.
  const ts = Math.round(Number(rec.__REALTIME_TIMESTAMP || 0) / 1000);
  if (!ip || !ts) continue;
  lines += 1;

  const h = history[ip] || (history[ip] = { firstSeen: null, lastSeen: null, total: 0, times: [] });
  h.firstSeen = h.firstSeen ? Math.min(h.firstSeen, ts) : ts;
  h.lastSeen = h.lastSeen ? Math.max(h.lastSeen, ts) : ts;
  h.total += 1;
  h.times.push(ts);
}

// Same retention as server.js recordHistory(): window pruned, newest kept at cap.
const cutoff = Date.now() - KEEP_MS;
for (const h of Object.values(history)) {
  h.times = h.times.filter((t) => t >= cutoff).sort((a, b) => a - b).slice(-HISTORY_CAP);
}

store.writeHistorySync(history);

// This script runs as root; the service runs as its own user. The file was
// just created root-owned with mode 0600, which the service then cannot read —
// it silently starts with an empty history and its next save wipes this file.
// Hand ownership to whoever owns the data directory (monsvc).
const fs = require('fs');
try {
  const { uid, gid } = fs.statSync(store.dir);
  fs.chownSync(store.historyFile, uid, gid);
} catch (err) {
  console.error(`warning: could not chown ${store.historyFile}: ${err.message}`);
  console.error('fix manually, e.g.: chown monsvc:monsvc /var/lib/monitor/fail-history.json');
}

console.log(`backfilled ${Object.keys(history).length} IPs from ${lines} failures`);
for (const [ip, h] of Object.entries(history)) {
  const first = new Date(h.firstSeen).toISOString();
  const last = new Date(h.lastSeen).toISOString();
  console.log(`  ${ip}  total=${h.total}  first=${first}  last=${last}  window=${h.times.length}`);
}
