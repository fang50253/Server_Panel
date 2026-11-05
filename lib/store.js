'use strict';

/**
 * Atomic JSON persistence for the monitor.
 *
 * Everything lives in one directory (/var/lib/monitor by default, owned by the
 * service user, mode 0750). Files are written temp-then-rename so a crash mid
 * write cannot leave half a JSON document behind.
 */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');

async function writeJsonAtomic(file, value) {
  const dir = path.dirname(file);
  await fsp.mkdir(dir, { recursive: true, mode: 0o750 });
  const tmp = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, `${JSON.stringify(value, null, 1)}\n`, { mode: 0o600 });
  await fsp.rename(tmp, file);
}

function readJsonSync(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

/**
 * Sync twin of writeJsonAtomic. Only for one-shot CLI tools (the backfill
 * migration); the server itself must stay async so a slow disk can never
 * freeze a request or the tick loop.
 */
function writeJsonAtomicSync(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o750 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 1)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

class Store {
  constructor({ dir = '/var/lib/monitor' } = {}) {
    this.dir = dir;
    this.configFile = path.join(dir, 'config.json');
    this.stateFile = path.join(dir, 'state.json');
    this.ipsFile = path.join(dir, 'known-ips.json');
    this.geoFile = path.join(dir, 'geo-cache.json');
    this.failFile = path.join(dir, 'ssh-failures.json');
    this.blockedFile = path.join(dir, 'blocked.json');
    this.historyFile = path.join(dir, 'fail-history.json');
    this.trafficFilterFile = path.join(dir, 'traffic-filter.json');
    this.blockCursorFile = path.join(dir, 'kernel.cursor');
    this.cursorFile = path.join(dir, 'journal.cursor');
  }

  readConfig(fallback) {
    return readJsonSync(this.configFile, fallback);
  }

  async writeConfig(config) {
    await writeJsonAtomic(this.configFile, config);
  }

  readState(fallback) {
    return readJsonSync(this.stateFile, fallback);
  }

  /**
   * Persist engine state at most once a minute. Losing the consecutive counter
   * on a restart only delays an alert by a minute, so this is cheap insurance
   * rather than something that has to be transactional.
   */
  async writeState(state) {
    await writeJsonAtomic(this.stateFile, state);
  }

  readKnownIps(fallback) {
    return readJsonSync(this.ipsFile, fallback);
  }

  async writeKnownIps(map) {
    await writeJsonAtomic(this.ipsFile, map);
  }

  readGeoCache(fallback) {
    return readJsonSync(this.geoFile, fallback);
  }

  async writeGeoCache(map) {
    await writeJsonAtomic(this.geoFile, map);
  }

  readFailures(fallback) {
    return readJsonSync(this.failFile, fallback);
  }

  async writeFailures(state) {
    await writeJsonAtomic(this.failFile, state);
  }

  /**
   * Block bookkeeping: when an IP was blocked, by whom, and how many attempts
   * have been dropped since. The nft set is the source of truth for "is it
   * blocked", this file is the audit trail the panel shows.
   */
  readBlocked(fallback) {
    return readJsonSync(this.blockedFile, fallback);
  }

  async writeBlocked(map) {
    await writeJsonAtomic(this.blockedFile, map);
  }

  /**
   * Permanent per-IP failure history: ip -> { firstSeen, lastSeen, total }.
   *
   * Separate from ssh-failures.json on purpose. That file is a rolling window
   * and forgets an IP once the attacker stops; this one is append-only
   * bookkeeping so "首次 / 最近" never silently reset to "—", and so the total
   * count survives a quiet period. Removed only by an explicit reset.
   */
  readHistory(fallback) {
    return readJsonSync(this.historyFile, fallback);
  }

  async writeHistory(map) {
    await writeJsonAtomic(this.historyFile, map);
  }

  /** Sync variant, used by deploy/backfill-fail-history.js only. */
  writeHistorySync(map) {
    writeJsonAtomicSync(this.historyFile, map);
  }

  /**
   * Traffic filter: { enabled, rules }.
   *
   * Kept out of config.json on purpose — rules are a list with their own
   * lifecycle (add/edit/delete) and mixing them into the alert-threshold blob
   * would make the panel's "save rules" button rewrite firewall state.
   */
  readTrafficFilter(fallback) {
    return readJsonSync(this.trafficFilterFile, fallback);
  }

  async writeTrafficFilter(value) {
    await writeJsonAtomic(this.trafficFilterFile, value);
  }

  /** Kernel-log cursor, separate from the ssh-unit cursor. */
  readBlockCursor() {
    try {
      return fs.readFileSync(this.blockCursorFile, 'utf8').trim();
    } catch {
      return '';
    }
  }

  async writeBlockCursor(cursor) {
    await fsp.mkdir(this.dir, { recursive: true, mode: 0o750 });
    const tmp = `${this.blockCursorFile}.${process.pid}.tmp`;
    await fsp.writeFile(tmp, `${cursor}\n`, { mode: 0o600 });
    await fsp.rename(tmp, this.blockCursorFile);
  }

  readCursor() {
    try {
      return fs.readFileSync(this.cursorFile, 'utf8').trim();
    } catch {
      return '';
    }
  }

  /** The cursor is opaque text, not JSON, so it is written verbatim. */
  async writeCursor(cursor) {
    await fsp.mkdir(this.dir, { recursive: true, mode: 0o750 });
    const tmp = `${this.cursorFile}.${process.pid}.tmp`;
    await fsp.writeFile(tmp, `${cursor}\n`, { mode: 0o600 });
    await fsp.rename(tmp, this.cursorFile);
  }

  /** Append one JSON line to the alert history. */
  async appendHistory(entry) {
    await fsp.mkdir(this.dir, { recursive: true, mode: 0o750 });
    await fsp.appendFile(path.join(this.dir, 'alerts.jsonl'), `${JSON.stringify(entry)}\n`);
  }

  /**
   * Read the alert history (alerts.jsonl) for the panel's "最近告警" section.
   *
   * Named "alerts", not "history", on purpose: there is also a fail-history
   * file (readHistory/writeHistory above), and when both methods were called
   * readHistory the later definition silently won — the panel then showed
   * alerts where failure statistics were expected.
   */
  readAlerts(limit = 50) {
    try {
      const text = fs.readFileSync(path.join(this.dir, 'alerts.jsonl'), 'utf8');
      return text
        .split('\n')
        .filter(Boolean)
        .slice(-limit)
        .map((line) => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        })
        .filter(Boolean)
        .reverse();
    } catch {
      return [];
    }
  }
}

module.exports = { Store, writeJsonAtomic, readJsonSync };
