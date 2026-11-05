'use strict';

/**
 * Resource + login monitor for 203.0.113.10.
 *
 * Two independent jobs in one process:
 *
 *   resources — sample /proc every 60s, evaluate the sustained-usage rules,
 *               email through the mail panel when a rule fires
 *   logins    — follow the ssh unit's journal, email on a never-seen IP
 *
 * Both can be switched off from https://panel.example.com/ (password +
 * signed cookie + CSRF), and both settings persist to /var/lib/monitor.
 *
 * Deliberately no shell-outs for measurement: /proc is read directly, so the
 * monitor cannot itself become the load it is complaining about.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const net = require('net');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

const { Sampler, formatBytes, formatMbps } = require('./lib/metrics');
const { normalizeRules, evaluate, emptyState, DEFAULTS } = require('./lib/policy');
const { Store } = require('./lib/store');
const { Auth } = require('./lib/auth');
const { MailApiClient } = require('./lib/mail-client');
const { GeoCache, describe } = require('./lib/geo');
const blocker = require('./lib/blocker');
const trafficfilter = require('./lib/trafficfilter');
const failedPage = require('./lib/failed-page');
const cloudflare = require('./lib/cloudflare');
const {
  currentCursor,
  currentKernelCursor,
  readEventsSince,
  readBlockedSince,
  readRecent,
  classify,
  FailureTracker,
  groupByIp,
} = require('./lib/ssh-watch');
const { buildResourceAlert, buildSshAlert, buildSshFailAlert, formatTime } = require('./lib/notify');

const PORT = Number(process.env.PORT || 8087);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.DATA_DIR || '/var/lib/monitor';
const UI_FILE = path.join(__dirname, 'ui.html');

const SAMPLE_INTERVAL_MS = Number(process.env.SAMPLE_INTERVAL_MS || 60_000);
const SSH_POLL_MS = Number(process.env.SSH_POLL_MS || 20_000);

const ALERT_TO = process.env.ALERT_TO || 'admin@example.com';
const PUBLIC_URL = process.env.PUBLIC_URL || 'https://panel.example.com/';
const HOSTNAME = process.env.SERVER_NAME || os.hostname();

// Never blockable, even if someone asks. This is the belt to the
// "has successfully logged in" braces: an IP that is how you administer the box
// must not be turned into a brick.
const PROTECTED_IPS = String(process.env.PROTECTED_IPS || '')
  .split(',')
  .map((s) => blocker.normalizeIp(s))
  .filter(Boolean);

const store = new Store({ dir: DATA_DIR });
const auth = new Auth({
  password: process.env.MONITOR_PASSWORD || '',
  secret: process.env.MONITOR_SECRET || '',
});

// Email is optional. Without credentials the panel still monitors and records;
// alerts are logged as failed instead of crashing the process at boot.
const mailConfig = {
  socket: process.env.MAIL_API_SOCKET || '/run/mail-panel/api.sock',
  keyId: process.env.MAIL_API_KEY_ID || '',
  secret: process.env.MAIL_API_SECRET || '',
};
const mail = mailConfig.keyId && mailConfig.secret
  ? new MailApiClient(mailConfig)
  : null;

let rules = normalizeRules(store.readConfig({ rules: DEFAULTS }).rules || {});
let state = store.readState(emptyState());
let knownIps = store.readKnownIps({});
const geo = new GeoCache({ cache: store.readGeoCache({}) });
const failures = new FailureTracker({ state: store.readFailures({}) });

/**
 * Audit trail for manual blocks: ip -> { blockedAt, count (attempts dropped
 * since blocking), lastSeen, packets }.
 *
 * The nft set is authoritative for "is this IP blocked"; this map adds the
 * context the panel needs (when, how many retries since) and survives restarts.
 */
let blocked = store.readBlocked({});

/**
 * Traffic filter: { enabled, rules }. Rules match a source + port set.
 *
 * Rules are an ordered list, not a config blob, so they get their own file and
 * their own save path. `trafficState` is runtime-only: it records whether the table
 * is actually loaded, which is what the panel reports.
 */
let trafficFilter = store.readTrafficFilter({ enabled: false, rules: [] });
// `mode` decides what a blocked HTTP/HTTPS client sees: nothing (drop), a bare
// 404, or a redirect to the failure page. `failedHtml` is the editable body of
// that page. Both default gently so an older file keeps working.
if (!trafficfilter.MODES.includes(trafficFilter.mode)) trafficFilter.mode = 'drop';
if (typeof trafficFilter.failedHtml !== 'string') trafficFilter.failedHtml = failedPage.DEFAULT_FAILED_HTML;
const trafficState = { error: null, appliedAt: null, v4Count: 0, v6Count: 0, dropRules: 0, allowRules: 0, webCounts: null, cfTrusted: null };

/**
 * Permanent failure history: ip -> { firstSeen, lastSeen, total }.
 *
 * Deliberately never pruned. The rolling window in `failures` decides what is
 * happening *now*; this decides what has *ever* happened, so the panel can keep
 * showing 首次 / 最近 after an attacker gives up. Cleared only via an explicit
 * reset action, never by time.
 */
const history = store.readHistory({});

const sampler = new Sampler({
  // Overridable so the whole server can be exercised with fixture files.
  cpuPath: process.env.PROC_STAT || '/proc/stat',
  memPath: process.env.PROC_MEMINFO || '/proc/meminfo',
  netPath: process.env.PROC_NET_DEV || '/proc/net/dev',
});
let latestSample = null;
let lastSampleAt = 0;
let lastError = null;
let lastNftError = null;
let alertInFlight = false;
let lastSshPollAt = 0;
let lastSshError = null;

const counters = { alertsSent: 0, alertsFailed: 0, sshAlertsSent: 0, sshFailAlertsSent: 0, failedAttempts: 0, samples: 0 };

/* ---------------------------------------------------------------- logging */

function log(event) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), svc: 'monitor', ...event }));
}

/**
 * Every address this host answers on.
 *
 * Blocking the server's own IP would cut outbound connections (GeoIP lookups,
 * the mail socket is local so that is fine, but package updates and ACME are
 * not). Cheap to compute and only ever used as a refusal list.
 */
function selfIps() {
  const out = new Set();
  for (const list of Object.values(os.networkInterfaces())) {
    for (const info of list || []) {
      if (info && info.address) out.add(blocker.normalizeIp(info.address));
    }
  }
  return [...out];
}

/**
 * The operator's address for this request.
 *
 * The service only listens on 127.0.0.1 behind nginx, so the socket address is
 * useless for the lockout guard and the proxy headers are trustworthy here.
 */
function requestIp(req) {
  const real = String(req.headers['x-real-ip'] || '').trim();
  if (real) return real;
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (forwarded) return forwarded;
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}

/* ------------------------------------------------------------ persistence */

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(async () => {
    saveTimer = null;
    try {
      await store.writeState(state);
      await store.writeKnownIps(knownIps);
      await store.writeGeoCache(geo.cache);
      await store.writeFailures(failures.state);
      await store.writeBlocked(blocked);
      await store.writeHistory(history);
    } catch (err) {
      log({ level: 'error', event: 'save_failed', error: err.message });
    }
  }, 2000);
  saveTimer.unref?.();
}

async function saveRules() {
  await store.writeConfig({ rules, updatedAt: new Date().toISOString() });
}

/* ---------------------------------------------------------------- mailing */

/**
 * Send one alert through the mail panel.
 *
 * Serialised on purpose: if CPU and memory both trip in the same minute, the
 * two emails go out one after another rather than racing on the same socket.
 */
async function sendAlert({ template, vars }, meta = {}) {  while (alertInFlight) await new Promise((r) => setTimeout(r, 200));
  alertInFlight = true;

  const entry = { ts: new Date().toISOString(), ...meta, template, title: vars.title, to: ALERT_TO };

  try {
    if (!mail) throw new Error('mail API is not configured');
    const res = await mail.send({ template, to: ALERT_TO, vars });
    counters.alertsSent += 1;
    await store.appendHistory({ ...entry, ok: true, id: res.id });
    log({ level: 'info', event: 'alert_sent', kind: meta.kind, id: res.id, title: vars.title });
    return { ok: true, id: res.id };
  } catch (err) {
    counters.alertsFailed += 1;
    await store.appendHistory({ ...entry, ok: false, error: err.message, code: err.code });
    log({ level: 'error', event: 'alert_failed', kind: meta.kind, error: err.message, code: err.code });
    lastError = `发信失败：${err.message}`;
    return { ok: false, error: err.message, code: err.code };
  } finally {
    alertInFlight = false;
  }
}

/* --------------------------------------------------------- resource loop */

async function tickResources(now = Date.now()) {
  const sample = sampler.sample(now);
  sample.cpuCores = os.cpus().length || 1;
  latestSample = sample;
  lastSampleAt = now;
  counters.samples += 1;

  if (!rules.enabled) {
    state.lastSampleAt = now;
    return;
  }

  const { state: nextState, actions } = evaluate(state, sample, rules, now);
  state = nextState;

  for (const action of actions) {
    const { template, vars } = buildResourceAlert({
      action,
      sample,
      rules,
      host: HOSTNAME,
      url: PUBLIC_URL,
      now,
    });
    await sendAlert(
      { template, vars },
      { kind: 'resource', metric: action.metric, value: action.value, threshold: action.threshold },
    );
  }

  scheduleSave();
}

/* -------------------------------------------------------------- ssh loop */

// How much failure history to keep for the auto-block window, and how many
// timestamps at most per IP. The auto-block window is configurable up to a
// week; keeping a full week of timestamps makes extending the window later
// meaningful. The cap bounds memory and the JSON file size: a brute-force IP
// at a few attempts per second would otherwise grow the file without limit.
const HISTORY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const HISTORY_CAP = 50000;

/**
 * Fold one batch of failures into the permanent history.
 *
 * Uses the journal's own timestamps, not "now": if the monitor was restarting,
 * the events it reads afterwards still carry the time they actually happened,
 * so 首次 is the true first attempt rather than "when we noticed".
 *
 * `times` is what the auto-block rule counts over its (possibly day-long)
 * window. The alerting tracker prunes to the alert window, which can be much
 * shorter, so the window timestamps live here instead — see evaluateAutoBlock.
 */
function recordHistory(grouped) {
  let changed = false;
  for (const [ip, attempts] of grouped) {
    const stamps = (attempts || []).map((a) => a && a.ts).filter(Boolean);
    if (!stamps.length && !attempts) continue;
    const min = stamps.length ? Math.min(...stamps) : null;
    const max = stamps.length ? Math.max(...stamps) : null;
    const rec = history[ip] || { firstSeen: null, lastSeen: null, total: 0, times: [] };

    if (min !== null) rec.firstSeen = rec.firstSeen ? Math.min(rec.firstSeen, min) : min;
    if (max !== null) rec.lastSeen = rec.lastSeen ? Math.max(rec.lastSeen, max) : max;
    rec.total = (rec.total || 0) + (attempts || []).length;

    // Merge, prune to the retention window, and cap. Newest are kept, so if an
    // IP is so relentless it exceeds the cap, what is lost is the oldest part
    // of the window — the count only ever under-reports for extreme cases.
    const cutoff = Date.now() - HISTORY_WINDOW_MS;
    rec.times = [...(rec.times || []), ...stamps]
      .filter((t) => t >= cutoff)
      .sort((a, b) => a - b)
      .slice(-HISTORY_CAP);

    history[ip] = rec;
    changed = true;
  }
  if (changed) scheduleSave();
}

async function tickSsh() {
  lastSshPollAt = Date.now();

  // The journal is read even when both switches are off. Recording is not the
  // same as alerting: if it stopped, turning a switch back on would replay a
  // backlog and fire a burst of stale emails, and "记录每一次失败尝试" would
  // quietly become false.
  const cursor = store.readCursor();
  const { accepted, failed, cursor: nextCursor, ok, error, truncated } = await readEventsSince(cursor);

  if (!ok) {
    lastSshError = error || 'journalctl failed';
    log({ level: 'warn', event: 'ssh_read_failed', error: lastSshError });
    // An invalid cursor (journal rotated away, machine rebuilt) must not stall
    // forever. Jumping to the newest entry loses whatever was in between, which
    // is unavoidable — the cursor no longer refers to anything.
    const fresh = await currentCursor();
    if (fresh) await store.writeCursor(fresh);
    return;
  }
  lastSshError = null;

  if (truncated) {
    // The tick read its event cap. The cursor still points at the last entry
    // actually parsed, so the next tick continues from exactly there.
    log({ level: 'warn', event: 'ssh_read_truncated', nextCursor });
  }

  if (!accepted.length && !failed.length) {
    if (nextCursor && nextCursor !== cursor) await store.writeCursor(nextCursor);
    return;
  }

  const { known, fresh: freshLogins } = classify(accepted, knownIps);

  // Seed mode: no cursor yet means this is (re)starting without history. Adopt
  // every existing IP as known and absorb existing failures, but do not email
  // about anything that happened before the monitor existed.
  if (!cursor) {
    knownIps = known;
    const grouped = groupByIp(failed);
    for (const [ip, attempts] of grouped) {
      failures.record(ip, attempts, rules.sshFailWindowMinutes * 60 * 1000);
    }
    recordHistory(grouped);
    if (nextCursor) await store.writeCursor(nextCursor);
    scheduleSave();
    log({
      level: 'info',
      event: 'ssh_seeded',
      ips: Object.keys(known).length,
      accepted: accepted.length,
      failed: failed.length,
    });
    return;
  }

  knownIps = known;
  if (nextCursor) await store.writeCursor(nextCursor);

  /* ---------------------------------------------------- new-IP logins */

  if (rules.sshAlertsEnabled) {
    for (const login of freshLogins) {
      const result = await geo.resolve(login.ip);
      knownIps[login.ip] = {
        ...knownIps[login.ip],
        geo: result.ok
          ? { country: result.country, countryCode: result.countryCode, city: result.city, org: result.org }
          : { error: result.error },
      };

      const { template, vars } = buildSshAlert({
        ip: login.ip,
        user: login.user,
        method: login.method,
        ts: login.ts,
        geo: result,
        host: HOSTNAME,
        url: PUBLIC_URL,
      });

      const sent = await sendAlert(
        { template, vars },
        { kind: 'ssh', ip: login.ip, user: login.user, country: result.ok ? result.country : null },
      );
      if (sent.ok) counters.sshAlertsSent += 1;
    }
  }
  // Switch off: the IP is still in knownIps, so enabling the switch later does
  // not back-fill alerts for logins that already happened.

  /* ------------------------------------------------------ failed logins */

  const windowMs = rules.sshFailWindowMinutes * 60 * 1000;
  const cooldownMs = rules.sshFailCooldownMinutes * 60 * 1000;

  const groupedFailures = groupByIp(failed);
  // Permanent bookkeeping happens before any alerting decision, so an IP is
  // recorded even when every switch is off.
  recordHistory(groupedFailures);

  for (const [ip, attempts] of groupedFailures) {
    const summary = failures.record(ip, attempts, windowMs);
    counters.failedAttempts += attempts.length;

    if (!rules.sshFailAlertsEnabled) continue;
    if (summary.count < rules.sshFailCount) continue;
    if (!failures.canAlert(ip, cooldownMs)) continue;

    const result = await geo.resolve(ip);
    const { template, vars } = buildSshFailAlert({
      ip,
      count: summary.count,
      windowMinutes: rules.sshFailWindowMinutes,
      users: summary.users,
      first: summary.first,
      last: summary.last,
      geo: result,
      host: HOSTNAME,
      url: PUBLIC_URL,
      cooldownMinutes: rules.sshFailCooldownMinutes,
    });

    const sent = await sendAlert(
      { template, vars },
      { kind: 'ssh-fail', ip, count: summary.count, country: result.ok ? result.country : null },
    );
    if (sent.ok) {
      failures.markAlerted(ip, Date.now());
      counters.sshFailAlertsSent += 1;
    }
  }

  failures.prune(windowMs);
  scheduleSave();
}

/* ------------------------------------------------------------ blocked tick */

/**
 * Put an IP into the kernel set and record who did it.
 *
 * `source` is stored with every entry so the panel can show a human block
 * differently from one the service made on its own. That distinction is not
 * cosmetic: an automatic block is a guess made from a rule, and an operator
 * needs to see at a glance which entries are theirs to trust and which ones
 * they may want to reverse.
 *
 * @param {string} ip
 * @param {'manual'|'auto'} source
 */
async function applyBlock(ip, source) {
  const added = await blocker.addBlock(ip);
  if (!added.ok) {
    lastNftError = added.stderr.trim() || 'nft add failed';
    log({ level: 'error', event: 'block_failed', ip, source, error: lastNftError });
    return { ok: false, error: lastNftError };
  }
  lastNftError = null;

  const rec = failures.state[ip] || {};
  blocked[ip] = {
    blockedAt: Date.now(),
    source,
    count: 0,
    lastSeen: null,
    users: rec.users || [],
    failedBeforeBlock: rec.count || 0,
  };
  await store.writeBlocked(blocked);
  scheduleSave();
  return { ok: true, failedBeforeBlock: rec.count || 0 };
}

/**
 * Block on behalf of the auto-block rule, if it is allowed to fire.
 *
 * Runs on the same cadence as the SSH poll. Being a background action that
 * changes the firewall, it is louder in the log than a manual click and it
 * records `source: "auto"` so the resulting entry is visibly not an operator's.
 */
async function tickAutoBlock() {
  if (!rules.autoBlockEnabled) return;

  const windowMs = rules.autoBlockWindowMinutes * 60 * 1000;

  // Candidates come from the permanent history, not the alerting window: an IP
  // that failed 100 times over the past day and then went quiet is exactly the
  // case the rule exists for, and the alert window would have forgotten it.
  const candidates = Object.entries(history)
    .filter(([ip, h]) => !blocked[ip] && Array.isArray(h.times) && h.times.length >= rules.autoBlockCount)
    .map(([ip]) => ip);

  if (!candidates.length) return;

  const [active, current] = await Promise.all([
    blocker.activeSshPeers(),
    blocker.listBlocked(),
  ]);
  const blockedIps = current.ok ? current.entries.map((e) => e.ip) : Object.keys(blocked);

  for (const ip of candidates) {
    const verdict = blocker.evaluateAutoBlock({
      ip,
      times: history[ip].times,
      count: rules.autoBlockCount,
      windowMs,
      failures: failures.state,
      knownIps,
      protectedIps: PROTECTED_IPS,
      activeIps: active,
      selfIps: selfIps(),
      blockedIps,
    });

    if (!verdict.ok) {
      // Only log refusals that were close to firing, otherwise a single noisy
      // IP would write a line every 20 seconds forever.
      if (verdict.code !== 'below_threshold' && verdict.code !== 'no_record') {
        log({ level: 'warn', event: 'auto_block_refused', ip, code: verdict.code });
      }
      continue;
    }

    const table = await blocker.ensureTable();
    if (!table.ok) {
      lastNftError = table.stderr.trim() || 'nft failed';
      log({ level: 'error', event: 'auto_block_failed', ip, error: lastNftError });
      return; // a broken nft must not be retried in a tight loop
    }

    const applied = await applyBlock(ip, 'auto');
    if (applied.ok) {
      log({
        level: 'info',
        event: 'ip_blocked',
        ip,
        source: 'auto',
        count: verdict.count,
        threshold: rules.autoBlockCount,
        windowMinutes: rules.autoBlockWindowMinutes,
      });
    }
  }
}

/* ------------------------------------------------------ ssh country filter */

const GEOIP_DIR = path.join(DATA_DIR, 'geoip');
const GEOIP_V4_URL = 'https://www.ipdeny.com/ipblocks/data/countries';
const GEOIP_V6_URL = 'https://www.ipdeny.com/ipv6/ipaddresses/blocks';
const GEOIP_REFRESH_MS = 24 * 60 * 60 * 1000;

const geoip = { error: null, lastFetchAt: null, appliedAt: null, v4Count: 0, v6Count: 0 };

/** Minimal text GET. The zone files are a few hundred KB; 60s is generous. */
function fetchText(url, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs, headers: { 'user-agent': 'server-panel/1.0' } }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error(`timeout fetching ${url}`)));
    req.on('error', reject);
  });
}

/**
 * Download the allow-list data for every configured country.
 *
 * Each file must clear the sanity floor in blocker.js before it is accepted:
 * a truncated or HTML error page that slipped through would otherwise shrink
 * the allow-list to nothing, and an empty allow-list rejects *everyone*.
 * Files are written only after all countries parsed, so a half-download can
 * never replace good cached data with bad.
 */
async function fetchGeoipZones(countries, { minV4, minV6, track = true } = {}) {
  const floorV4 = minV4 === undefined ? blocker.ZONE_MIN_V4 : minV4;
  const floorV6 = minV6 === undefined ? blocker.ZONE_MIN_V6 : minV6;
  const perCountry = {};
  for (const cc of countries) {
    const [raw4, raw6] = await Promise.all([
      fetchText(`${GEOIP_V4_URL}/${cc}.zone`),
      fetchText(`${GEOIP_V6_URL}/${cc}.zone`),
    ]);
    const v4 = blocker.parseZone(raw4, 4);
    const v6 = blocker.parseZone(raw6, 6);
    if (v4.length < floorV4 || v6.length < floorV6) {
      throw new Error(`${cc}.zone looks truncated (v4=${v4.length}, v6=${v6.length})`);
    }
    perCountry[cc] = { v4, v6 };
  }

  fs.mkdirSync(GEOIP_DIR, { recursive: true });
  for (const [cc, { v4, v6 }] of Object.entries(perCountry)) {
    fs.writeFileSync(path.join(GEOIP_DIR, `${cc}.zone4`), v4.join('\n') + '\n');
    fs.writeFileSync(path.join(GEOIP_DIR, `${cc}.zone6`), v6.join('\n') + '\n');
  }
  if (track) {
    geoip.lastFetchAt = Date.now();
    geoip.error = null;
  }
  return perCountry;
}

/** Cached zone data from the last successful download, or null. */
function readCachedZones(countries) {
  const perCountry = {};
  for (const cc of countries) {
    try {
      const v4 = blocker.parseZone(fs.readFileSync(path.join(GEOIP_DIR, `${cc}.zone4`), 'utf8'), 4);
      const v6 = blocker.parseZone(fs.readFileSync(path.join(GEOIP_DIR, `${cc}.zone6`), 'utf8'), 6);
      if (v4.length < blocker.ZONE_MIN_V4 || v6.length < blocker.ZONE_MIN_V6) return null;
      perCountry[cc] = { v4, v6 };
    } catch {
      return null;
    }
  }
  return perCountry;
}

/**
 * Rebuild and atomically replace the country filter table.
 *
 * Anti-lockout, in order of paranoia:
 *   1. Country data comes from cache, or a fresh fetch if there is no cache.
 *      A failed fetch throws *before* nft runs — the previous table, if any,
 *      keeps running; it is never replaced with a smaller one.
 *   2. Explicit /32 and /128 entries for PROTECTED_IPS, every IP that has ever
 *      logged in successfully, and the machine's own addresses are merged into
 *      the sets, so even stale or wrong country data cannot cut off the
 *      operator or the box itself.
 *   3. buildGeoipRuleset refuses to render an empty set at all.
 */
async function applyGeoipFilter({ forceFetch = false } = {}) {
  const countries = rules.geoipCountries;
  let zones = forceFetch ? null : readCachedZones(countries);
  let fetched = false;
  if (!zones) {
    zones = await fetchGeoipZones(countries);
    fetched = true;
  }

  const v4 = [];
  const v6 = [];
  for (const { v4: c4, v6: c6 } of Object.values(zones)) {
    v4.push(...c4);
    v6.push(...c6);
  }

  // Always-allowed singles: protected, previously-successful, self.
  for (const ip of [...PROTECTED_IPS, ...Object.keys(knownIps), ...selfIps()]) {
    const clean = blocker.normalizeIp(ip);
    if (!clean) continue;
    if (net.isIPv6(clean)) v6.push(clean);
    else v4.push(clean);
  }

  const uniqueV4 = [...new Set(v4)];
  const uniqueV6 = [...new Set(v6)];
  for (const ip of PROTECTED_IPS) {
    if (ip && !uniqueV4.includes(ip) && !uniqueV6.includes(ip)) {
      throw new Error(`internal error: ${ip} missing from allow-list`);
    }
  }

  const ruleset = blocker.buildGeoipRuleset({ v4: uniqueV4, v6: uniqueV6 });
  const applied = await blocker.applyGeoip(ruleset);
  if (!applied.ok) throw new Error(applied.stderr.trim() || 'nft failed');

  geoip.v4Count = uniqueV4.length;
  geoip.v6Count = uniqueV6.length;
  geoip.appliedAt = Date.now();
  geoip.error = null;

  log({
    level: 'info',
    event: 'geoip_applied',
    countries: countries.join(','),
    v4: uniqueV4.length,
    v6: uniqueV6.length,
    fetched,
  });
}

/** Daily refresh of the underlying data, then re-apply if the filter is on. */
async function refreshGeoip() {
  if (!rules.geoipEnabled) return;
  try {
    await applyGeoipFilter({ forceFetch: true });
  } catch (err) {
    geoip.error = err.message;
    log({ level: 'warn', event: 'geoip_refresh_failed', error: err.message });
  }
}

/* ----------------------------------------------------- traffic filter */

/**
 * Zone data for a single country, from cache or a fresh download.
 *
 * The download is lenient about the geoip allow-list's minimum size floors: a
 * small country can legitimately have fewer than 200 v4 ranges, and a web
 * filter block does not have the "reject everyone if data is bad" failure mode
 * the SSH allow-list has.
 */
async function zoneForCountry(cc) {
  const cached = readCachedZones([cc]);
  if (cached) return cached[cc];
  const fresh = await fetchGeoipZones([cc], { minV4: 1, minV6: 1, track: false });
  return fresh[cc];
}

/**
 * Addresses the filter must never cut off.
 *
 * `knownIps` holds every IP that has logged in over SSH, `PROTECTED_IPS` is the
 * explicit env list, `selfIps()` is the box itself, and panel clients are added
 * as they authenticate. Rather than refusing a rule that would cover one of
 * them, these get an `accept` at the top of the chain — otherwise "block a whole
 * country" would be impossible for an operator who lives in that country.
 */
const recentClientIps = new Set();

/** Remember the address behind an authenticated request (bounded). */
function noteClientIp(req) {
  const ip = blocker.normalizeIp(requestIp(req));
  if (!ip) return;
  recentClientIps.add(ip);
  while (recentClientIps.size > 32) recentClientIps.delete(recentClientIps.values().next().value);
}

function trafficGuardIps() {
  return [...new Set(
    [...PROTECTED_IPS, ...Object.keys(knownIps), ...selfIps(), ...recentClientIps]
      .map((ip) => blocker.normalizeIp(ip))
      .filter(Boolean),
  )];
}

function splitFamilies(ips) {
  const v4 = [];
  const v6 = [];
  for (const ip of ips) (net.isIPv6(ip) ? v6 : v4).push(ip);
  return { v4, v6 };
}

/** Complete in-memory state, for rollback when an apply fails. */
function trafficSnapshot() {
  return {
    enabled: trafficFilter.enabled,
    mode: trafficFilter.mode,
    failedHtml: trafficFilter.failedHtml,
    rules: trafficFilter.rules.map((r) => ({ ...r })),
  };
}

function trafficFilterPayload(live = null) {
  const status = live || { ok: true, active: false, v4Count: 0, v6Count: 0, dropRules: 0, allowRules: 0, exemptRules: 0, droppedPackets: 0, allowedPackets: 0, exemptPackets: 0 };
  return {
    ok: true,
    enabled: Boolean(trafficFilter.enabled),
    mode: trafficfilter.MODES.includes(trafficFilter.mode) ? trafficFilter.mode : 'drop',
    failedUrl: trafficfilter.FAILED_URL,
    failedHtml: typeof trafficFilter.failedHtml === 'string' ? trafficFilter.failedHtml : failedPage.DEFAULT_FAILED_HTML,
    defaultFailedHtml: failedPage.DEFAULT_FAILED_HTML,
    maxFailedBytes: failedPage.MAX_FAILED_HTML,
    rules: trafficfilter.sortRules(trafficFilter.rules.map((r) => ({ ...r }))),
    active: Boolean(status.active),
    appliedAt: trafficState.appliedAt,
    error: trafficState.error || (status.ok ? null : status.error),
    v4Count: status.v4Count,
    v6Count: status.v6Count,
    dropRules: status.dropRules,
    allowRules: status.allowRules,
    exemptRules: status.exemptRules,
    droppedPackets: status.droppedPackets,
    allowedPackets: status.allowedPackets,
    exemptPackets: status.exemptPackets,
    exemptIps: trafficGuardIps(),
    webCounts: trafficState.webCounts,
    cfTrusted: trafficState.cfTrusted,
    defaultPort: trafficfilter.DEFAULT_PORT_SPEC,
    maxRules: trafficfilter.MAX_RULES,
  };
}

/* --------------------------------------------------- nginx block list sync */

// Root-owned helper installed by deploy.sh; the only command monsvc may run via
// sudo. It validates the staged files, installs them, runs `nginx -t` and swaps
// the configuration in one go (rolling back on any failure).
const WEB_HELPER = process.env.NGINX_TF_HELPER || '/usr/local/libexec/monitor-nginx-tf';
const STAGE_DIR = path.join(store.dir, 'nginx');
const NGINX_CONF = '/etc/nginx/conf.d/monitor-traffic-filter.conf';

const EMPTY_WEB = { '80': { v4: [], v6: [] }, '443': { v4: [], v6: [] } };

/** `geo` include body: one `<cidr> 1;` per line. */
function mapLines(bucket) {
  const lines = [...bucket.v4, ...bucket.v6].map((cidr) => `${cidr} 1;`);
  return lines.length ? `${lines.join('\n')}\n` : '';
}

async function writeStaging(name, content) {
  await fs.promises.mkdir(STAGE_DIR, { recursive: true, mode: 0o750 });
  const target = path.join(STAGE_DIR, name);
  const tmp = path.join(STAGE_DIR, `.${name}.${process.pid}.tmp`);
  await fs.promises.writeFile(tmp, content, { mode: 0o640 });
  await fs.promises.rename(tmp, target);
}

function runHelper() {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('sudo', ['-n', WEB_HELPER], { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      resolve({ ok: false, stdout: '', stderr: String(err.message) });
      return;
    }
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('error', (err) => resolve({ ok: false, stdout, stderr: String(err.message) }));
    child.on('close', (code) => resolve({ ok: code === 0, stdout, stderr }));
  });
}

function nginxConfigured() {
  try {
    return fs.existsSync(NGINX_CONF);
  } catch {
    return false;
  }
}

/**
 * Push the flat block list and the current mode to nginx.
 *
 * In `drop` mode nothing on the nginx side may exist, so a failure to clear it
 * is fatal — otherwise stale pages would keep answering. When the helper has
 * never been installed and there is nothing to clear, the sync is skipped so an
 * older deployment keeps working.
 */
async function syncNginx(web, mode, webAllow = null) {
  // The public sites sit behind Cloudflare. Trusting CF-Connecting-IP from
  // Cloudflare's own ranges makes nginx see the visitor's real address, so the
  // country/CIDR maps below match the visitor instead of a Cloudflare edge.
  const cf = await cloudflare.currentRanges(path.join(store.dir, 'cloudflare-ranges.json'));
  trafficState.cfTrusted = {
    v4: cf.v4.length,
    v6: cf.v6.length,
    source: cf.source,
    fetchedAt: cf.fetchedAt || null,
  };

  // The exemption map is used a second time when Cloudflare supplies the
  // country. Without it the CF-IPCountry fallback could block the operator's
  // own address or an explicit allow rule even though the country CIDR map
  // already subtracts them.
  const exempt = splitFamilies(trafficGuardIps());
  if (webAllow) {
    for (const port of trafficfilter.WEB_PORTS) {
      const bucket = webAllow[String(port)];
      if (bucket) {
        exempt.v4.push(...bucket.v4);
        exempt.v6.push(...bucket.v6);
      }
    }
  }

  await writeStaging('mode', `${mode}\n`);
  await writeStaging('cf.map', mapLines({ v4: cf.v4, v6: cf.v6 }));
  await writeStaging('tf-exempt.map', mapLines(exempt));
  await writeStaging('tf-80.map', mapLines(web['80']));
  await writeStaging('tf-443.map', mapLines(web['443']));
  await writeStaging('index.html', trafficFilter.failedHtml);

  const res = await runHelper();
  if (res.ok) return;
  const detail = (res.stderr || res.stdout || 'unknown error').trim();
  if (mode === 'drop' && !nginxConfigured()) {
    log({ level: 'warn', event: 'trafficfilter_nginx_skipped', reason: detail.slice(0, 300) });
    return;
  }
  throw new Error(`nginx 同步失败：${detail}`);
}

/**
 * Rebuild the filter: nginx block list first, then the nft table.
 *
 * Order is deliberate. nginx is only told to answer 404/redirect while the
 * kernel still drops the same addresses, so turning on "failure page" never
 * opens a gap. The nft ruleset is validated with `nft -c` before either side is
 * touched. A failed nft apply leaves the previous table in place.
 */
// Every apply rewrites staging files, nginx and the nft table. Two overlapping
// requests (a double-click on the mode picker, or a save while a toggle is still
// running) would interleave their snapshots and could leave the in-memory mode
// different from what is on disk. Serialize them: each call waits for the
// previous one, and a failure does not poison the chain.
let trafficApplyChain = Promise.resolve();

function applyTrafficFilter() {
  const next = trafficApplyChain.then(
    () => applyTrafficFilterNow(),
    () => applyTrafficFilterNow(),
  );
  trafficApplyChain = next.catch(() => {});
  return next;
}

async function applyTrafficFilterNow() {
  const active = trafficFilter.rules.filter((r) => r && r.enabled !== false);

  const zones = {};
  for (const rule of active) {
    if (rule.type === 'country' && !zones[rule.value]) {
      zones[rule.value] = await zoneForCountry(rule.value);
    }
  }
  const zoneFor = (cc) => zones[cc];
  const guards = trafficGuardIps();
  const exempt = splitFamilies(guards);
  const enabled = Boolean(trafficFilter.enabled) && active.length > 0;
  const mode = enabled ? trafficFilter.mode : 'drop';

  if (!enabled) {
    await syncNginx(EMPTY_WEB, 'drop');
    const removed = await trafficfilter.removeTable();
    if (!removed.ok) throw new Error(removed.stderr.trim() || 'nft delete failed');
    trafficState.error = null;
    trafficState.appliedAt = Date.now();
    trafficState.v4Count = 0;
    trafficState.v6Count = 0;
    trafficState.dropRules = 0;
    trafficState.allowRules = 0;
    trafficState.webCounts = null;
    log({ level: 'info', event: 'trafficfilter_removed' });
    return { active: false };
  }

  const web = trafficfilter.webBlockList(trafficFilter.rules, zoneFor, { exempt });
  const webAllow = trafficfilter.webAllowList(trafficFilter.rules, zoneFor);
  const ruleset = trafficfilter.buildRuleset(trafficFilter.rules, zoneFor, {
    exempt,
    webAnswer: mode === 'drop' ? null : trafficfilter.WEB_PORTS,
  });

  if (ruleset) {
    const checked = await trafficfilter.check(ruleset);
    if (!checked.ok) throw new Error(`nft 校验失败：${checked.stderr.trim() || 'nft -c failed'}`);
  }

  await syncNginx(web, mode, webAllow);

  if (ruleset) {
    const res = await trafficfilter.apply(ruleset);
    if (!res.ok) throw new Error(res.stderr.trim() || 'nft failed');
  } else {
    // Every rule was 80/443-only, so nginx answers all of it.
    const removed = await trafficfilter.removeTable();
    if (!removed.ok) throw new Error(removed.stderr.trim() || 'nft delete failed');
  }

  const live = await trafficfilter.tableStatus();
  trafficState.error = live.ok ? null : live.error;
  trafficState.appliedAt = Date.now();
  trafficState.v4Count = live.v4Count || 0;
  trafficState.v6Count = live.v6Count || 0;
  trafficState.dropRules = live.dropRules || 0;
  trafficState.allowRules = live.allowRules || 0;
  trafficState.webCounts = {
    p80: web['80'].v4.length + web['80'].v6.length,
    p443: web['443'].v4.length + web['443'].v6.length,
  };

  log({
    level: 'info',
    event: 'trafficfilter_applied',
    mode,
    rules: active.length,
    v4: trafficState.v4Count,
    v6: trafficState.v6Count,
    web80: trafficState.webCounts.p80,
    web443: trafficState.webCounts.p443,
    exempt: guards.length,
  });
  return { active: true };
}

async function saveTrafficFilterState() {
  trafficFilter = {
    enabled: Boolean(trafficFilter.enabled),
    mode: trafficfilter.MODES.includes(trafficFilter.mode) ? trafficFilter.mode : 'drop',
    failedHtml: typeof trafficFilter.failedHtml === 'string' ? trafficFilter.failedHtml : failedPage.DEFAULT_FAILED_HTML,
    rules: trafficFilter.rules.map((r) => ({ ...r })),
  };
  await store.writeTrafficFilter(trafficFilter);
}

/**
 * Follow the kernel's netfilter log for attempts that arrive *after* a block.
 *
 * Once an IP is in the nft set its packets are dropped before sshd ever sees
 * them, so those attempts do not appear in the ssh unit's journal at all. The
 * panel promises to show them anyway, and the kernel log is the only place they
 * exist. The nft set's own per-IP counters provide the authoritative total if
 * the log has rotated.
 */
async function tickBlocked() {
  if (!Object.keys(blocked).length) return;

  const cursor = store.readBlockCursor();
  const { entries, cursor: nextCursor, ok, error } = await readBlockedSince(cursor);

  if (!ok) {
    if (error) log({ level: 'warn', event: 'kernel_read_failed', error });
    const fresh = await currentKernelCursor();
    if (fresh) await store.writeBlockCursor(fresh);
    return;
  }
  if (nextCursor && nextCursor !== cursor) await store.writeBlockCursor(nextCursor);
  if (!entries.length) return;

  let changed = false;
  for (const entry of entries) {
    const rec = blocked[entry.ip];
    if (!rec) continue; // an IP we no longer track; ignore stragglers

    // The kernel cursor can lag behind a *re-*block: if an IP was blocked,
    // unblocked, and blocked again, the log still holds drops from the first
    // block. Counting those would overstate "attempts since blocking", so only
    // take lines that are actually newer than this block.
    if (rec.blockedAt && entry.ts && entry.ts < rec.blockedAt - 1000) continue;

    rec.count = (rec.count || 0) + 1;
    rec.lastSeen = entry.ts;
    if (!rec.firstAfterBlockAt) rec.firstAfterBlockAt = entry.ts;
    changed = true;
  }

  if (changed) scheduleSave();
}

/**
 * Country/organisation for an IP, from whichever source has it.
 *
 * Order matters. `knownIps` only ever contains IPs that logged in *successfully*,
 * so reading it first — as the blocked list used to — returned null for every
 * blocked IP, which is why the panel showed no country for any of them. The geo
 * cache is the general-purpose store; `knownIps` is the fallback for records
 * written before the cache existed.
 */
function geoOf(ip) {
  const cached = geo.get(ip);
  if (cached && cached.ok) return cached;
  const fromKnown = knownIps[ip] && knownIps[ip].geo;
  if (fromKnown && fromKnown.ok) return fromKnown;
  return cached || null;
}

/**
 * Fill in missing geo data in the background.
 *
 * Lookups are HTTP calls, so the API endpoints must never await them; the panel
 * just shows nothing for one refresh and the country appears on the next one.
 */
function warmGeo(ips) {
  for (const ip of ips) {
    if (geoOf(ip)) continue;
    geo.resolve(ip).then((result) => {
      if (result && result.ok) scheduleSave();
    }).catch(() => {});
  }
}

/**
 * The most recent failure timestamp ever seen for an IP.
 *
 * `failures` prunes on a rolling window, so "最近" used to drift backwards and
 * eventually disappear once an attacker gave up — losing the record of when the
 * attack actually happened. `firstSeen`/`lastSeen` are kept forever and only
 * cleared by an explicit reset.
 */
function firstLast(ip) {
  const rec = failures.state[ip];
  const hist = history[ip] || {};
  const first = [hist.firstSeen, rec && rec.firstSeen, rec && rec.times && rec.times[0]]
    .filter(Boolean).reduce((a, b) => Math.min(a, b), Infinity);
  const last = [hist.lastSeen, rec && rec.lastSeen, rec && rec.times && rec.times[rec.times.length - 1]]
    .filter(Boolean).reduce((a, b) => Math.max(a, b), -Infinity);
  return {
    first: Number.isFinite(first) ? first : null,
    last: Number.isFinite(last) ? last : null,
  };
}

/* ------------------------------------------------------------------- http */

function send(res, status, body, headers = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  res.writeHead(status, { 'Content-Length': buf.length, ...headers });
  res.end(buf);
}

function json(res, status, payload, headers = {}) {
  send(res, status, JSON.stringify(payload), {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req, limit = 64 * 1024) {
  const buf = await readBody(req, limit);
  if (!buf.length) return {};
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw Object.assign(new Error('invalid JSON'), { status: 400 });
  }
}

function statusPayload() {
  return {
    ok: true,
    host: HOSTNAME,
    now: Date.now(),
    rules,
    sample: latestSample,
    lastSampleAt,
    sampleIntervalMs: SAMPLE_INTERVAL_MS,
    ssh: {
      enabled: rules.sshAlertsEnabled,
      failAlertsEnabled: rules.sshFailAlertsEnabled,
      lastPollAt: lastSshPollAt,
      knownIps: Object.keys(knownIps).length,
      trackedFailIps: failures.size,
      lastError: lastSshError,
    },
    counters,
    lastError,
    mail: {
      socket: mailConfig.socket,
      configured: Boolean(mail),
      to: ALERT_TO,
    },
    blocks: {
      total: Object.keys(blocked).length,
      manual: Object.values(blocked).filter((r) => r.source === 'manual').length,
      auto: Object.values(blocked).filter((r) => r.source === 'auto').length,
      nftError: lastNftError,
      protectedIps: PROTECTED_IPS,
      // Kept out of `auto`: that key is the count of auto-blocked IPs above.
      autoBlock: {
        enabled: rules.autoBlockEnabled,
        count: rules.autoBlockCount,
        windowMinutes: rules.autoBlockWindowMinutes,
      },
    },
  };
}

const server = http.createServer(async (req, res) => {
  let pathname = '/';
  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch {
    json(res, 400, { ok: false, error: 'bad_request' });
    return;
  }

  try {
    // Unauthenticated: used by systemd/curl and by nginx health checks. It
    // exposes no secrets and never reveals sample contents.
    if (req.method === 'GET' && pathname === '/health') {
      json(res, 200, { ok: true, uptime: process.uptime(), monitored: rules.enabled });
      return;
    }

    if (req.method === 'GET' && pathname === '/login') {
      send(res, 200, loginPage(), {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/login') {
      const body = await readJson(req);
      if (!auth.enabled) {
        json(res, 503, { ok: false, error: 'auth_disabled', message: 'MONITOR_PASSWORD / MONITOR_SECRET 未设置' });
        return;
      }
      if (!auth.checkPassword(body.password)) {
        log({ level: 'warn', event: 'login_failed', ip: req.socket.remoteAddress });
        json(res, 401, { ok: false, error: 'bad_password' });
        return;
      }
      const token = auth.issueToken();
      json(res, 200, { ok: true, csrf: auth.csrfFor({ headers: { cookie: `mon_session=${token}` } }) }, {
        'Set-Cookie': auth.cookieHeader(token),
      });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/logout') {
      json(res, 200, { ok: true }, { 'Set-Cookie': auth.clearCookieHeader() });
      return;
    }

    if (!auth.isAuthed(req)) {
      if (pathname.startsWith('/api/')) json(res, 401, { ok: false, error: 'unauthorized' });
      else send(res, 302, '', { Location: '/login' });
      return;
    }

    // Any address that can log in to the panel is one we must not lock out of
    // it — remember it for the traffic filter's exemption set.
    noteClientIp(req);

    if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      send(res, 200, fs.readFileSync(UI_FILE), {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/session') {
      json(res, 200, { ok: true, csrf: auth.csrfFor(req) });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/status') {
      json(res, 200, statusPayload());
      return;
    }

    if (req.method === 'GET' && pathname === '/api/history') {
      json(res, 200, { ok: true, alerts: store.readAlerts(50) });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/config') {
      json(res, 200, { ok: true, rules, defaults: DEFAULTS, to: ALERT_TO });
      return;
    }

    if ((req.method === 'POST' || req.method === 'PUT') && pathname === '/api/config') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }
      const body = await readJson(req);
      const geoipChanged = Array.isArray(body.geoipCountries) &&
        JSON.stringify(body.geoipCountries) !== JSON.stringify(rules.geoipCountries);
      const next = normalizeRules({ ...rules, ...body });

      // An empty allow-list would only ever match the protected/self IPs —
      // practically locking the operator out of a country they forgot to
      // re-check. Refuse it rather than loading it.
      if (next.geoipEnabled && next.geoipCountries && !next.geoipCountries.length) {
        json(res, 400, { ok: false, error: '至少选择一个国家/地区，否则会把你自己的 SSH 也拒绝掉' });
        return;
      }

      rules = next;
      state = emptyState(Date.now()); // thresholds changed: old counters are meaningless
      await saveRules();
      log({ level: 'info', event: 'rules_updated', rules });

      // Country checkboxes on the panel save through this endpoint. The nft
      // table holds the *old* selection until rebuilt, so apply immediately
      // when the whitelist is live — otherwise the panel would say one thing
      // and the kernel do another.
      if (geoipChanged && rules.geoipEnabled) {
        applyGeoipFilter().catch((err) => {
          geoip.error = err.message;
          log({ level: 'warn', event: 'geoip_apply_failed', error: err.message });
        });
      }

      json(res, 200, { ok: true, rules });
      return;
    }

    // Manual test: proves the whole path (socket → mail panel → Resend) works
    // without waiting for a real incident.
    if (req.method === 'POST' && pathname === '/api/test-alert') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }
      const body = await readJson(req);
      const kind = body.kind === 'ssh' ? 'ssh' : body.kind === 'ssh-fail' ? 'ssh-fail' : 'resource';
      const sample = latestSample || { mem: null, net: null, cpuPercent: null, cpuCores: os.cpus().length };

      let built;
      if (kind === 'ssh') {
        built = buildSshAlert({
          ip: '203.0.113.42',
          user: 'root',
          method: 'password',
          ts: Date.now(),
          geo: { ok: true, country: '测试', city: '测试城市', org: 'TEST-NET-3', timezone: 'UTC' },
          host: HOSTNAME,
          url: PUBLIC_URL,
        });
      } else if (kind === 'ssh-fail') {
        const now = Date.now();
        built = buildSshFailAlert({
          ip: '203.0.113.42',
          count: rules.sshFailCount,
          windowMinutes: rules.sshFailWindowMinutes,
          users: ['root', 'admin'],
          first: now - 8 * 60 * 1000,
          last: now,
          geo: { ok: true, country: '测试', city: '测试城市', org: 'TEST-NET-3' },
          host: HOSTNAME,
          url: PUBLIC_URL,
          cooldownMinutes: rules.sshFailCooldownMinutes,
        });
      } else {
        built = buildResourceAlert({
          action: {
            metric: 'mem',
            value: sample.memPercent || rules.memPercent,
            threshold: rules.memPercent,
            consecutive: rules.consecutive,
            windowCount: rules.windowCount,
            peak: sample.memPercent || null,
            reason: 'both',
          },
          sample,
          rules,
          host: HOSTNAME,
          url: PUBLIC_URL,
        });
      }

      built.vars.title = `[测试] ${built.vars.title}`;
      built.vars.detail = `这是一封测试邮件，由 ${PUBLIC_URL} 的「发送测试」按钮触发，不代表真实告警。\n\n${built.vars.detail}`;

      const result = await sendAlert({ ...built }, { kind: `test-${kind}` });
      json(res, result.ok ? 200 : 502, result);
      return;
    }

    if (req.method === 'GET' && pathname === '/api/known-ips') {
      const list = Object.entries(knownIps)
        .map(([ip, rec]) => ({ ip, ...rec }))
        .sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
        .slice(0, 200);
      json(res, 200, { ok: true, ips: list });
      return;
    }

    // Failed-attempt view: every IP currently inside the window, with its count.
    //
    // Blocked IPs are merged in on purpose. Once an IP is dropped by nftables it
    // never reaches sshd, so it would silently vanish from this table — the
    // panel would look like the attacks stopped, which is exactly when an
    // operator stops paying attention. They stay listed, flagged, with the
    // attempt count that keeps growing.
    if (req.method === 'GET' && pathname === '/api/ssh-failures') {
      const windowMs = rules.sshFailWindowMinutes * 60 * 1000;
      failures.prune(windowMs);

      const list = Object.entries(failures.state).map(([ip, rec]) => ({
        ip,
        count: rec.count || 0,
        users: rec.users || [],
        // 首次 / 最近 come from the permanent history, not the rolling window.
        first: firstLast(ip).first,
        last: firstLast(ip).last,
        totalEver: (history[ip] && history[ip].total) || rec.count || 0,
        lastAlertAt: rec.lastAlertAt || null,
        threshold: rules.sshFailCount,
        blocked: Boolean(blocked[ip]),
        blockSource: blocked[ip] ? blocked[ip].source || null : null,
      }));

      // Blocked IPs whose failure window has aged out still belong in the list:
      // they are still blocked and still being dropped.
      for (const [ip, rec] of Object.entries(blocked)) {
        if (list.some((r) => r.ip === ip)) continue;
        list.push({
          ip,
          count: 0,
          users: [],
          first: firstLast(ip).first,
          last: firstLast(ip).last || rec.lastSeen || rec.blockedAt || null,
          totalEver: (history[ip] && history[ip].total) || 0,
          lastAlertAt: null,
          threshold: rules.sshFailCount,
          blocked: true,
          blockSource: rec.source || null,
        });
      }

      // The same goes for IPs that are neither: 首次/最近/累计 are permanent
      // records, so an attacker whose alert window has simply aged out must
      // stay visible — otherwise the record the user asked to keep "until
      // manually cleared" silently vanishes from the panel on its own.
      for (const ip of Object.keys(history)) {
        if (failures.state[ip] || blocked[ip]) continue;
        list.push({
          ip,
          count: 0,
          users: [],
          first: firstLast(ip).first,
          last: firstLast(ip).last,
          totalEver: history[ip].total || 0,
          lastAlertAt: null,
          threshold: rules.sshFailCount,
          blocked: false,
          blockSource: null,
        });
      }

      for (const row of list) {
        const rec = blocked[row.ip];
        if (!rec) {
          row.blockedAt = null;
          row.droppedSinceBlock = 0;
          continue;
        }
        row.blockedAt = rec.blockedAt || null;
        row.source = rec.source || null;
        row.droppedSinceBlock = rec.count || 0;
        if (rec.lastSeen) row.last = Math.max(row.last || 0, rec.lastSeen);
        // A blocked IP's traffic never reaches sshd, so "attempts" means
        // "attempts the kernel dropped after the block".
        row.attempts = rec.count || 0;
      }

      // Rank by the biggest of the three numbers that matter: live drops for a
      // blocked IP, current-window failures for an active one, and the
      // permanent total for an attacker that has since gone quiet.
      list.sort((a, b) =>
        Math.max(b.attempts || 0, b.count || 0, b.totalEver || 0) -
        Math.max(a.attempts || 0, a.count || 0, a.totalEver || 0));

      warmGeo(list.map((r) => r.ip));

      json(res, 200, {
        ok: true,
        windowMinutes: rules.sshFailWindowMinutes,
        threshold: rules.sshFailCount,
        nftAvailable: lastNftError === null,
        nftError: lastNftError,
        protectedIps: PROTECTED_IPS,
        ips: list.slice(0, 200),
      });
      return;
    }

    // Clearing the permanent history is explicit and separate from unlocking:
    // an operator may want to forget an IP's track record without changing what
    // the firewall is doing, and vice versa.
    if (req.method === 'POST' && pathname === '/api/fail-history/clear') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const target = blocker.normalizeIp(body.ip);
      const cleared = Object.keys(history).length;

      if (target) {
        delete history[target];
      } else {
        for (const ip of Object.keys(history)) delete history[ip];
      }
      await store.writeHistory(history);

      log({ level: 'info', event: 'fail_history_cleared', ip: target || null, entries: target ? 1 : cleared });
      json(res, 200, { ok: true, cleared: target ? 1 : cleared });
      return;
    }

    // ---- SSH country filter ---------------------------------------------
    if (req.method === 'GET' && pathname === '/api/geoip') {
      const live = await blocker.geoipTableStatus();
      json(res, 200, {
        ok: true,
        enabled: rules.geoipEnabled,
        countries: rules.geoipCountries,
        active: live.ok ? live.active : false,
        v4Count: live.ok && live.active ? live.v4Count : geoip.v4Count,
        v6Count: live.ok && live.active ? live.v6Count : geoip.v6Count,
        acceptedPackets: live.ok && live.active ? live.acceptedPackets : 0,
        rejectedPackets: live.ok && live.active ? live.rejectedPackets : 0,
        lastFetchAt: geoip.lastFetchAt,
        appliedAt: geoip.appliedAt,
        error: geoip.error || (live.ok ? null : live.error),
        protectedIps: PROTECTED_IPS,
      });
      return;
    }

    // Turning the filter on can fail (network, nft). Only persist the switch
    // after the table is actually live, otherwise a silent reload would bring
    // back a half-enabled state with no rule set behind it.
    if (req.method === 'POST' && pathname === '/api/geoip/toggle') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const enable = body.enabled === true;

      try {
        if (enable) {
          await applyGeoipFilter();
        } else {
          await blocker.removeGeoipTable();
        }
      } catch (err) {
        geoip.error = err.message;
        log({ level: 'warn', event: 'geoip_toggle_failed', enable, error: err.message });
        json(res, 500, { ok: false, error: err.message });
        return;
      }

      rules = normalizeRules({ ...rules, geoipEnabled: enable });
      await saveRules();
      log({ level: 'info', event: 'geoip_toggled', enabled: enable });
      json(res, 200, { ok: true, enabled: enable });
      return;
    }

    // ---- firewall-level traffic filter ------------------------------------
    if (req.method === 'GET' && pathname === '/api/trafficfilter') {
      const live = await trafficfilter.tableStatus();
      json(res, 200, trafficFilterPayload(live));
      return;
    }

    // Turning the filter on/off is a firewall change: only persist the switch
    // once nft has actually accepted (or removed) the table. A failed apply
    // leaves the old ruleset untouched, so the in-memory state is rolled back
    // to match reality.
    if (req.method === 'POST' && pathname === '/api/trafficfilter/toggle') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const enable = body.enabled === true;
      const snapshot = trafficSnapshot();

      trafficFilter = { ...trafficFilter, enabled: enable };
      try {
        await applyTrafficFilter();
      } catch (err) {
        trafficFilter = snapshot;
        trafficState.error = err.message;
        log({ level: 'warn', event: 'trafficfilter_toggle_failed', enable, error: err.message });
        json(res, 500, { ok: false, error: err.message });
        return;
      }

      await saveTrafficFilterState();
      log({ level: 'info', event: 'trafficfilter_toggled', enabled: enable });
      json(res, 200, trafficFilterPayload(await trafficfilter.tableStatus()));
      return;
    }

    // Response mode for blocked HTTP/HTTPS clients: drop | 404 | redirect.
    // Switching modes rewrites nginx and the nft table, so it is applied before
    // being persisted and rolled back on failure, exactly like the switch above.
    if (req.method === 'POST' && pathname === '/api/trafficfilter/mode') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const mode = String(body.mode || '');
      if (!trafficfilter.MODES.includes(mode)) {
        json(res, 400, { ok: false, error: 'bad_mode', reason: 'mode 只能是 drop、404 或 redirect' });
        return;
      }

      const snapshot = trafficSnapshot();
      trafficFilter = { ...trafficFilter, mode };
      try {
        await applyTrafficFilter();
      } catch (err) {
        trafficFilter = snapshot;
        trafficState.error = err.message;
        log({ level: 'warn', event: 'trafficfilter_mode_failed', mode, error: err.message });
        json(res, 500, { ok: false, error: err.message });
        return;
      }

      await saveTrafficFilterState();
      log({ level: 'info', event: 'trafficfilter_mode_changed', mode });
      json(res, 200, trafficFilterPayload(await trafficfilter.tableStatus()));
      return;
    }

    // Editable body of the failure page (served by blocked.example.com).
    // Stored as plain HTML and copied to a static file, never into a directive.
    if (req.method === 'POST' && pathname === '/api/trafficfilter/failedpage') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req, failedPage.MAX_FAILED_HTML * 4 + 64 * 1024);
      let html;
      try {
        html = failedPage.normalizeFailedHtml(body.html);
      } catch (err) {
        json(res, err.status || 400, { ok: false, error: err.code || 'bad_html', reason: err.message });
        return;
      }

      const snapshot = trafficSnapshot();
      trafficFilter = { ...trafficFilter, failedHtml: html };
      try {
        await applyTrafficFilter();
      } catch (err) {
        trafficFilter = snapshot;
        trafficState.error = err.message;
        json(res, 500, { ok: false, error: err.message });
        return;
      }

      await saveTrafficFilterState();
      log({ level: 'info', event: 'trafficfilter_failedpage_saved', bytes: html.length });
      json(res, 200, trafficFilterPayload(await trafficfilter.tableStatus()));
      return;
    }

    // Create or update one rule. The body may carry an `id` (edit) or not
    // (create). Validation, the lockout guard and the nft transaction all
    // happen before anything is persisted.
    if (req.method === 'POST' && pathname === '/api/trafficfilter/save') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const snapshot = trafficSnapshot();

      let rule;
      try {
        rule = trafficfilter.normalizeRule(body, {
          id: typeof body.id === 'string' && body.id ? body.id : `w${crypto.randomUUID()}`,
        });
      } catch (err) {
        json(res, err.status || 400, { ok: false, error: err.code || 'invalid_rule', reason: err.message });
        return;
      }

      const index = trafficFilter.rules.findIndex((r) => r.id === rule.id);
      const nextRules = trafficFilter.rules.slice();
      if (index === -1) nextRules.push(rule);
      else nextRules[index] = rule;

      if (nextRules.length > trafficfilter.MAX_RULES) {
        json(res, 400, { ok: false, error: 'too_many_rules', reason: `规则最多 ${trafficfilter.MAX_RULES} 条` });
        return;
      }

      trafficFilter = { ...trafficFilter, rules: nextRules };
      try {
        await applyTrafficFilter();
      } catch (err) {
        trafficFilter = snapshot;
        trafficState.error = err.message;
        json(res, 502, { ok: false, error: 'nft_failed', reason: err.message });
        return;
      }

      await saveTrafficFilterState();
      log({ level: 'info', event: 'trafficfilter_rule_saved', id: rule.id, type: rule.type, action: rule.action });
      json(res, 200, trafficFilterPayload(await trafficfilter.tableStatus()));
      return;
    }

    if (req.method === 'POST' && pathname === '/api/trafficfilter/delete') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const id = typeof body.id === 'string' ? body.id : '';
      const snapshot = trafficSnapshot();
      const nextRules = trafficFilter.rules.filter((r) => r.id !== id);
      if (nextRules.length === trafficFilter.rules.length) {
        json(res, 404, { ok: false, error: 'not_found', reason: '没有这条规则' });
        return;
      }

      trafficFilter = { ...trafficFilter, rules: nextRules };
      try {
        await applyTrafficFilter();
      } catch (err) {
        trafficFilter = snapshot;
        trafficState.error = err.message;
        json(res, 502, { ok: false, error: 'nft_failed', reason: err.message });
        return;
      }

      await saveTrafficFilterState();
      log({ level: 'info', event: 'trafficfilter_rule_deleted', id });
      json(res, 200, trafficFilterPayload(await trafficfilter.tableStatus()));
      return;
    }

    // ---- manual SSH block / unblock -------------------------------------
    //
    // Both endpoints are POST + CSRF: a link prefetch or a stray GET must never
    // be able to change the firewall.
    if (req.method === 'POST' && pathname === '/api/block') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const ip = blocker.normalizeIp(body.ip);
      if (!ip) {
        json(res, 400, { ok: false, error: 'no_ip', reason: '没有提供 IP' });
        return;
      }

      // Gather every fact the guard needs, then let the pure function decide.
      // Keeping the decision in blocker.js is what makes the refusals testable.
      const [active, current] = await Promise.all([
        blocker.activeSshPeers(),
        blocker.listBlocked(),
      ]);

      const verdict = blocker.evaluateBlockRequest({
        ip,
        failures: failures.state,
        knownIps,
        protectedIps: PROTECTED_IPS,
        activeIps: active,
        selfIps: selfIps(),
        blockedIps: current.ok ? current.entries.map((e) => e.ip) : Object.keys(blocked),
      });

      if (!verdict.ok) {
        log({ level: 'warn', event: 'block_refused', ip, code: verdict.code });
        json(res, 400, { ok: false, error: verdict.code, reason: verdict.reason });
        return;
      }

      const table = await blocker.ensureTable();
      if (!table.ok) {
        lastNftError = table.stderr.trim() || 'nft failed';
        log({ level: 'error', event: 'block_failed', ip, error: lastNftError });
        json(res, 502, { ok: false, error: 'nft_failed', reason: lastNftError });
        return;
      }

      const applied = await applyBlock(ip, 'manual');
      if (!applied.ok) {
        json(res, 502, { ok: false, error: 'nft_failed', reason: applied.error });
        return;
      }

      log({ level: 'info', event: 'ip_blocked', ip, source: 'manual', failedBeforeBlock: applied.failedBeforeBlock });
      json(res, 200, { ok: true, ip, blocked });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/unblock') {
      const csrf = req.headers['x-csrf-token'];
      if (!auth.checkCsrf(req, String(csrf || ''))) {
        json(res, 403, { ok: false, error: 'bad_csrf' });
        return;
      }

      const body = await readJson(req);
      const ip = blocker.normalizeIp(body.ip);
      if (!ip) {
        json(res, 400, { ok: false, error: 'no_ip', reason: '没有提供 IP' });
        return;
      }

      const removed = await blocker.removeBlock(ip);
      // "not in set" is success for an unblock: the desired end state is
      // reached either way. Any other failure is real.
      if (!removed.ok && !/No such file|does not exist|No such element/i.test(removed.stderr)) {
        lastNftError = removed.stderr.trim() || 'nft delete failed';
        json(res, 502, { ok: false, error: 'nft_failed', reason: lastNftError });
        return;
      }
      lastNftError = null;

      delete blocked[ip];
      await store.writeBlocked(blocked);
      scheduleSave();

      log({ level: 'info', event: 'ip_unblocked', ip });
      json(res, 200, { ok: true, ip });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/blocked') {
      const live = await blocker.listBlocked();
      if (!live.ok) lastNftError = live.error || 'nft list failed';

      const list = Object.entries(blocked).map(([ip, rec]) => {
        const hit = live.entries.find((e) => e.ip === ip);
        return {
          ip,
          blockedAt: rec.blockedAt || null,
          // 'manual' = an operator clicked it, 'auto' = the threshold rule fired.
          // Null for entries recovered from the kernel set with no audit record.
          source: rec.source || null,
          autoThreshold: rec.source === 'auto'
            ? { count: rules.autoBlockCount, windowMinutes: rules.autoBlockWindowMinutes }
            : null,
          failedBeforeBlock: rec.failedBeforeBlock || 0,
          droppedSinceBlock: rec.count || 0,
          // The nft counter is the truth even if the kernel log rotated away.
          packets: hit ? hit.packets : 0,
          bytes: hit ? hit.bytes : 0,
          lastSeen: rec.lastSeen || null,
          users: rec.users || [],
          // The geo cache is the right source, not known-ips: a blocked IP has
          // by definition never logged in successfully, so it is not in
          // known-ips at all and that lookup returned null for every entry.
          geo: geoOf(ip),
          inKernelSet: Boolean(hit),
        };
      });

      // Anything in the nft set that the audit file lost (restored backup, manual
      // nft command) is still a real block, so surface it rather than hide it.
      for (const entry of live.entries) {
        if (list.some((r) => r.ip === entry.ip)) continue;
        list.push({
          ip: entry.ip,
          blockedAt: null,
          failedBeforeBlock: 0,
          droppedSinceBlock: 0,
          packets: entry.packets,
          bytes: entry.bytes,
          lastSeen: null,
          users: [],
          geo: null,
          inKernelSet: true,
        });
      }

      list.sort((a, b) => (b.blockedAt || 0) - (a.blockedAt || 0));
      warmGeo(list.map((r) => r.ip));
      json(res, 200, {
        ok: true,
        ips: list,
        nftAvailable: live.ok,
        nftError: live.ok ? null : lastNftError,
        protectedIps: PROTECTED_IPS,
        sshPorts: [22],
      });
      return;
    }

    json(res, 404, { ok: false, error: 'not_found' });
  } catch (err) {
    log({ level: 'error', event: 'http_error', path: pathname, error: err.message });
    if (!res.headersSent) json(res, err.status || 500, { ok: false, error: err.message });
    else res.end();
  }
});

function loginPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · Server Panel 监控</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f5f7;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#111827}
.card{width:min(360px,92vw);background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:28px}
h1{margin:0 0 6px;font-size:19px}
p{margin:0 0 20px;font-size:13px;color:#6b7280}
label{display:block;font-size:13px;color:#374151;margin-bottom:6px}
input{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #d1d5db;border-radius:9px;font-size:15px}
button{margin-top:16px;width:100%;padding:11px;border:0;border-radius:9px;background:#111827;color:#fff;
  font-size:15px;font-weight:600;cursor:pointer}
.err{margin-top:12px;font-size:13px;color:#b91c1c;min-height:18px}
</style></head>
<body><form class="card" id="f">
<h1>Server Panel 资源监控</h1>
<p>请输入面板密码</p>
<label for="p">密码</label>
<input id="p" type="password" autocomplete="current-password" autofocus>
<button type="submit">登录</button>
<div class="err" id="e"></div>
</form>
<script>
document.getElementById('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const err = document.getElementById('e');
  err.textContent = '';
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: document.getElementById('p').value }),
    });
    const d = await r.json();
    if (d.ok) location.href = '/';
    else err.textContent = d.error === 'bad_password' ? '密码错误' : (d.message || '登录失败');
  } catch (e) { err.textContent = '网络错误'; }
});
</script></body></html>`;
}

/* ------------------------------------------------------------------- boot */

async function boot() {
  log({
    level: 'info',
    event: 'starting',
    host: HOSTNAME,
    dataDir: DATA_DIR,
    sampleIntervalMs: SAMPLE_INTERVAL_MS,
    alertsEnabled: rules.enabled,
    sshAlerts: rules.sshAlertsEnabled,
    sshFailAlerts: rules.sshFailAlertsEnabled,
    to: ALERT_TO,
    mailSocket: mailConfig.socket,
    authEnabled: auth.enabled,
  });

  if (!auth.enabled) {
    log({ level: 'error', event: 'auth_disabled', msg: 'MONITOR_PASSWORD / MONITOR_SECRET 未设置，面板不可登录' });
  }
  if (!mail) {
    log({ level: 'error', event: 'mail_not_configured', msg: 'MAIL_API_KEY_ID / MAIL_API_SECRET 未设置，告警无法发送' });
  }

  // Seed the journal cursor once so a first start does not email the backlog.
  // Only the recent past is learned: alerting on the whole retained journal
  // would be both slow and pointless, and it would seed the failure tracker
  // with attempts from days ago.
  if (!store.readCursor()) {
    try {
      const cursor = await currentCursor();
      if (cursor) {
        // Learn existing IPs and failures without alerting on them.
        const { accepted, failed } = await readRecent({ limit: 5000 });
        const { known } = classify(accepted, {});
        knownIps = known;
        for (const [ip, attempts] of groupByIp(failed)) {
          failures.record(ip, attempts, rules.sshFailWindowMinutes * 60 * 1000);
        }
        await store.writeKnownIps(knownIps);
        await store.writeFailures(failures.state);
        await store.writeCursor(cursor);
        log({
          level: 'info',
          event: 'ssh_bootstrapped',
          ips: Object.keys(knownIps).length,
          failIps: failures.size,
        });
      }
    } catch (err) {
      log({ level: 'warn', event: 'ssh_bootstrap_failed', error: err.message });
    }
  }

  // One immediate sample so the dashboard is not empty, then every interval.
  await tickResources().catch((err) => log({ level: 'error', event: 'tick_failed', error: err.message }));
  setInterval(() => {
    tickResources().catch((err) => log({ level: 'error', event: 'tick_failed', error: err.message }));
  }, SAMPLE_INTERVAL_MS).unref?.();

  setInterval(() => {
    tickSsh().catch((err) => log({ level: 'error', event: 'ssh_tick_failed', error: err.message }));
  }, SSH_POLL_MS).unref?.();

  // Blocked-attempt log is read on the same cadence as SSH.
  setInterval(() => {
    tickBlocked().catch((err) => log({ level: 'error', event: 'blocked_tick_failed', error: err.message }));
  }, SSH_POLL_MS).unref?.();

  // Automatic blocking, on the same cadence. Separate from tickSsh so a slow
  // `ss`/`ps` cannot delay the journal read.
  setInterval(() => {
    tickAutoBlock().catch((err) => log({ level: 'error', event: 'auto_block_tick_failed', error: err.message }));
  }, SSH_POLL_MS).unref?.();

  // Reconcile the panel's audit file with the live nft set once at startup: a
  // restored backup or a manual `nft` command must not make the two disagree.
  blocker.listBlocked().then((live) => {
    if (!live.ok) {
      lastNftError = live.error || 'nft list failed';
      log({ level: 'warn', event: 'nft_unavailable', error: lastNftError });
      return;
    }
    const inSet = new Set(live.entries.map((e) => e.ip));
    for (const ip of inSet) {
      if (!blocked[ip]) blocked[ip] = { blockedAt: null, count: 0, recovered: true };
    }
    for (const ip of Object.keys(blocked)) {
      if (!inSet.has(ip)) delete blocked[ip];
    }
    log({ level: 'info', event: 'blocklist_synced', blocked: Object.keys(blocked).length });
    scheduleSave();
  }).catch((err) => log({ level: 'warn', event: 'blocklist_sync_failed', error: err.message }));

  // Country filter: restore the table if the switch is on, then refresh the
  // underlying data daily. A failed restore is logged and surfaced in the
  // panel but never fatal — SSH stays reachable, which is the safe direction.
  if (rules.geoipEnabled) {
    applyGeoipFilter().catch((err) => {
      geoip.error = err.message;
      log({ level: 'warn', event: 'geoip_start_failed', error: err.message });
    });
  }
  setInterval(() => {
    refreshGeoip().catch((err) => {
      log({ level: 'error', event: 'geoip_refresh_failed', error: err.message });
    });
  }, GEOIP_REFRESH_MS).unref?.();

  // Traffic filter: rebuild the table from traffic-filter.json. If this fails the
  // panel shows the error and nothing else changes — the table is replaced in a
  // single nft transaction, so a failure cannot leave a partial ruleset behind.
  if (trafficFilter.enabled && trafficFilter.rules.some((r) => r.enabled !== false)) {
    applyTrafficFilter().catch((err) => {
      trafficState.error = err.message;
      log({ level: 'warn', event: 'trafficfilter_start_failed', error: err.message });
    });
  } else {
    // Reconcile: a table or nginx snippet left over from a previous run must not
    // outlive the switch being off in the saved state.
    applyTrafficFilter().catch((err) => {
      trafficState.error = err.message;
      log({ level: 'warn', event: 'trafficfilter_stale_remove_failed', error: err.message });
    });
  }

  server.listen(PORT, HOST, () => {
    log({ level: 'info', event: 'listening', address: `http://${HOST}:${PORT}` });
  });
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    log({ level: 'info', event: 'shutdown', signal: sig });
    try {
      await store.writeState(state);
      await store.writeKnownIps(knownIps);
      await store.writeGeoCache(geo.cache);
      await store.writeFailures(failures.state);
      await store.writeBlocked(blocked);
      await store.writeHistory(history);
    } catch {
      /* best effort */
    }
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref?.();
  });
}

boot().catch((err) => {
  log({ level: 'error', event: 'boot_failed', error: err.message, stack: err.stack });
  process.exit(1);
});

module.exports = { server };
