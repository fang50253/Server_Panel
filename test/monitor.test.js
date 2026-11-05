'use strict';

/**
 * Tests for the monitor: /proc parsers, alert policy, SSH classification,
 * GeoIP cache behaviour, and message construction.
 *
 *   node test/monitor.test.js
 *
 * No network, no /proc, no email. The parsers take fixture strings so this
 * runs on macOS exactly the same as on the server.
 */

const assert = require('assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

const {
  parseProcStat,
  cpuPercent,
  parseMeminfo,
  parseNetDev,
  netRates,
  formatBytes,
  formatMbps,
} = require('../lib/metrics');
const { normalizeRules, evaluate, emptyState, DEFAULTS } = require('../lib/policy');
const { parseAccepted, parseFailed, isPrivateIp, classify, stripBrackets } = require('../lib/ssh-watch');
const { FailureTracker, groupByIp, readEventsSince, readRecent, parseBlocked } = require('../lib/ssh-watch');
const { normalizeIp, isPublicIp, evaluateBlockRequest, evaluateAutoBlock, parseSsPeers,
        liveSessionPeers, parseZone, buildGeoipRuleset } = require('../lib/blocker');
const { GeoCache, describe } = require('../lib/geo');
const {
  buildResourceAlert,
  buildSshAlert,
  buildSshFailAlert,
  formatTime,
  formatDuration,
} = require('../lib/notify');
const { writeJsonAtomic, readJsonSync, Store } = require('../lib/store');
const tf = require('../lib/trafficfilter');
const failedPage = require('../lib/failed-page');
const cloudflare = require('../lib/cloudflare');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
    passed += 1;
  } catch (err) {
    console.log(`  FAIL ${name}`);
    console.log(`       ${err.message}`);
    failed += 1;
  }
}

/* ---------------------------------------------------------------- fixtures */

const STAT_A = `cpu  100 0 50 1000 50 0 0 0 0 0
cpu0 50 0 25 500 25 0 0 0 0 0
intr 12345
ctxt 99999
`;
// 50 busy ticks, 50 idle ticks added: exactly 50% busy over the interval
const STAT_B = `cpu  125 0 75 1050 50 0 0 0 0 0
cpu0 75 0 37 525 25 0 0 0 0 0
intr 12345
`;

const MEMINFO = `MemTotal:        1240012 kB
MemFree:          120000 kB
MemAvailable:     907580 kB
Buffers:           30000 kB
Cached:           400000 kB
SwapTotal:       1048572 kB
SwapFree:        1048572 kB
`;
// 80% used: total 1000MB, available 200MB
const MEMINFO_HIGH = `MemTotal:        1024000 kB
MemFree:           50000 kB
MemAvailable:     204800 kB
SwapTotal:             0 kB
SwapFree:              0 kB
`;

const NETDEV_A = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 5000000   1000    0    0    0     0          0         0  5000000   1000    0    0    0     0       0          0
  eth0: 1000000   1000    0    0    0     0          0         0   200000   1000    0    0    0     0       0          0
`;

// 10s later: eth0 rx +10,000,000 (8 Mbps), tx +2,500,000 (2 Mbps)
const NETDEV_B = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999   9999    0    0    0     0          0         0  9999999   9999    0    0    0     0       0          0
  eth0: 11000000   2000    0    0    0     0          0         0  2700000   2000    0    0    0     0       0          0
`;

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'monitor-'));

/* -------------------------------------------------------------------- run */

(async () => {
  console.log('cpu parsing');

  await test('parses the aggregate cpu line', () => {
    const s = parseProcStat(STAT_A);
    assert.strictEqual(s.total, 100 + 0 + 50 + 1000 + 50);
    assert.strictEqual(s.idle, 1050);
  });

  await test('ignores per-core lines and headers', () => {
    const s = parseProcStat('intr 1\ncpu0 1 2 3 4\n');
    assert.strictEqual(s, null);
  });

  await test('computes usage from two snapshots', () => {
    const pct = cpuPercent(parseProcStat(STAT_A), parseProcStat(STAT_B));
    assert.strictEqual(pct, 50);
  });

  await test('returns null for a non-advancing snapshot', () => {
    const s = parseProcStat(STAT_A);
    assert.strictEqual(cpuPercent(s, s), null);
  });

  await test('clamps impossible values', () => {
    const pct = cpuPercent({ total: 100, idle: 100 }, { total: 200, idle: 100 });
    assert.ok(pct >= 0 && pct <= 100);
  });

  console.log('memory parsing');

  await test('uses MemAvailable, not MemFree', () => {
    const m = parseMeminfo(MEMINFO);
    assert.strictEqual(m.totalBytes, 1240012 * 1024);
    assert.strictEqual(m.availableBytes, 907580 * 1024);
    assert.strictEqual(m.usedBytes, (1240012 - 907580) * 1024);
  });

  await test('reports a high utilisation percentage', () => {
    const m = parseMeminfo(MEMINFO_HIGH);
    assert.ok(Math.abs(m.usedPercent - 80) < 0.001, `got ${m.usedPercent}`);
  });

  await test('falls back to MemFree when MemAvailable is absent', () => {
    const m = parseMeminfo('MemTotal: 1000 kB\nMemFree: 250 kB\n');
    assert.strictEqual(m.availableBytes, 250 * 1024);
    assert.strictEqual(m.usedPercent, 75);
  });

  await test('handles empty input without throwing', () => {
    const m = parseMeminfo('');
    assert.strictEqual(m.totalBytes, 0);
    assert.strictEqual(m.usedPercent, 0);
  });

  console.log('network parsing');

  await test('sums rx/tx and skips loopback', () => {
    const n = parseNetDev(NETDEV_A);
    assert.strictEqual(n.rxBytes, 1000000);
    assert.strictEqual(n.txBytes, 200000);
    assert.strictEqual(n.totalBytes, 1200000);
  });

  await test('computes per-second and Mbps rates', () => {
    const r = netRates(parseNetDev(NETDEV_A), parseNetDev(NETDEV_B), 10000);
    assert.strictEqual(r.rxBytesPerSec, 1_000_000);
    assert.strictEqual(r.txBytesPerSec, 250_000);
    assert.strictEqual(r.rxMbps, 8);
    assert.strictEqual(r.txMbps, 2);
    assert.strictEqual(r.totalMbps, 10);
  });

  await test('returns null without an interval', () => {
    assert.strictEqual(netRates(null, parseNetDev(NETDEV_A), 1000), null);
    assert.strictEqual(netRates(parseNetDev(NETDEV_A), parseNetDev(NETDEV_B), 0), null);
  });

  await test('a counter reset does not produce negative rates', () => {
    const r = netRates(parseNetDev(NETDEV_B), parseNetDev(NETDEV_A), 10000);
    assert.ok(r.rxBytesPerSec >= 0);
  });

  console.log('formatting');

  await test('formats bytes with sensible units', () => {
    assert.strictEqual(formatBytes(512), '512 B');
    assert.strictEqual(formatBytes(1024 * 1024), '1.0 MB');
    assert.strictEqual(formatBytes(1536 * 1024), '1.5 MB');
  });

  await test('formats Mbps with precision by magnitude', () => {
    assert.strictEqual(formatMbps(2.345), '2.35 Mbps');
    assert.strictEqual(formatMbps(42.5), '42.5 Mbps');
    assert.strictEqual(formatMbps(180), '180 Mbps');
  });

  await test('formats durations', () => {
    assert.strictEqual(formatDuration(30), '30 分钟');
    assert.strictEqual(formatDuration(60), '1 小时');
    assert.strictEqual(formatDuration(90), '1 小时 30 分钟');
  });

  await test('formats timestamps explicitly in UTC', () => {
    assert.strictEqual(formatTime(Date.UTC(2026, 10, 5, 9, 41, 7)), '2026-11-05 09:41:07 (UTC)');
  });

  console.log('rules');

  await test('defaults match the requested behaviour', () => {
    assert.strictEqual(DEFAULTS.consecutive, 3);
    assert.strictEqual(DEFAULTS.windowCount, 10);
    assert.strictEqual(DEFAULTS.windowMinutes, 60);
  });

  await test('normalizes and clamps user input', () => {
    const r = normalizeRules({ cpuPercent: 500, memPercent: -5, consecutive: 0, combine: 'weird' });
    assert.strictEqual(r.cpuPercent, 100);
    assert.strictEqual(r.memPercent, 1);
    assert.strictEqual(r.consecutive, 1);
    assert.strictEqual(r.combine, 'any');
  });

  await test('treats missing input as defaults', () => {
    const r = normalizeRules({});
    assert.deepStrictEqual(r, DEFAULTS);
  });

  await test('rounds integer fields', () => {
    const r = normalizeRules({ consecutive: 3.7, windowCount: 9.4 });
    assert.strictEqual(r.consecutive, 4);
    assert.strictEqual(r.windowCount, 9);
  });

  console.log('alert policy');

  const rules = normalizeRules({ cpuPercent: 80, memPercent: 80, netMbps: 10 });
  const mk = (over) => ({ cpuPercent: over ? 95 : 20, memPercent: 30, net: { totalMbps: 1 } });

  await test('one sample over threshold does not alert', () => {
    const { actions } = evaluate(emptyState(), mk(true), rules, 1000);
    assert.strictEqual(actions.length, 0);
  });

  await test('three consecutive samples fire exactly once', () => {
    let state = emptyState();
    let fired = 0;
    for (let i = 0; i < 3; i += 1) {
      const r = evaluate(state, mk(true), rules, 1000 + i * 60_000);
      state = r.state;
      fired += r.actions.filter((a) => a.metric === 'cpu').length;
    }
    assert.strictEqual(fired, 1);
  });

  await test('a dropped sample resets the consecutive counter', () => {
    let state = emptyState();
    evaluate(state, mk(true), rules, 0);
    const mid = evaluate(state, mk(false), rules, 60_000);
    state = mid.state;
    assert.strictEqual(state.metrics.cpu.consecutive, 0);
    const after = evaluate(state, mk(true), rules, 120_000);
    assert.strictEqual(after.actions.length, 0);
  });

  await test('window rule catches flapping without 3 in a row', () => {
    // 10 one-off spikes within the hour, never 3 consecutive.
    const windowRules = normalizeRules({ ...rules, consecutive: 3, windowCount: 10, combine: 'any' });
    let state = emptyState();
    let fired = 0;
    for (let i = 0; i < 10; i += 1) {
      const t = i * 2 * 60_000; // over, then under, 2 min apart
      const over = evaluate(state, mk(true), windowRules, t);
      state = over.state;
      fired += over.actions.filter((a) => a.metric === 'cpu').length;
      state = evaluate(state, mk(false), windowRules, t + 60_000).state;
    }
    assert.strictEqual(fired, 1, 'the 10th spike should trip the window rule');
    assert.strictEqual(state.metrics.cpu.consecutive, 0, 'never 3 in a row');
  });

  await test('combine=all requires both conditions', () => {
    const strict = normalizeRules({ ...rules, combine: 'all', windowCount: 10, consecutive: 3 });
    let state = emptyState();
    let fired = 0;
    for (let i = 0; i < 3; i += 1) {
      const r = evaluate(state, mk(true), strict, i * 60_000);
      state = r.state;
      fired += r.actions.length;
    }
    assert.strictEqual(fired, 0, '3 consecutive alone must not fire under combine=all');
  });

  await test('cooldown suppresses repeats', () => {
    const cd = normalizeRules({ ...rules, cooldownMinutes: 30 });
    let state = emptyState();
    let fired = 0;
    for (let i = 0; i < 10; i += 1) {
      const r = evaluate(state, mk(true), cd, i * 60_000);
      state = r.state;
      fired += r.actions.filter((a) => a.metric === 'cpu').length;
    }
    assert.strictEqual(fired, 1);
  });

  await test('fires again after the cooldown expires', () => {
    const cd = normalizeRules({ ...rules, cooldownMinutes: 5 });
    let state = emptyState();
    let fired = 0;
    for (let i = 0; i < 12; i += 1) {
      const r = evaluate(state, mk(true), cd, i * 60_000);
      state = r.state;
      fired += r.actions.filter((a) => a.metric === 'cpu').length;
    }
    assert.ok(fired >= 2, `expected a second alert after cooldown, got ${fired}`);
  });

  await test('a null cpu reading (first sample) is ignored', () => {
    const first = { cpuPercent: null, memPercent: 30, net: null };
    const { actions, state: s } = evaluate(emptyState(), first, rules, 0);
    assert.strictEqual(actions.length, 0);
    assert.strictEqual(s.metrics.cpu.consecutive, 0);
  });

  await test('memory and network are evaluated independently', () => {
    const sample = { cpuPercent: 10, memPercent: 99, net: { totalMbps: 50 } };
    let state = emptyState();
    let metrics = new Set();
    for (let i = 0; i < 3; i += 1) {
      const r = evaluate(state, sample, rules, i * 60_000);
      state = r.state;
      r.actions.forEach((a) => metrics.add(a.metric));
    }
    assert.ok(metrics.has('mem'));
    assert.ok(metrics.has('net'));
  });

  await test('peak tracks the highest value in a run and resets', () => {
    let state = emptyState();
    state = evaluate(state, { cpuPercent: 81, memPercent: 1, net: null }, rules, 0).state;
    state = evaluate(state, { cpuPercent: 99, memPercent: 1, net: null }, rules, 60_000).state;
    assert.strictEqual(state.metrics.cpu.peak, 99);
    state = evaluate(state, { cpuPercent: 10, memPercent: 1, net: null }, rules, 120_000).state;
    assert.strictEqual(state.metrics.cpu.peak, null);
  });

  console.log('ssh parsing');

  await test('parses an Accepted password line', () => {
    const e = parseAccepted('Accepted password for root from 1.1.1.1 port 51174 ssh2');
    assert.deepStrictEqual(e, { method: 'password', user: 'root', ip: '1.1.1.1', port: 51174 });
  });

  await test('parses a publickey line', () => {
    const e = parseAccepted('Accepted publickey for deploy from 203.0.113.9 port 22 ssh2');
    assert.strictEqual(e.method, 'publickey');
    assert.strictEqual(e.user, 'deploy');
  });

  await test('ignores failures and disconnects', () => {
    assert.strictEqual(parseAccepted('Failed password for root from 1.2.3.4 port 22 ssh2'), null);
    assert.strictEqual(parseAccepted('Disconnected from 1.2.3.4 port 22'), null);
    assert.strictEqual(parseAccepted(''), null);
  });

  await test('identifies private and loopback addresses', () => {
    assert.strictEqual(isPrivateIp('10.0.0.1'), true);
    assert.strictEqual(isPrivateIp('192.168.1.5'), true);
    assert.strictEqual(isPrivateIp('172.16.0.1'), true);
    assert.strictEqual(isPrivateIp('172.32.0.1'), false);
    assert.strictEqual(isPrivateIp('127.0.0.1'), true);
    assert.strictEqual(isPrivateIp('::1'), true);
    assert.strictEqual(isPrivateIp('fe80::1'), true);
    assert.strictEqual(isPrivateIp('1.1.1.1'), false);
  });

  await test('strips IPv6 brackets from the journal format', () => {
    assert.strictEqual(stripBrackets('[2001:db8::1]'), '2001:db8::1');
    assert.strictEqual(stripBrackets('1.2.3.4'), '1.2.3.4');
  });

  await test('first sighting is fresh, second is not', () => {
    const first = classify([{ ip: '18.1.2.3', user: 'root', ts: 1000, method: 'password' }], {});
    assert.strictEqual(first.fresh.length, 1);
    const second = classify(
      [{ ip: '18.1.2.3', user: 'root', ts: 2000, method: 'password' }],
      first.known,
    );
    assert.strictEqual(second.fresh.length, 0);
    assert.strictEqual(second.known['18.1.2.3'].count, 2);
  });

  await test('private IPs are recorded but never alerted', () => {
    const r = classify([{ ip: '10.0.0.9', user: 'root', ts: 1, method: 'password' }], {});
    assert.strictEqual(r.fresh.length, 0);
    assert.strictEqual(r.known['10.0.0.9'].private, true);
  });

  await test('two new IPs in one batch both alert', () => {
    const r = classify(
      [
        { ip: '18.1.1.1', user: 'root', ts: 1, method: 'password' },
        { ip: '18.2.2.2', user: 'root', ts: 2, method: 'password' },
      ],
      {},
    );
    assert.strictEqual(r.fresh.length, 2);
  });

  await test('the same IP twice in one batch alerts only once', () => {
    const r = classify(
      [
        { ip: '18.1.1.1', user: 'root', ts: 1, method: 'password' },
        { ip: '18.1.1.1', user: 'root', ts: 2, method: 'password' },
      ],
      {},
    );
    assert.strictEqual(r.fresh.length, 1);
    assert.strictEqual(r.known['18.1.1.1'].count, 2);
  });

  console.log('ssh failures');

  await test('parses a Failed password line', () => {
    const e = parseFailed('Failed password for root from 1.0.0.1 port 51422 ssh2');
    assert.deepStrictEqual(
      { ip: e.ip, user: e.user, method: e.method, invalidUser: e.invalidUser },
      { ip: '1.0.0.1', user: 'root', method: 'password', invalidUser: false },
    );
  });

  await test('parses Failed password for invalid user', () => {
    const e = parseFailed('Failed password for invalid user admin from 1.0.0.1 port 51422 ssh2');
    assert.strictEqual(e.user, 'admin');
    assert.strictEqual(e.invalidUser, true);
  });

  await test('parses Invalid user lines', () => {
    const e = parseFailed('Invalid user test from 1.0.0.1');
    assert.strictEqual(e.ip, '1.0.0.1');
    assert.strictEqual(e.user, 'test');
    assert.strictEqual(e.invalidUser, true);
  });

  await test('parses Failed publickey', () => {
    const e = parseFailed('Failed publickey for deploy from 203.0.113.9 port 50000 ssh2');
    assert.strictEqual(e.method, 'publickey');
    assert.strictEqual(e.ip, '203.0.113.9');
  });

  await test('does not treat a success as a failure', () => {
    assert.strictEqual(parseFailed('Accepted password for root from 18.1.2.3 port 22 ssh2'), null);
  });

  await test('does not count preauth disconnects as password failures', () => {
    assert.strictEqual(parseFailed('Disconnected from 1.2.3.4 port 22'), null);
  });

  await test('groups failed events by IP', () => {
    const map = groupByIp([
      { ip: '1.1.1.1', ts: 1 },
      { ip: '2.2.2.2', ts: 2 },
      { ip: '1.1.1.1', ts: 3 },
    ]);
    assert.strictEqual(map.get('1.1.1.1').length, 2);
    assert.strictEqual(map.get('2.2.2.2').length, 1);
  });

  await test('tracker counts attempts inside the window', () => {
    const t = new FailureTracker({ now: () => 1000 });
    const windowMs = 60 * 60 * 1000;
    const r = t.record('1.1.1.1', [{ ts: 1000 }, { ts: 2000 }, { ts: 3000 }], windowMs, 3000);
    assert.strictEqual(r.count, 3);
    assert.strictEqual(r.first, 1000);
    assert.strictEqual(r.last, 3000);
  });

  await test('tracker drops attempts older than the window', () => {
    const windowMs = 60 * 60 * 1000;
    const t = new FailureTracker({ now: () => 0 });
    t.record('1.1.1.1', [{ ts: 0 }], windowMs, 0);
    t.record('1.1.1.1', [{ ts: 2 * 60 * 60 * 1000 }], windowMs, 2 * 60 * 60 * 1000);
    const rec = t.state['1.1.1.1'];
    assert.strictEqual(rec.count, 1, 'the hour-old attempt must have aged out');
  });

  await test('tracker distinguishes IPs', () => {
    const windowMs = 60_000;
    const t = new FailureTracker({});
    t.record('1.1.1.1', [{ ts: 1 }, { ts: 2 }, { ts: 3 }], windowMs, 3);
    t.record('2.2.2.2', [{ ts: 1 }], windowMs, 3);
    assert.strictEqual(t.state['1.1.1.1'].count, 3);
    assert.strictEqual(t.state['2.2.2.2'].count, 1);
  });

  await test('three failures reach the default threshold', () => {
    const rules3 = normalizeRules({});
    const t = new FailureTracker({});
    const windowMs = rules3.sshFailWindowMinutes * 60 * 1000;
    const r = t.record('9.9.9.9', [{ ts: 1 }, { ts: 2 }, { ts: 3 }], windowMs, 3);
    assert.ok(r.count >= rules3.sshFailCount, 'default threshold must be 3');
  });

  await test('cooldown blocks a second alert then releases', () => {
    let now = 1_000_000;
    const t = new FailureTracker({ now: () => now });
    const cooldownMs = 60 * 60 * 1000;
    t.record('1.1.1.1', [{ ts: now }], 60 * 60 * 1000, now);
    assert.strictEqual(t.canAlert('1.1.1.1', cooldownMs), true);
    t.markAlerted('1.1.1.1', now);
    assert.strictEqual(t.canAlert('1.1.1.1', cooldownMs), false);
    now += cooldownMs + 1;
    assert.strictEqual(t.canAlert('1.1.1.1', cooldownMs), true);
  });

  await test('an unseen IP cannot alert', () => {
    const t = new FailureTracker({});
    assert.strictEqual(t.canAlert('5.5.5.5', 1000), false);
  });

  await test('tracks the usernames that were tried', () => {
    const t = new FailureTracker({});
    t.record('1.1.1.1', [{ ts: 1, user: 'root' }, { ts: 2, user: 'admin' }], 60_000, 2);
    assert.deepStrictEqual(t.state['1.1.1.1'].users, ['root', 'admin']);
  });

  await test('repeated usernames do not crowd out the others', () => {
    const t = new FailureTracker({});
    const attempts = [
      { ts: 1, user: 'root' }, { ts: 2, user: 'admin' }, { ts: 3, user: 'root' },
      { ts: 4, user: 'pi' }, { ts: 5, user: 'root' },
    ];
    t.record('1.1.1.1', attempts, 60_000, 5);
    assert.deepStrictEqual(t.state['1.1.1.1'].users, ['root', 'admin', 'pi']);
  });

  await test('prune removes IPs whose attempts all aged out', () => {
    const t = new FailureTracker({});
    t.record('1.1.1.1', [{ ts: 0 }], 1000, 0);
    t.prune(1000, 100000);
    assert.strictEqual(t.size, 0);
  });

  console.log('journal reading');

  await test('readEventsSince reads forward from the cursor, never tail-limited', async () => {
    const bin = tmp();
    const log = path.join(bin, 'argv.json');
    fs.writeFileSync(
      path.join(bin, 'journalctl'),
      `#!/usr/bin/env node
const fs=require('fs');
fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify(process.argv.slice(2)));
const rows=[];
for (let i=1;i<=5;i+=1) {
  rows.push({__CURSOR:'c'+i,__REALTIME_TIMESTAMP:String(1000000+i),
             MESSAGE:i%2?'Failed password for root from 1.1.1.'+i+' port 22 ssh2'
                        :'Accepted password for root from 2.2.2.'+i+' port 22 ssh2'});
}
process.stdout.write(rows.map(r=>JSON.stringify(r)).join('\\n')+'\\n');
`,
      { mode: 0o755 },
    );
    const old = process.env.PATH;
    process.env.PATH = `${bin}:${old}`;
    try {
      const res = await readEventsSince('c0');
      assert.strictEqual(res.ok, true);
      assert.strictEqual(res.accepted.length, 2);
      assert.strictEqual(res.failed.length, 3);
      assert.strictEqual(res.cursor, 'c5', 'cursor must land on the last entry read');

      const argv = JSON.parse(fs.readFileSync(log, 'utf8'));
      assert.ok(argv.includes('--no-tail'), 'must not let journalctl return the newest N');
      assert.ok(argv.includes('--after-cursor=c0'));
    } finally {
      process.env.PATH = old;
    }
  });

  await test('readEventsSince stops at maxEvents without losing the pointer', async () => {
    const bin = tmp();
    fs.writeFileSync(
      path.join(bin, 'journalctl'),
      `#!/usr/bin/env node
const rows=[];
for (let i=1;i<=50;i+=1) {
  rows.push({__CURSOR:'c'+i,__REALTIME_TIMESTAMP:String(1000000+i),
             MESSAGE:'Failed password for root from 1.1.1.1 port '+i+' ssh2'});
}
process.stdout.write(rows.map(r=>JSON.stringify(r)).join('\\n')+'\\n');
`,
      { mode: 0o755 },
    );
    const old = process.env.PATH;
    process.env.PATH = `${bin}:${old}`;
    try {
      const res = await readEventsSince('c0', { maxEvents: 10 });
      assert.strictEqual(res.truncated, true);
      assert.strictEqual(res.failed.length, 10);
      // The cursor must point at the 10th entry, not the 50th, or the other 40
      // failures would be skipped on the next poll.
      assert.strictEqual(res.cursor, 'c10');
    } finally {
      process.env.PATH = old;
    }
  });

  await test('readRecent asks for the newest entries, not the oldest', async () => {
    const bin = tmp();
    const log = path.join(bin, 'argv.json');
    fs.writeFileSync(
      path.join(bin, 'journalctl'),
      `#!/usr/bin/env node
const fs=require('fs');
fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify(process.argv.slice(2)));
process.stdout.write(JSON.stringify({__CURSOR:'c1',__REALTIME_TIMESTAMP:'1000001',MESSAGE:'Accepted password for root from 9.9.9.9 port 22 ssh2'})+'\\n');
`,
      { mode: 0o755 },
    );
    const old = process.env.PATH;
    process.env.PATH = `${bin}:${old}`;
    try {
      const res = await readRecent({ limit: 5000 });
      assert.strictEqual(res.accepted.length, 1);
      const argv = JSON.parse(fs.readFileSync(log, 'utf8'));
      assert.ok(argv.includes('-n'), 'bootstrap must bound the read');
      assert.ok(!argv.includes('--after-cursor'), 'bootstrap reads without a cursor');
    } finally {
      process.env.PATH = old;
    }
  });

  await test('SSH brute-force alert states count, window and location', () => {
    const built = buildSshFailAlert({
      ip: '1.0.0.1',
      count: 7,
      windowMinutes: 60,
      users: ['root', 'admin'],
      first: Date.UTC(2026, 10, 5, 1, 0, 0),
      last: Date.UTC(2026, 10, 5, 1, 8, 0),
      geo: { ok: true, country: 'Netherlands', city: 'Amsterdam', org: 'AS9009 M247' },
      host: 'example.com',
      url: 'https://panel.example.com/',
      cooldownMinutes: 60,
    });
    assert.strictEqual(built.template, 'security-alert');
    assert.ok(built.vars.title.includes('1.0.0.1'));
    assert.ok(built.vars.detail.includes('7 次'));
    assert.ok(built.vars.detail.includes('1 小时'));
    assert.ok(built.vars.detail.includes('Netherlands · Amsterdam'));
    assert.ok(built.vars.detail.includes('root, admin'));
    assert.ok(built.vars.detail.includes('2026-11-05 01:00:00'));
    assert.ok(built.vars.detail.includes('2026-11-05 01:08:00'));
    assert.ok(built.vars.action.includes('ufw'));
    assert.ok(built.vars.action.includes('1 小时'));
  });

  await test('brute-force alert survives an unknown location', () => {
    const built = buildSshFailAlert({
      ip: '1.2.3.4', count: 3, windowMinutes: 60, users: [],
      first: 0, last: 0, geo: null, host: 'h', url: 'u', cooldownMinutes: 60,
    });
    assert.ok(built.vars.detail.includes('未知'));
    assert.ok(built.vars.detail.includes('未知'), 'usernames fall back too');
  });

  console.log('blocking guards');

  await test('normalizes wrapped and mapped addresses', () => {
    assert.strictEqual(normalizeIp('[1.0.0.1]'), '1.0.0.1');
    assert.strictEqual(normalizeIp('::ffff:1.0.0.1'), '1.0.0.1');
    assert.strictEqual(normalizeIp(' 8.8.8.8 '), '8.8.8.8');
  });

  await test('only globally routable addresses are blockable targets', () => {
    for (const ip of ['1.0.0.1', '8.8.8.8', '2001:4860::1']) {
      assert.strictEqual(isPublicIp(ip), true, ip);
    }
    for (const ip of ['10.0.0.5', '127.0.0.1', '192.168.1.1', '172.16.0.1', '169.254.1.1',
                      '100.64.0.1', '203.0.113.9', '198.51.100.2', '::1', 'fe80::1',
                      'fd00::1', '224.0.0.1', '0.0.0.0']) {
      assert.strictEqual(isPublicIp(ip), false, ip);
    }
  });

  const guardBase = () => ({
    failures: { '1.0.0.1': { count: 9, users: ['root'] } },
    knownIps: { '208.67.222.222': { user: 'root', count: 1 } },
    selfIps: ['8.8.4.4'],
    protectedIps: ['1.1.1.1'],
    activeIps: ['9.9.9.9'],
  });

  await test('an IP with failures and no successful login can be blocked', () => {
    const r = evaluateBlockRequest({ ...guardBase(), ip: '1.0.0.1' });
    assert.strictEqual(r.ok, true);
  });

  await test('an IP that has logged in successfully is refused', () => {
    const r = evaluateBlockRequest({ ...guardBase(), ip: '208.67.222.222' });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.code, 'has_logged_in');
  });

  await test('an IP with no failures at all is refused', () => {
    const r = evaluateBlockRequest({ ...guardBase(), ip: '8.8.8.8' });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.code, 'no_failures');
  });

  await test('the server s own address is refused', () => {
    const r = evaluateBlockRequest({ ...guardBase(), ip: '8.8.4.4' });
    assert.strictEqual(r.code, 'self');
  });

  await test('the protected allowlist is refused', () => {
    const r = evaluateBlockRequest({ ...guardBase(), ip: '1.1.1.1' });
    assert.strictEqual(r.code, 'protected');
  });

  await test('an IP with a live SSH session is refused', () => {
    const r = evaluateBlockRequest({ ...guardBase(), ip: '9.9.9.9' });
    assert.strictEqual(r.code, 'active_session');
  });

  await test('private, loopback and test ranges are refused', () => {
    for (const ip of ['10.0.0.5', '127.0.0.1', '203.0.113.9']) {
      assert.strictEqual(evaluateBlockRequest({ ...guardBase(), ip }).code, 'not_public', ip);
    }
  });

  await test('garbage and empty input are refused', () => {
    assert.strictEqual(evaluateBlockRequest({ ...guardBase(), ip: '' }).code, 'no_ip');
    assert.strictEqual(evaluateBlockRequest({ ...guardBase(), ip: '999.1.1.1' }).code, 'invalid_ip');
    assert.strictEqual(evaluateBlockRequest({ ...guardBase(), ip: 'not-an-ip' }).code, 'invalid_ip');
  });

  await test('an already blocked IP is refused', () => {
    const r = evaluateBlockRequest({ ...guardBase(), ip: '1.0.0.1', blockedIps: ['1.0.0.1'] });
    assert.strictEqual(r.code, 'already_blocked');
  });

  await test('every refusal carries an actionable reason', () => {
    const base = guardBase();
    for (const ip of ['208.67.222.222', '8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9', '10.0.0.5', '']) {
      const r = evaluateBlockRequest({ ...base, ip });
      assert.strictEqual(r.ok, false, ip);
      assert.ok(r.reason && r.reason.length > 5, 'missing reason for ' + ip);
    }
  });

  await test('parses established SSH peers from ss output', () => {
    assert.deepStrictEqual(
      parseSsPeers('Recv-Q Send-Q Local Address:Port Peer Address:Port\n0 540 8.8.4.4:22 1.1.1.1:34498'),
      ['1.1.1.1'],
    );
    assert.deepStrictEqual(
      parseSsPeers('0 0 10.0.0.1:22 5.6.7.8:1234 users:(("sshd",pid=1,fd=3))'),
      ['5.6.7.8'],
    );
    assert.deepStrictEqual(
      parseSsPeers('0 0 [::]:22 [2001:db8::9]:4432'),
      ['2001:db8::9'],
    );
    assert.deepStrictEqual(parseSsPeers(''), []);
  });

  // Regression: a brute-forcing IP always has a preauth TCP connection open, so
  // treating `ss` established connections as sessions made the worst offenders
  // the least blockable. `ss -p` cannot be used to tell them apart because it
  // needs CAP_SYS_PTRACE, which monsvc does not have — verified on the box.
  const PS_ADMIN = '   484 sshd: /usr/sbin/sshd -D [listener] 1 of 10-100 startups\n' +
                   ' 32613 sshd: root@notty';
  const PS_ATTACK = '   484 sshd: /usr/sbin/sshd -D [listener] 2 of 10-100 startups\n' +
                    ' 32638 sshd: [accepted]\n 32639 sshd: [net]';
  const PS_BOTH = PS_ADMIN + '\n 32638 sshd: [accepted]\n 32639 sshd: [net]';
  const J_ADMIN = 'Accepted password for root from 1.1.1.1 port 58870 ssh2';
  const J_EMPTY = 'Failed password for invalid user vss from 1.0.0.2 port 44364 ssh2';

  await test('an established connection alone is not an active session', () => {
    // 1.0.0.2 must be blockable *while it is attacking*.
    const live = liveSessionPeers({
      connected: ['1.0.0.2'],
      psOutput: PS_ATTACK,
      journalOutput: J_EMPTY,
    });
    assert.deepStrictEqual(live, []);
  });

  await test('a logged-in administrator session is still detected', () => {
    const live = liveSessionPeers({
      connected: ['1.1.1.1'],
      psOutput: PS_ADMIN,
      journalOutput: J_ADMIN,
    });
    assert.deepStrictEqual(live, ['1.1.1.1'], 'must not let you block yourself');

    const v = evaluateBlockRequest({
      ip: '1.1.1.1',
      failures: { '1.1.1.1': { count: 5 } },
      knownIps: {},
      activeIps: live,
    });
    assert.strictEqual(v.code, 'active_session');
  });

  await test('an attacker is blockable even while an admin is logged in', () => {
    const live = liveSessionPeers({
      connected: ['1.1.1.1', '1.0.0.2'],
      psOutput: PS_BOTH,
      journalOutput: J_ADMIN + '\n' + J_EMPTY,
    });
    assert.deepStrictEqual(live, ['1.1.1.1']);
    const v = evaluateBlockRequest({
      ip: '1.0.0.2',
      failures: { '1.0.0.2': { count: 427 } },
      knownIps: {},
      activeIps: live,
    });
    assert.strictEqual(v.ok, true);
  });

  await test('a failed ps read fails closed, not open', () => {
    // Unreadable process list: we cannot prove nobody is logged in. `ps` output
    // is empty, so "no authenticated child" must NOT be read as "nobody logged
    // in" — the psOk=false flag is what distinguishes the two.
    const live = liveSessionPeers({
      connected: ['1.1.1.1'],
      psOutput: '',
      psOk: false,
      journalOutput: J_ADMIN,
    });
    assert.deepStrictEqual(live, ['1.1.1.1']);

    // `ps` succeeded but shows no session child at all -> nobody is logged in.
    const idle = liveSessionPeers({
      connected: ['1.1.1.1'],
      psOutput: '   484 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups',
      psOk: true,
      journalOutput: '',
      journalOk: false,
    });
    assert.deepStrictEqual(idle, []);
  });

  await test('a failed journal read fails closed when someone is logged in', () => {
    const live = liveSessionPeers({
      connected: ['1.1.1.1', '1.0.0.2'],
      psOutput: PS_BOTH,
      journalOutput: '',
      journalOk: false,
    });
    assert.deepStrictEqual(live, ['1.1.1.1', '1.0.0.2']);
  });

  await test('no authenticated child means nothing is a live session', () => {
    const live = liveSessionPeers({
      connected: ['1.0.0.2'],
      psOutput: PS_ATTACK,
      journalOk: false,
    });
    assert.deepStrictEqual(live, []);
  });

  await test('parses the kernel drop log line our rule emits', () => {
    const line = 'MONITOR_BLOCK IN=eth0 OUT= MAC=00:11 SRC=1.0.0.1 DST=8.8.4.4 ' +
                 'LEN=60 TOS=0x00 PROTO=TCP SPT=51000 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0';
    assert.deepStrictEqual(parseBlocked(line), { ip: '1.0.0.1', port: 22 });
  });

  await test('ignores kernel drops that are not ours', () => {
    const other = 'IN=eth0 OUT= MAC=00:11 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=22';
    assert.strictEqual(parseBlocked(other), null);
    assert.strictEqual(parseBlocked(''), null);
    assert.strictEqual(parseBlocked(null), null);
  });

  console.log('auto block');

  const autoBase = (now) => ({
    ip: '1.0.0.2',
    count: 100,
    windowMs: 24 * 60 * 60 * 1000,
    now,
    // The permanent history entry: timestamps come straight from history, not
    // from the (much shorter) alerting window.
    times: Array.from({ length: 120 }, (_, i) => now - (i + 1) * 10 * 60 * 1000),
    failures: {
      '1.0.0.2': { count: 3, users: ['root'], times: [] },
    },
    knownIps: {},
    selfIps: [],
    protectedIps: [],
    activeIps: [],
    blockedIps: [],
  });

  await test('fires once the window holds enough failures', () => {
    const now = Date.now();
    const v = evaluateAutoBlock(autoBase(now));
    assert.strictEqual(v.ok, true);
    assert.strictEqual(v.count, 120);
  });

  await test('does not fire below the configured count', () => {
    const now = Date.now();
    const v = evaluateAutoBlock({ ...autoBase(now), count: 500 });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.code, 'below_threshold');
  });

  await test('counts only failures inside the window', () => {
    const now = Date.now();
    // 120 failures at 10-minute spacing = 20 inside a 3-hour window
    const v = evaluateAutoBlock({ ...autoBase(now), count: 50, windowMs: 3 * 60 * 60 * 1000 });
    assert.strictEqual(v.ok, false, 'old failures must not count');
    assert.strictEqual(v.code, 'below_threshold');
  });

  await test('the threshold is configurable per deployment', () => {
    const now = Date.now();
    assert.strictEqual(evaluateAutoBlock({ ...autoBase(now), count: 120 }).ok, true);
    assert.strictEqual(evaluateAutoBlock({ ...autoBase(now), count: 121 }).ok, false);
  });

  await test('an IP with no record at all never fires', () => {
    const v = evaluateAutoBlock({ ...autoBase(Date.now()), times: [], failures: {} });
    assert.strictEqual(v.code, 'no_record');
  });

  await test('auto blocking still refuses every self-lockout case', () => {
    const now = Date.now();
    const base = autoBase(now);
    const cases = [
      [{ knownIps: { '1.0.0.2': { user: 'root' } } }, 'has_logged_in'],
      [{ protectedIps: ['208.67.222.222'], ip: '208.67.222.222' }, 'protected'],
      [{ activeIps: ['1.0.0.2'] }, 'active_session'],
      [{ ip: '8.8.4.4', selfIps: ['8.8.4.4'] }, 'self'],
      [{ ip: '10.0.0.5' }, 'not_public'],
      [{ blockedIps: ['1.0.0.2'] }, 'already_blocked'],
    ];
    for (const [patch, code] of cases) {
      const v = evaluateAutoBlock({ ...base, ...patch });
      assert.strictEqual(v.ok, false, `${code} must not auto-block`);
      assert.strictEqual(v.code, code);
    }
  });

  await test('automation may not override the "has logged in" rule', () => {
    // The one refusal the auto path is *not* allowed to relax, because it is
    // how an administrator gets locked out of their own box.
    const v = evaluateAutoBlock({
      ...autoBase(Date.now()),
      knownIps: { '1.0.0.2': { user: 'root', count: 1 } },
    });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.code, 'has_logged_in');
  });

  await test('auto-block defaults are off and match the requested 100/day', () => {
    const r = normalizeRules({});
    assert.strictEqual(r.autoBlockEnabled, false, 'must be opt-in');
    assert.strictEqual(r.autoBlockCount, 100);
    assert.strictEqual(r.autoBlockWindowMinutes, 1440);
  });

  await test('auto-block settings survive normalization and clamping', () => {
    const r = normalizeRules({ autoBlockEnabled: true, autoBlockCount: 0,
                               autoBlockWindowMinutes: 999999999 });
    assert.strictEqual(r.autoBlockEnabled, true);
    assert.strictEqual(r.autoBlockCount, 2, 'clamped to a sane minimum');
    assert.strictEqual(r.autoBlockWindowMinutes, 10080, 'clamped to a week');
  });

  console.log('country allow-list');

  await test('parseZone keeps valid CIDRs and rejects garbage', () => {
    const v4 = parseZone(
      '# comment\n' +
      '1.0.1.0/24\n' +
      '1.0.2.0/23\n' +
      '1.0.1.0/24\n' +           // duplicate
      '<html>404</html>\n' +
      'not an ip\n' +
      '\n',
      4,
    );
    assert.deepStrictEqual(v4, ['1.0.1.0/24', '1.0.2.0/23']);

    const v6 = parseZone(
      '2001:200::/35\n' +
      '2400:2000::/32\n' +
      '2001:200::/35\n' +
      'garbage here\n' +
      '<html>error page\n',
      6,
    );
    assert.deepStrictEqual(v6, ['2001:200::/35', '2400:2000::/32']);
  });

  await test('an HTML error page never parses as zone data', () => {
    const page = '<html>\n<head><title>404 Not Found</title></head>\n</html>\n';
    assert.deepStrictEqual(parseZone(page, 4), []);
    assert.deepStrictEqual(parseZone(page, 6), []);
  });

  await test('buildGeoipRuleset refuses to render an allow-list that blocks everyone', () => {
    assert.throws(() => buildGeoipRuleset({ v4: [], v6: ['2001::/32'] }), /v4 is empty/);
    assert.throws(() => buildGeoipRuleset({ v4: ['1.2.3.0/24'], v6: [] }), /v6 is empty/);
    assert.throws(() => buildGeoipRuleset({}), /v4 is empty/);
  });

  await test('buildGeoipRuleset keeps the operator inside the allow-list', () => {
    const rs = buildGeoipRuleset({
      v4: ['1.0.1.0/24', '208.67.222.222'],
      v6: ['2001:200::/35', '2001:db8:beef::/48'],
    });
    // Explicit always-allow entries survive into the set.
    assert.ok(rs.includes('208.67.222.222'), 'protected IP must be in allow4');
    assert.ok(rs.includes('2001:db8:beef::/48'), 'self v6 must be in allow6');
    // Accept rules precede the reject; the reject answers with tcp reset.
    assert.ok(rs.includes('reject with tcp reset'));
    assert.ok(rs.indexOf('@allow4 counter accept') < rs.indexOf('reject with tcp reset'));
    assert.ok(rs.indexOf('@allow6 counter accept') < rs.indexOf('reject with tcp reset'));
    // Only SSH is touched, and the chain runs after monitor_block's -10 hook
    // so blocked IPs still get dropped, logged and counted first.
    assert.ok(rs.includes('tcp dport { 22 }'));
    assert.ok(rs.includes('priority 0'));
    // Atomic replace, not incremental: delete and rebuild in one transaction.
    assert.ok(rs.includes('add table inet ssh_geoip'));
    assert.ok(rs.includes('delete table inet ssh_geoip'));
  });

  await test('geoip rules default off with the requested countries', () => {
    const r = normalizeRules({});
    assert.strictEqual(r.geoipEnabled, false, 'must be opt-in');
    assert.deepStrictEqual(r.geoipCountries, ['cn', 'hk', 'tw', 'gb', 'jp', 'sg']);
  });

  await test('geoip country codes are sanitized', () => {
    const r = normalizeRules({ geoipCountries: ['CN', 'usa', 'jp', '', 'c'] });
    assert.deepStrictEqual(r.geoipCountries, ['cn', 'jp']);
    const none = normalizeRules({ geoipCountries: 'not-an-array' });
    assert.deepStrictEqual(none.geoipCountries, ['cn', 'hk', 'tw', 'gb', 'jp', 'sg']);
  });

  console.log('geo cache');  await test('caches a successful lookup', async () => {
    const cache = new GeoCache({ now: () => 1000 });
    cache.set('1.2.3.4', { ok: true, country: 'Japan' });
    let calls = 0;
    const r = await cache.resolve('1.2.3.4');
    calls += 1;
    assert.strictEqual(r.country, 'Japan');
    assert.strictEqual(calls, 1);
  });

  await test('caches failures briefly', () => {
    const cache = new GeoCache({ now: () => 1000 });
    cache.set('1.2.3.4', { ok: false, error: 'boom' });
    assert.strictEqual(cache.get('1.2.3.4').ok, false);
  });

  await test('retries a failure after the ttl', () => {
    let now = 1000;
    const cache = new GeoCache({ now: () => now });
    cache.set('1.2.3.4', { ok: false, error: 'boom' });
    now += 11 * 60 * 1000;
    assert.strictEqual(cache.get('1.2.3.4'), null);
  });

  await test('skips the network when disabled', async () => {
    const cache = new GeoCache({});
    const r = await cache.resolve('1.2.3.4', { allowNetwork: false });
    assert.strictEqual(r.ok, false);
  });

  await test('describes a location readably', () => {
    assert.strictEqual(
      describe({ ok: true, country: 'United Kingdom', city: 'London', org: 'AS16509 Amazon' }),
      'United Kingdom · London（AS16509 Amazon）',
    );
    assert.strictEqual(describe({ ok: false }), '国家/地区未知');
    assert.strictEqual(describe({ ok: true, country: 'Japan' }), 'Japan');
  });

  console.log('messages');

  const alertRules = normalizeRules({});

  await test('CPU alert mentions value, threshold and trigger', () => {
    const built = buildResourceAlert({
      action: { metric: 'cpu', value: 93.2, threshold: 85, consecutive: 3, windowCount: 4, peak: 97.1, reason: 'consecutive' },
      sample: { cpuPercent: 93.2, cpuCores: 2, mem: null, net: null },
      rules: alertRules,
      host: 'example.com',
      url: 'https://panel.example.com/',
      now: Date.UTC(2026, 10, 5, 9, 41, 7),
    });
    assert.strictEqual(built.template, 'security-alert');
    assert.ok(built.vars.title.includes('CPU'));
    assert.ok(built.vars.detail.includes('93.2%'));
    assert.ok(built.vars.detail.includes('85%'));
    assert.ok(built.vars.detail.includes('连续 3 次'));
    assert.ok(built.vars.detail.includes('97.1%'));
    assert.ok(built.vars.detail.includes('2026-11-05 09:41:07'));
    assert.ok(built.vars.url.startsWith('https://'));
  });

  await test('memory alert includes byte detail', () => {
    const built = buildResourceAlert({
      action: { metric: 'mem', value: 91, threshold: 85, consecutive: 3, windowCount: 3, peak: 91, reason: 'consecutive' },
      sample: {
        cpuPercent: 5,
        cpuCores: 2,
        mem: { usedBytes: 1100 * 1024 * 1024, totalBytes: 1240 * 1024 * 1024, availableBytes: 140 * 1024 * 1024 },
        net: null,
      },
      rules: alertRules,
      host: 'example.com',
      url: 'u',
      now: 0,
    });
    assert.ok(built.vars.detail.includes('内存明细'));
    assert.ok(built.vars.detail.includes('1.1 GB'));
  });

  await test('network alert includes direction split', () => {
    const built = buildResourceAlert({
      action: { metric: 'net', value: 40, threshold: 25, consecutive: 3, windowCount: 3, peak: 40, reason: 'consecutive' },
      sample: {
        cpuPercent: 5,
        cpuCores: 2,
        mem: null,
        net: { rxMbps: 35, txMbps: 5, totalMbps: 40 },
      },
      rules: alertRules,
      host: 'example.com',
      url: 'u',
      now: 0,
    });
    assert.ok(built.vars.detail.includes('入站 35.0 Mbps'));
    assert.ok(built.vars.detail.includes('出站 5.00 Mbps'));
  });

  await test('window-triggered alert explains the window rule', () => {
    const built = buildResourceAlert({
      action: { metric: 'cpu', value: 90, threshold: 85, consecutive: 1, windowCount: 10, peak: 90, reason: 'window' },
      sample: { cpuPercent: 90, cpuCores: 2, mem: null, net: null },
      rules: alertRules,
      host: 'h',
      url: 'u',
      now: 0,
    });
    assert.ok(built.vars.detail.includes('1 小时内累计 10 次'));
  });

  await test('SSH alert states country, region and login time', () => {
    const built = buildSshAlert({
      ip: '1.1.1.1',
      user: 'root',
      method: 'password',
      ts: Date.UTC(2026, 10, 5, 2, 14, 52),
      geo: { ok: true, country: 'United Kingdom', city: 'London', org: 'AS16509 Amazon', timezone: 'Europe/London' },
      host: 'example.com',
      url: 'https://panel.example.com/',
    });
    assert.strictEqual(built.template, 'security-alert');
    assert.ok(built.vars.title.includes('1.1.1.1'));
    assert.ok(built.vars.detail.includes('United Kingdom · London'));
    assert.ok(built.vars.detail.includes('AS16509 Amazon'));
    assert.ok(built.vars.detail.includes('2026-11-05 02:14:52 (UTC)'));
    assert.ok(built.vars.detail.includes('root'));
    assert.ok(built.vars.action.includes('立即'));
  });

  await test('SSH alert degrades gracefully when GeoIP fails', () => {
    const built = buildSshAlert({
      ip: '1.2.3.4',
      user: 'root',
      method: 'publickey',
      ts: 0,
      geo: { ok: false, error: 'timeout' },
      host: 'h',
      url: 'u',
    });
    assert.ok(built.vars.detail.includes('未知'));
    assert.ok(!built.vars.detail.includes('undefined'));
  });

  await test('alert messages contain no undefined or null text', () => {
    const samples = [
      buildResourceAlert({
        action: { metric: 'mem', value: 90, threshold: 85, consecutive: 3, windowCount: 3, peak: null, reason: 'consecutive' },
        sample: null,
        rules: alertRules,
        host: 'h',
        url: 'u',
        now: 0,
      }),
      buildSshAlert({ ip: '1.1.1.1', user: 'u', method: 'password', ts: 0, geo: null, host: 'h', url: 'u' }),
    ];
    for (const s of samples) {
      for (const value of Object.values(s.vars)) {
        assert.ok(!/undefined|null|NaN/.test(value), `suspicious text: ${value}`);
      }
    }
  });

  await test('all template variables are strings', () => {
    const built = buildSshAlert({
      ip: '1.1.1.1', user: 'u', method: 'password', ts: 0,
      geo: { ok: true, country: 'X', city: 'Y', org: 'Z', timezone: 'T' },
      host: 'h', url: 'u',
    });
    for (const [k, v] of Object.entries(built.vars)) {
      assert.strictEqual(typeof v, 'string', `${k} must be a string`);
    }
  });

  console.log('storage');

  await test('writes json atomically and reads it back', async () => {
    const dir = tmp();
    const file = path.join(dir, 'x.json');
    await writeJsonAtomic(file, { a: 1 });
    assert.deepStrictEqual(readJsonSync(file, null), { a: 1 });
  });

  await test('a corrupt file falls back instead of throwing', () => {
    const dir = tmp();
    const file = path.join(dir, 'bad.json');
    fs.writeFileSync(file, '{not json');
    assert.deepStrictEqual(readJsonSync(file, { safe: true }), { safe: true });
  });

  await test('store persists config, state, ips and history', async () => {
    const dir = tmp();
    const store = new Store({ dir });
    await store.writeConfig({ rules: { enabled: false } });
    assert.strictEqual(store.readConfig({}).rules.enabled, false);

    await store.writeState({ metrics: {} });
    assert.deepStrictEqual(store.readState({}), { metrics: {} });

    await store.writeKnownIps({ '1.2.3.4': { count: 1 } });
    assert.strictEqual(store.readKnownIps({})['1.2.3.4'].count, 1);

    await store.appendHistory({ ts: 'a', ok: true });
    await store.appendHistory({ ts: 'b', ok: false });
    const hist = store.readAlerts(10);
    assert.strictEqual(hist.length, 2);
    assert.strictEqual(hist[0].ts, 'b', 'newest first');
  });

  await test('history is capped at the requested limit', async () => {
    const dir = tmp();
    const store = new Store({ dir });
    for (let i = 0; i < 20; i += 1) await store.appendHistory({ i });
    assert.strictEqual(store.readAlerts(5).length, 5);
    assert.strictEqual(store.readAlerts(5)[0].i, 19);
  });

  await test('failure history and alert history are separate channels', async () => {
    // Regression: store once had two methods both named readHistory, and the
    // later definition (alerts) silently won — the server then loaded a list
    // of alerts where per-IP failure statistics were expected. The two must
    // stay separate methods reading separate files.
    const dir = tmp();
    const store = new Store({ dir });

    await store.writeHistory({ '1.0.0.2': { firstSeen: 1, lastSeen: 2, total: 3, times: [1, 2] } });
    await store.appendHistory({ ts: 'a', ok: true });

    const failures = store.readHistory({});
    assert.ok(!Array.isArray(failures), 'failure history is a map, not a list');
    assert.strictEqual(failures['1.0.0.2'].total, 3);
    assert.strictEqual(failures['1.0.0.2'].times.length, 2);

    const alerts = store.readAlerts(10);
    assert.ok(Array.isArray(alerts), 'alert history is a list');
    assert.strictEqual(alerts.length, 1);

    // A fresh store must see the same failure history (i.e. it is persisted,
    // not just held in memory).
    assert.strictEqual(new Store({ dir }).readHistory({})['1.0.0.2'].total, 3);

    store.writeHistorySync({ '1.2.3.4': { firstSeen: 5, lastSeen: 5, total: 1, times: [5] } });
    assert.strictEqual(new Store({ dir }).readHistory({})['1.2.3.4'].total, 1);
  });

  await test('cursor round-trips verbatim', async () => {
    const dir = tmp();
    const store = new Store({ dir });
    const cursor = 's=abc;i=4db6;b=edc0';
    await store.writeCursor(cursor);
    assert.strictEqual(store.readCursor(), cursor);
  });

  await test('missing cursor is an empty string', () => {
    assert.strictEqual(new Store({ dir: tmp() }).readCursor(), '');
  });

  await test('written files are not world readable', async () => {
    const dir = tmp();
    const file = path.join(dir, 'secret.json');
    await writeJsonAtomic(file, { k: 1 });
    const mode = fs.statSync(file).mode & 0o777;
    assert.strictEqual(mode, 0o600);
  });

  /* ------------------------------------------------------ traffic filter */

  await test('port list is normalised and merged', () => {
    const spec = tf.normalizePortSpec('8000-8100, 80, 80, 8000');
    assert.deepStrictEqual(spec.ranges, [[80, 80], [8000, 8100]]);
    assert.strictEqual(spec.spec, '80,8000-8100');
    assert.strictEqual(spec.all, false);
  });

  await test('adjacent ports collapse into one range', () => {
    assert.deepStrictEqual(tf.normalizePortSpec('80,81,82').ranges, [[80, 82]]);
  });

  await test('"all" drops the port match entirely', () => {
    const spec = tf.normalizePortSpec('all');
    assert.strictEqual(spec.all, true);
    assert.strictEqual(spec.spec, 'all');
  });

  await test('out-of-range port is rejected', () => {
    assert.throws(() => tf.normalizePortSpec('70000'), /不是合法端口/);
    assert.throws(() => tf.normalizePortSpec('10-5'), /不是合法端口/);
  });

  await test('regex over the port number expands to ranges', () => {
    const spec = tf.normalizePortSpec('8\\d{3}');
    assert.strictEqual(spec.spec, 're:8\\d{3}');
    assert.deepStrictEqual(spec.ranges, [[8000, 8999]]);
  });

  await test('regex is anchored to the whole port', () => {
    // "8" alone matches only port 8, not 18/80/800.
    assert.deepStrictEqual(tf.normalizePortSpec('re:8').ranges, [[8, 8]]);
  });

  await test('regex matching nothing is rejected', () => {
    assert.throws(() => tf.normalizePortSpec('re:99999'), /语法有误|匹配不到/);
  });

  await test('regex is length-capped', () => {
    assert.throws(() => tf.normalizePortSpec(`re:${'1'.repeat(tf.MAX_PORT_SPEC_LEN + 1)}`), /正则太长/);
  });

  await test('over-fragmented regex is refused', () => {
    // Odd-ending ports alternate with even ones, so this is ~32k disjoint ranges.
    assert.throws(() => tf.normalizePortSpec('re:\\d*[13579]'), /太碎/);
  });

  await test('rule defaults to 80/443 when no port is given', () => {
    const rule = tf.normalizeRule({ type: 'ip', value: '203.0.113.9', action: 'block' });
    assert.strictEqual(rule.port, '80,443');
    assert.strictEqual(rule.portLabel, '80,443');
  });

  await test('rule keeps a custom regex port spec', () => {
    const rule = tf.normalizeRule({ type: 'cidr', value: '198.51.100.0/24', action: 'block', port: 're:8\\d{3}' });
    assert.strictEqual(rule.port, 're:8\\d{3}');
    assert.match(rule.portLabel, /8000-8999/);
  });

  await test('CIDR with host bits set is normalised to the network', () => {
    const rule = tf.normalizeRule({ type: 'cidr', value: '8.8.8.77/24', action: 'block' });
    assert.strictEqual(rule.value, '8.8.8.0/24');
  });

  await test('too-broad CIDR is refused', () => {
    assert.throws(() => tf.normalizeRule({ type: 'cidr', value: '10.0.0.0/4', action: 'block' }), /范围太大/);
  });

  await test('empty match value is refused', () => {
    assert.throws(() => tf.normalizeRule({ type: 'ip', value: '', action: 'block' }), /请填写/);
  });

  await test('ruleset renders a port match for a web rule', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'block', priority: 10 }),
    ];
    const rs = tf.buildRuleset(rules, () => ({ v4: [], v6: [] }));
    assert.match(rs, /meta l4proto \{ tcp, udp \} th dport \{ 80, 443 \} ip  saddr @w0v4 counter drop/);
    assert.match(rs, /hook input priority 10; policy accept/);
  });

  await test('"all ports" rule has no l4 match', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'block', port: 'all' }),
    ];
    const rs = tf.buildRuleset(rules, () => ({ v4: [], v6: [] }));
    assert.match(rs, /\t\tip  saddr @w0v4 counter drop/);
    assert.doesNotMatch(rs, /th dport/);
  });

  await test('allow rules render accept', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'allow' }),
    ];
    const rs = tf.buildRuleset(rules, () => ({ v4: [], v6: [] }));
    assert.match(rs, /counter accept/);
  });

  await test('exempt addresses are accepted before any drop rule', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'country', value: 'cn', action: 'block', port: '80,443' }),
    ];
    const zone = { cn: { v4: ['1.2.3.0/24'], v6: ['2001:db8::/32'] } };
    const rs = tf.buildRuleset(rules, (cc) => zone[cc], {
      exempt: { v4: ['203.0.113.12'], v6: ['2001:db8:cafe::1'] },
    });
    const accept4 = rs.indexOf('ip  saddr @exemptv4 counter accept');
    const accept6 = rs.indexOf('ip6 saddr @exemptv6 counter accept');
    const drop4 = rs.indexOf('counter drop');
    assert.ok(accept4 > -1 && accept6 > -1, 'exempt accepts rendered');
    assert.ok(accept4 < drop4 && accept6 < drop4, 'exempt must come before the block rule');
    assert.match(rs, /elements = \{\n\t\t\t203\.0\.113\.12\n\t\t\}/);
  });

  await test('no exempt set when every rule is an allow', () => {
    const rules = [tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'allow' })];
    const rs = tf.buildRuleset(rules, () => ({}), { exempt: { v4: ['203.0.113.12'], v6: [] } });
    assert.doesNotMatch(rs, /exemptv4/);
  });

  await test('rules are ordered by priority then creation order', () => {

    const rules = [
      tf.normalizeRule({ id: 'c', type: 'ip', value: '203.0.113.3', action: 'block', priority: 20 }),
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.1', action: 'block', priority: 5 }),
      tf.normalizeRule({ id: 'b', type: 'ip', value: '203.0.113.2', action: 'block', priority: 20 }),
    ];
    const sorted = tf.sortRules(rules).map((r) => r.id);
    assert.deepStrictEqual(sorted, ['a', 'c', 'b']);
  });

  await test('country rule renders both address families', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'country', value: 'jp', action: 'block' }),
    ];
    const zone = { jp: { v4: ['1.2.3.0/24'], v6: ['2001:db8::/32'] } };
    const rs = tf.buildRuleset(rules, (cc) => zone[cc]);
    assert.match(rs, /set w0v4/);
    assert.match(rs, /set w0v6/);
    assert.match(rs, /ip6 saddr @w0v6 counter drop/);
  });

  await test('missing country zone is refused', () => {
    const rules = [tf.normalizeRule({ id: 'a', type: 'country', value: 'zz', action: 'block' })];
    assert.throws(() => tf.buildRuleset(rules, () => undefined), /没有 zz 的国家/);
  });

  await test('buildRuleset refuses an empty rule list', () => {
    assert.throws(() => tf.buildRuleset([], () => ({})), /没有启用的规则/);
  });

  await test('disabled rules are skipped in the ruleset', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'block', enabled: false }),
    ];
    assert.throws(() => tf.buildRuleset(rules, () => ({})), /没有启用的规则/);
  });

  await test('cidrContains matches inside and outside a parsed range', () => {
    const parsed = tf.parseCidr('198.51.100.0/24');
    assert.strictEqual(tf.cidrContains(parsed, '198.51.100.200'), true);
    assert.strictEqual(tf.cidrContains(parsed, '198.51.101.1'), false);
  });

  await test('traffic filter file round-trips', async () => {
    const dir = tmp();
    const store = new Store({ dir });
    await store.writeTrafficFilter({ enabled: true, rules: [{ id: 'w1', type: 'ip', value: '1.2.3.4' }] });
    assert.strictEqual(store.readTrafficFilter({}).rules[0].value, '1.2.3.4');
  });

  /* ------------------------------------------- web answer (404 / redirect) */

  await test('range splits into the minimal prefix list', () => {
    const prefixes = tf.rangeToPrefixes(tf.ipv4ToInt('1.0.1.0'), tf.ipv4ToInt('1.0.3.255'), 4);
    assert.deepStrictEqual(prefixes, ['1.0.1.0/24', '1.0.2.0/23']);
  });

  await test('a single host becomes a /32', () => {
    const n = tf.ipv4ToInt('203.0.113.9');
    assert.deepStrictEqual(tf.rangeToPrefixes(n, n, 4), ['203.0.113.9/32']);
  });

  await test('subtract removes the tail of a range', () => {
    const base = tf.cidrsToRanges(['198.51.100.0/24'], 4);
    const remove = tf.cidrsToRanges(['198.51.100.128/25'], 4);
    const left = tf.rangesToCidrs(tf.subtractRangeList(base, remove), 4);
    assert.deepStrictEqual(left, ['198.51.100.0/25']);
  });

  await test('web list honours first-match: later allow does not undo a block', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'cidr', value: '203.0.113.0/24', action: 'block', priority: 10, port: '443' }),
      tf.normalizeRule({ id: 'b', type: 'ip', value: '203.0.113.9', action: 'allow', priority: 20, port: '443' }),
    ];
    const web = tf.webBlockCidrs(rules, () => ({}), { port: 443 });
    const hit = web.v4.some((cidr) => tf.cidrContains(tf.parseCidr(cidr), '203.0.113.9'));
    assert.ok(hit, 'the earlier block still wins');
  });

  await test('web list lets an earlier allow punch a hole', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'allow', priority: 1, port: 'all' }),
      tf.normalizeRule({ id: 'b', type: 'cidr', value: '203.0.113.0/24', action: 'block', priority: 10, port: '443' }),
    ];
    const web = tf.webBlockCidrs(rules, () => ({}), { port: 443 });
    const hit = web.v4.some((cidr) => tf.cidrContains(tf.parseCidr(cidr), '203.0.113.9'));
    assert.strictEqual(hit, false, 'the allowed address is not in the block list');
  });

  await test('web list is per port and skips other-port rules', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'block', port: '443' }),
      tf.normalizeRule({ id: 'b', type: 'ip', value: '8.8.4.4', action: 'block', port: '22' }),
    ];
    const web = tf.webBlockList(rules, () => ({}), {});
    assert.deepStrictEqual(web['80'].v4, []);
    assert.ok(web['443'].v4.length > 0);
    const port443 = new Set(web['443'].v4);
    assert.ok(port443.has('203.0.113.9/32'));
    assert.ok(!port443.has('8.8.4.4/32'), 'port 22 rule must not leak into HTTPS');
  });

  await test('web list removes exempt addresses', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'cidr', value: '203.0.113.0/24', action: 'block', port: '443' }),
    ];
    const web = tf.webBlockCidrs(rules, () => ({}), { port: 443, exempt: { v4: ['203.0.113.9'], v6: [] } });
    const hit = web.v4.some((cidr) => tf.cidrContains(tf.parseCidr(cidr), '203.0.113.9'));
    assert.strictEqual(hit, false);
  });

  await test('web allow list keeps only addresses whose first web rule is allow', () => {
    const earlierAllow = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'allow', priority: 1, port: 'all' }),
      tf.normalizeRule({ id: 'b', type: 'cidr', value: '203.0.113.0/24', action: 'block', priority: 10, port: '443' }),
    ];
    const allowed = tf.webAllowCidrs(earlierAllow, () => ({}), { port: 443 });
    assert.ok(allowed.v4.some((cidr) => tf.cidrContains(tf.parseCidr(cidr), '203.0.113.9')));

    const laterAllow = [
      tf.normalizeRule({ id: 'a', type: 'cidr', value: '203.0.113.0/24', action: 'block', priority: 10, port: '443' }),
      tf.normalizeRule({ id: 'b', type: 'ip', value: '203.0.113.9', action: 'allow', priority: 20, port: '443' }),
    ];
    const after = tf.webAllowCidrs(laterAllow, () => ({}), { port: 443 });
    assert.ok(!after.v4.some((cidr) => tf.cidrContains(tf.parseCidr(cidr), '203.0.113.9')));
  });

  await test('web allow list is per port', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'allow', port: '80' }),
    ];
    const allowed = tf.webAllowList(rules, () => ({}));
    assert.ok(allowed['80'].v4.includes('203.0.113.9/32'));
    assert.deepStrictEqual(allowed['443'].v4, []);
  });

  await test('a rule answered entirely by nginx leaves no nft rule', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'block', port: '80,443' }),
    ];
    const rs = tf.buildRuleset(rules, () => ({}), { webAnswer: tf.WEB_PORTS });
    assert.strictEqual(rs, null);
  });

  await test('webAnswer strips only 80/443 from a mixed rule', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'block', port: '22,80,443' }),
    ];
    const rs = tf.buildRuleset(rules, () => ({}), { webAnswer: tf.WEB_PORTS });
    assert.match(rs, /th dport \{ 22 \} ip  saddr @w0v4 counter drop/);
    assert.doesNotMatch(rs, /80, 443\}/);
  });

  await test('webAnswer keeps non-port protocols for an "all" rule', () => {
    const rules = [
      tf.normalizeRule({ id: 'a', type: 'ip', value: '203.0.113.9', action: 'block', port: 'all' }),
    ];
    const rs = tf.buildRuleset(rules, () => ({}), { webAnswer: tf.WEB_PORTS });
    assert.match(rs, /meta l4proto != \{ tcp, udp \} ip  saddr @w0v4 counter drop/);
    assert.match(rs, /meta l4proto \{ tcp, udp \} th dport \{ 1-79, 81-442, 444-65535 \} ip  saddr @w0v4 counter drop/);
  });

  await test('mode list and failure URL are stable', () => {
    assert.deepStrictEqual(tf.MODES, ['drop', '404', 'redirect']);
    assert.strictEqual(tf.FAILED_URL, 'https://blocked.example.com/');
  });

  await test('default failure page picks the language in the browser', () => {
    const html = failedPage.DEFAULT_FAILED_HTML;
    assert.match(html, /navigator\.language/);
    assert.match(html, /zh: \[/);
    assert.match(html, /en: \[/);
    assert.match(html, /\|\| strings\.en/);
    // The blocked-visitor wording the panel documents.
    assert.match(html, /本网站暂未对您所在的国家或地区开放/);
  });

  await test('failure page input is size-capped but otherwise free-form', () => {
    assert.strictEqual(failedPage.normalizeFailedHtml('<p>hi</p>'), '<p>hi</p>');
    assert.throws(
      () => failedPage.normalizeFailedHtml('x'.repeat(failedPage.MAX_FAILED_HTML + 1)),
      /太长/,
    );
  });

  /* ------------------------------------------------ Cloudflare trusted ranges */

  await test('cloudflare list keeps only valid CIDRs of the right family', () => {
    assert.deepStrictEqual(
      cloudflare.parseList('173.245.48.0/20\nnot-a-cidr\n1.2.3.4/24\n2606:4700::/32\n', 4),
      ['173.245.48.0/20', '1.2.3.0/24'],
    );
    assert.deepStrictEqual(
      cloudflare.parseList('2606:4700::/32\n173.245.48.0/20\n', 6),
      ['2606:4700:0000:0000:0000:0000:0000:0000/32'],
    );
  });

  await test('cloudflare defaults are valid and non-empty', () => {
    const v4 = cloudflare.parseList(cloudflare.BUILTIN_V4.join('\n'), 4);
    const v6 = cloudflare.parseList(cloudflare.BUILTIN_V6.join('\n'), 6);
    assert.strictEqual(v4.length, cloudflare.BUILTIN_V4.length);
    assert.strictEqual(v6.length, cloudflare.BUILTIN_V6.length);
  });

  await test('empty Cloudflare input falls back to the built-in list', () => {
    const ranges = cloudflare.normalizeRanges({ v4: [], v6: [] });
    assert.ok(ranges.v4.includes('104.16.0.0/13'));
    assert.ok(ranges.v6.some((cidr) => cidr.startsWith('2606:4700:')));
    assert.strictEqual(ranges.v6.length, cloudflare.BUILTIN_V6.length);
    assert.strictEqual(ranges.source, 'builtin');
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
