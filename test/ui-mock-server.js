'use strict';
/**
 * Local render harness: serves the real ui.html with canned API responses so
 * the block/unblock UI can be inspected without touching the server.
 *
 *   node monitor/test/ui-mock-server.js   ->   http://127.0.0.1:8099/
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const UI = path.join(__dirname, '..', 'ui.html');
const now = Date.now();

const status = {
  ok: true,
  host: 'example.com',
  now,
  sampleIntervalMs: 60000,
  lastSampleAt: now,
  sample: {
    cpuPercent: 12.4, memPercent: 41.2, memUsed: 1.6e9, memTotal: 4e9,
    netMbps: 0.3, diskPercent: 22, load1: 0.1, load5: 0.1, load15: 0.1,
    uptimeSec: 900000,
  },
  rules: {
    enabled: true, cpuPercent: 85, memPercent: 85, netMbps: 25, consecutive: 3,
    windowMinutes: 60, windowCount: 10, combine: 'any', cooldownMinutes: 30,
    sshAlertsEnabled: true, sshFailAlertsEnabled: true,
    sshFailCount: 3, sshFailWindowMinutes: 60, sshFailCooldownMinutes: 60,
    autoBlockEnabled: true, autoBlockCount: 100, autoBlockWindowMinutes: 1440,
  },
  ssh: { enabled: true, failAlertsEnabled: true, knownIps: 3, trackedFailIps: 4, lastError: null },
  counters: { alertsSent: 2, sshAlertsSent: 2, sshFailAlertsSent: 1 },
  lastError: null,
  mail: { socket: '/run/mail-panel/api.sock', configured: true, to: 'admin@example.com' },
  blocks: { total: 2, nftError: null, protectedIps: ['203.0.113.11'] },
};

// Failed-attempt rows: generated so the UI's paging (10 per page) can be
// exercised locally without touching the server.
const failRows = [
  { ip: '198.51.100.66', count: 550, users: ['qwe', 'alpha', 'root'], first: now - 3600e3, last: now - 600e3, lastAlertAt: now - 3000e3, totalEver: 1001, threshold: 3, blocked: true, blockSource: 'manual', blockedAt: now - 900e3, droppedSinceBlock: 24, attempts: 24 },
  { ip: '198.51.100.152', count: 10, users: ['root'], first: now - 2400e3, last: now - 300e3, lastAlertAt: null, totalEver: 65, threshold: 3, blocked: true, blockSource: 'auto', blockedAt: now - 800e3, droppedSinceBlock: 0, attempts: 0 },
  { ip: '198.51.100.141', count: 15, users: ['root'], first: now - 1800e3, last: now - 120e3, lastAlertAt: null, totalEver: 60, threshold: 3, blocked: false, blockedAt: null, droppedSinceBlock: 0 },
  { ip: '203.0.113.11', count: 2, users: ['root'], first: now - 900e3, last: now - 60e3, lastAlertAt: null, totalEver: 2, threshold: 3, blocked: false, blockedAt: null, droppedSinceBlock: 0 },
  // History-only: window aged out, not blocked, permanent record remains.
  { ip: '198.51.100.180', count: 0, users: [], first: now - 86400e3, last: now - 72000e3, lastAlertAt: null, totalEver: 1427, threshold: 3, blocked: false, blockedAt: null, droppedSinceBlock: 0 },
  { ip: '198.51.100.194', count: 0, users: [], first: now - 86400e3, last: now - 70000e3, lastAlertAt: null, totalEver: 1789, threshold: 3, blocked: false, blockedAt: null, droppedSinceBlock: 0 },
];
for (let i = 0; i < 20; i += 1) {
  failRows.push({ ip: `52.${i}.0.1`, ...(failRows[i % 6]) });
}

const failures = {
  ok: true,
  windowMinutes: 60,
  threshold: 3,
  nftAvailable: true,
  nftError: null,
  protectedIps: ['203.0.113.11'],
  ips: failRows,
};

const blocked = {
  ok: true,
  nftAvailable: true,
  nftError: null,
  protectedIps: ['203.0.113.11'],
  sshPorts: [22],
  ips: [
    { ip: '198.51.100.66', blockedAt: now - 900e3, source: 'manual', failedBeforeBlock: 534, droppedSinceBlock: 24, packets: 24, bytes: 1440, lastSeen: now - 600e3, users: ['qwe'], geo: { country: 'Germany', city: 'Frankfurt' }, inKernelSet: true },
    { ip: '198.51.100.152', blockedAt: now - 800e3, source: 'auto', failedBeforeBlock: 10, droppedSinceBlock: 0, packets: 0, bytes: 0, lastSeen: null, users: ['root'], geo: { country: 'Netherlands', city: 'Amsterdam' }, inKernelSet: true },
  ],
};

const known = {
  ok: true,
  ips: [
    { ip: '203.0.113.13', firstSeen: now - 86400e3, lastSeen: now - 60e3, count: 404, user: 'root', geo: { country: 'United Kingdom', city: 'London' } },
    { ip: '203.0.113.11', firstSeen: now - 4000e3, lastSeen: now - 4000e3, count: 1, user: 'root', geo: { country: 'China', city: 'Nanjing' } },
  ],
};

const alertsList = Array.from({ length: 15 }, (_, i) => ({
  ts: new Date(now - i * 3600e3).toISOString(),
  kind: ['resource', 'ssh', 'ssh-fail'][i % 3],
  ok: i % 4 !== 0,
  title: ['CPU 持续超阈值', '新 IP root 登录', '失败登录密集'][i % 3],
  id: 'deadbeef' + i,
  error: i % 4 === 0 ? 'SMTP connect failed' : null,
}));

const routes = {
  '/api/session': { ok: true, csrf: 'mock-csrf' },
  '/api/status': status,
  '/api/history': { ok: true, alerts: alertsList },
  '/api/known-ips': known,
  '/api/ssh-failures': failures,
  '/api/blocked': blocked,
  '/api/geoip': { ok: true, enabled: true, countries: ['cn', 'hk', 'tw', 'gb', 'jp', 'sg'],
                  active: true, v4Count: 29293, v6Count: 6691, acceptedPackets: 4102,
                  rejectedPackets: 377, lastFetchAt: now - 3600e3, appliedAt: now - 3600e3,
                  error: null, protectedIps: ['203.0.113.11'] },
};

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/' ) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(UI));
    return;
  }
  if (req.method === 'POST' && (url.pathname === '/api/block' || url.pathname === '/api/unblock')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method === 'POST' && url.pathname === '/api/fail-history/clear') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, cleared: 24 }));
    return;
  }
  if (req.method === 'POST' && url.pathname === '/api/geoip/toggle') {
    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, enabled: JSON.parse(body || '{}').enabled === true }));
    });
    return;
  }
  const body = routes[url.pathname];
  res.writeHead(body ? 200 : 404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body || { ok: false }));
}).listen(8099, '127.0.0.1', () => console.log('http://127.0.0.1:8099/'));
