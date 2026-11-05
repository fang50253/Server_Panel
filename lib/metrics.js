'use strict';

/**
 * Resource sampling from /proc.
 *
 * Everything that touches /proc is wrapped so the parsers can be unit tested
 * with fixture strings — the test machine is macOS, where /proc does not exist.
 */

const fs = require('fs');

function clampPercent(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.min(100, Math.max(0, value));
}

/**
 * Parse the aggregate `cpu` line of /proc/stat.
 *
 * Fields: user nice system idle iowait irq softirq steal guest guest_nice
 * guest time is already included in user/nice, so only the first 8 are summed.
 */
function parseProcStat(text) {
  const line = String(text || '')
    .split('\n')
    .find((l) => l.startsWith('cpu '));
  if (!line) return null;

  const nums = line.trim().split(/\s+/).slice(1, 9).map(Number);
  if (nums.length < 4 || nums.some((n) => !Number.isFinite(n))) return null;

  const total = nums.reduce((a, b) => a + b, 0);
  const idle = nums[3] + (nums[4] || 0); // idle + iowait
  return { total, idle, busy: total - idle };
}

/** CPU usage between two snapshots, as a percentage. */
function cpuPercent(prev, next) {
  if (!prev || !next) return null;
  const dTotal = next.total - prev.total;
  const dIdle = next.idle - prev.idle;
  if (dTotal <= 0) return null;
  return clampPercent(((dTotal - dIdle) / dTotal) * 100);
}

function parseMeminfo(text) {
  const out = {};
  for (const line of String(text || '').split('\n')) {
    const m = /^(\w+):\s+(\d+)\s*kB/.exec(line);
    if (m) out[m[1]] = Number(m[2]) * 1024;
  }
  const total = out.MemTotal || 0;
  // MemAvailable is the realistic "could be freed" figure on Linux >= 3.14.
  const available = out.MemAvailable ?? out.MemFree ?? 0;
  const used = Math.max(0, total - available);
  return {
    totalBytes: total,
    availableBytes: available,
    usedBytes: used,
    usedPercent: total ? clampPercent((used / total) * 100) : 0,
    swapTotalBytes: out.SwapTotal || 0,
    swapFreeBytes: out.SwapFree || 0,
  };
}

/**
 * Sum rx/tx over every interface except loopback.
 * Loopback traffic is local IPC, not real network usage.
 */
function parseNetDev(text) {
  let rx = 0;
  let tx = 0;
  for (const line of String(text || '').split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim();
    if (!name || name === 'lo') continue;
    const nums = line.slice(idx + 1).trim().split(/\s+/).map(Number);
    if (nums.length < 9) continue;
    if (Number.isFinite(nums[0])) rx += nums[0]; // received bytes
    if (Number.isFinite(nums[8])) tx += nums[8]; // transmitted bytes
  }
  return { rxBytes: rx, txBytes: tx, totalBytes: rx + tx };
}

/** Bytes-per-second between two net snapshots, split by direction. */
function netRates(prev, next, elapsedMs) {
  if (!prev || !next || !(elapsedMs > 0)) return null;
  const seconds = elapsedMs / 1000;
  const rxDelta = Math.max(0, next.rxBytes - prev.rxBytes);
  const txDelta = Math.max(0, next.txBytes - prev.txBytes);
  return {
    rxBytesPerSec: rxDelta / seconds,
    txBytesPerSec: txDelta / seconds,
    totalBytesPerSec: (rxDelta + txDelta) / seconds,
    rxMbps: (rxDelta * 8) / seconds / 1e6,
    txMbps: (txDelta * 8) / seconds / 1e6,
    totalMbps: ((rxDelta + txDelta) * 8) / seconds / 1e6,
  };
}

function readFile(path) {
  try {
    return fs.readFileSync(path, 'utf8');
  } catch {
    return '';
  }
}

/**
 * Stateful sampler. Call `sample(now)` once per interval and compare the
 * returned values against thresholds. The first call has no deltas yet, so
 * cpu/net are null and only memory is meaningful.
 */
class Sampler {
  constructor({ cpuPath = '/proc/stat', memPath = '/proc/meminfo', netPath = '/proc/net/dev' } = {}) {
    this.cpuPath = cpuPath;
    this.memPath = memPath;
    this.netPath = netPath;
    this.prevCpu = null;
    this.prevNet = null;
    this.prevTs = null;
  }

  sample(now = Date.now()) {
    const cpu = parseProcStat(readFile(this.cpuPath));
    const mem = parseMeminfo(readFile(this.memPath));
    const net = parseNetDev(readFile(this.netPath));

    const elapsedMs = this.prevTs === null ? 0 : now - this.prevTs;

    const result = {
      ts: now,
      cpuPercent: cpuPercent(this.prevCpu, cpu),
      memPercent: mem.usedPercent,
      mem: {
        totalBytes: mem.totalBytes,
        usedBytes: mem.usedBytes,
        availableBytes: mem.availableBytes,
      },
      net: null,
      cpuCores: 1,
    };

    if (elapsedMs > 0) {
      result.net = netRates(this.prevNet, net, elapsedMs);
    }

    this.prevCpu = cpu;
    this.prevNet = net;
    this.prevTs = now;
    return result;
  }
}

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatMbps(mbps) {
  const n = Number(mbps) || 0;
  if (n >= 100) return `${n.toFixed(0)} Mbps`;
  if (n >= 10) return `${n.toFixed(1)} Mbps`;
  return `${n.toFixed(2)} Mbps`;
}

module.exports = {
  parseProcStat,
  cpuPercent,
  parseMeminfo,
  parseNetDev,
  netRates,
  Sampler,
  formatBytes,
  formatMbps,
  clampPercent,
};
