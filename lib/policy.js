'use strict';

/**
 * Alert decision logic.
 *
 * A single over-threshold sample means nothing — a `tar` or a deploy spikes CPU
 * for a second. The user's definition of "sustained" is two conditions:
 *
 *   - consecutive: N samples in a row are over the threshold
 *   - window:      M samples within the last hour are over the threshold
 *
 * Both are configurable at panel.example.com. `combine` decides how they
 * relate:
 *
 *   "any" (default) — either condition fires. Catches a 3-minute spike quickly,
 *                     and also catches flapping that never lasts 3 samples.
 *   "all"           — both must hold. Quieter, but the first alert cannot
 *                     arrive before the window count is reached (~10 min).
 *
 * After firing, the metric enters a cooldown. Without it a load that lasts an
 * hour would send 60 emails.
 */

const DEFAULTS = {
  enabled: true,
  cpuPercent: 85,
  memPercent: 85,
  netMbps: 25,
  consecutive: 3,
  windowCount: 10,
  windowMinutes: 60,
  combine: 'any',
  cooldownMinutes: 30,
  sshAlertsEnabled: true,
  sshFailAlertsEnabled: true,
  sshFailCount: 3,
  sshFailWindowMinutes: 60,
  sshFailCooldownMinutes: 60,
  // Automatic blocking. Off by default: blocking is a change to the firewall,
  // and an operator should opt in rather than have it happen unannounced.
  autoBlockEnabled: false,
  autoBlockCount: 100,
  autoBlockWindowMinutes: 1440,
  // Country allow-list for SSH. Off by default for the same reason: this can
  // lock a travelling operator out, so it must never turn itself on.
  geoipEnabled: false,
  geoipCountries: ['cn', 'hk', 'tw', 'gb', 'jp', 'sg'],
};

const METRICS = ['cpu', 'mem', 'net'];

function toNumber(value, fallback, { min = -Infinity, max = Infinity, integer = false } = {}) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const clamped = Math.min(max, Math.max(min, n));
  return integer ? Math.round(clamped) : clamped;
}

/** Coerce arbitrary user input into a complete, sane ruleset. */
function normalizeRules(input = {}) {
  const src = input && typeof input === 'object' ? input : {};
  const combine = src.combine === 'all' ? 'all' : 'any';

  return {
    enabled: src.enabled === undefined ? DEFAULTS.enabled : Boolean(src.enabled),
    cpuPercent: toNumber(src.cpuPercent, DEFAULTS.cpuPercent, { min: 1, max: 100 }),
    memPercent: toNumber(src.memPercent, DEFAULTS.memPercent, { min: 1, max: 100 }),
    netMbps: toNumber(src.netMbps, DEFAULTS.netMbps, { min: 0.1, max: 100000 }),
    consecutive: toNumber(src.consecutive, DEFAULTS.consecutive, { min: 1, max: 1440, integer: true }),
    windowCount: toNumber(src.windowCount, DEFAULTS.windowCount, { min: 1, max: 10000, integer: true }),
    windowMinutes: toNumber(src.windowMinutes, DEFAULTS.windowMinutes, { min: 1, max: 1440, integer: true }),
    combine,
    cooldownMinutes: toNumber(src.cooldownMinutes, DEFAULTS.cooldownMinutes, { min: 1, max: 1440, integer: true }),
    sshAlertsEnabled:
      src.sshAlertsEnabled === undefined ? DEFAULTS.sshAlertsEnabled : Boolean(src.sshAlertsEnabled),
    sshFailAlertsEnabled:
      src.sshFailAlertsEnabled === undefined
        ? DEFAULTS.sshFailAlertsEnabled
        : Boolean(src.sshFailAlertsEnabled),
    sshFailCount: toNumber(src.sshFailCount, DEFAULTS.sshFailCount, { min: 1, max: 10000, integer: true }),
    sshFailWindowMinutes: toNumber(src.sshFailWindowMinutes, DEFAULTS.sshFailWindowMinutes, {
      min: 1,
      max: 1440,
      integer: true,
    }),
    sshFailCooldownMinutes: toNumber(src.sshFailCooldownMinutes, DEFAULTS.sshFailCooldownMinutes, {
      min: 1,
      max: 1440,
      integer: true,
    }),
    autoBlockEnabled:
      src.autoBlockEnabled === undefined ? DEFAULTS.autoBlockEnabled : Boolean(src.autoBlockEnabled),
    autoBlockCount: toNumber(src.autoBlockCount, DEFAULTS.autoBlockCount, {
      min: 2,
      max: 100000,
      integer: true,
    }),
    autoBlockWindowMinutes: toNumber(src.autoBlockWindowMinutes, DEFAULTS.autoBlockWindowMinutes, {
      min: 1,
      max: 10080,
      integer: true,
    }),
    geoipEnabled:
      src.geoipEnabled === undefined ? DEFAULTS.geoipEnabled : Boolean(src.geoipEnabled),
    // Two-letter ISO codes only. Anything else would produce a URL that looks
    // valid but downloads an error page the firewall would then load.
    geoipCountries: Array.isArray(src.geoipCountries)
      ? src.geoipCountries
          .map((c) => String(c || '').trim().toLowerCase())
          .filter((c) => /^[a-z]{2}$/.test(c))
      : DEFAULTS.geoipCountries.slice(),
  };
}

function thresholdFor(metric, rules) {
  if (metric === 'cpu') return rules.cpuPercent;
  if (metric === 'mem') return rules.memPercent;
  return rules.netMbps;
}

function valueFor(metric, sample) {
  if (!sample) return null;
  if (metric === 'cpu') return sample.cpuPercent;
  if (metric === 'mem') return sample.memPercent;
  if (metric === 'net') return sample.net ? sample.net.totalMbps : null;
  return null;
}

function emptyState(now = Date.now()) {
  return {
    startedAt: now,
    metrics: Object.fromEntries(
      METRICS.map((m) => [m, { consecutive: 0, window: [], lastAlertAt: null, peak: null }]),
    ),
  };
}

/**
 * Feed one sample through the rules.
 *
 * Pure function: mutates and returns `state`, and reports which metrics should
 * send a notification now.
 *
 * @returns {{state: object, actions: Array<{metric: string, value: number, threshold: number, consecutive: number, windowCount: number, peak: number|null, reason: string}>}}
 */
function evaluate(state, sample, rules, now = Date.now()) {
  const next = state && state.metrics ? state : emptyState(now);
  const actions = [];
  const windowMs = rules.windowMinutes * 60 * 1000;

  for (const metric of METRICS) {
    const bucket = next.metrics[metric] || { consecutive: 0, window: [], lastAlertAt: null, peak: null };
    const value = valueFor(metric, sample);
    const threshold = thresholdFor(metric, rules);

    // The first sample has no CPU/network delta, so it cannot be judged.
    if (value === null || value === undefined || !Number.isFinite(value)) {
      next.metrics[metric] = bucket;
      continue;
    }

    const over = value >= threshold;
    if (over) {
      bucket.consecutive += 1;
      bucket.window.push(now);
      bucket.peak = bucket.peak === null ? value : Math.max(bucket.peak, value);
    } else {
      bucket.consecutive = 0;
      bucket.peak = null;
    }

    const cutoff = now - windowMs;
    while (bucket.window.length && bucket.window[0] < cutoff) bucket.window.shift();

    const byConsecutive = bucket.consecutive >= rules.consecutive;
    const byWindow = bucket.window.length >= rules.windowCount;
    const triggered =
      rules.combine === 'all' ? byConsecutive && byWindow : byConsecutive || byWindow;

    const cooledDown =
      bucket.lastAlertAt === null ||
      bucket.lastAlertAt === undefined ||
      now - bucket.lastAlertAt >= rules.cooldownMinutes * 60 * 1000;

    if (triggered && cooledDown) {
      bucket.lastAlertAt = now;
      actions.push({
        metric,
        value,
        threshold,
        consecutive: bucket.consecutive,
        windowCount: bucket.window.length,
        peak: bucket.peak,
        reason: byConsecutive && byWindow ? 'both' : byConsecutive ? 'consecutive' : 'window',
      });
    }

    next.metrics[metric] = bucket;
  }

  next.lastSampleAt = now;
  return { state: next, actions };
}

module.exports = {
  DEFAULTS,
  METRICS,
  normalizeRules,
  evaluate,
  emptyState,
  thresholdFor,
  valueFor,
};
