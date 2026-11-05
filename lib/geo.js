'use strict';

/**
 * GeoIP lookup for login alerts.
 *
 * ipwho.is is the primary: no API key, HTTPS, and it returns country, region,
 * city and organisation in one call. api.country.is is the fallback for the
 * case where the primary is rate limited.
 *
 * Results are cached per IP forever: an IP belongs to one organisation for a
 * long time, and re-querying on every login would just burn someone else's
 * free quota. Failures are cached briefly so a dead provider does not stall
 * every alert.
 */

const https = require('https');

const FAILURE_TTL_MS = 10 * 60 * 1000;

function getJson(url, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const req = https.get(
      url,
      { headers: { accept: 'application/json', 'user-agent': 'server-panel/1.0' }, timeout: timeoutMs },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve({ ok: false, error: `HTTP ${res.statusCode}` });
          return;
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve({ ok: true, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
          } catch (err) {
            resolve({ ok: false, error: `bad json: ${err.message}` });
          }
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (err) => resolve({ ok: false, error: err.message }));
  });
}

/**
 * @returns {Promise<{ok: true, country: string, countryCode: string, region: string,
 *                    city: string, org: string, timezone: string}
 *                 | {ok: false, error: string}>}
 */
async function lookupUncached(ip) {
  const primary = await getJson(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (primary.ok && primary.body && primary.body.success !== false) {
    const b = primary.body;
    return {
      ok: true,
      country: b.country || '未知',
      countryCode: b.country_code || '',
      region: b.region || '',
      city: b.city || '',
      org: (b.connection && (b.connection.isp || b.connection.org)) || '',
      timezone: (b.timezone && b.timezone.id) || '',
      source: 'ipwho.is',
    };
  }

  const fallback = await getJson(`https://api.country.is/${encodeURIComponent(ip)}`);
  if (fallback.ok && fallback.body && fallback.body.country) {
    return {
      ok: true,
      country: fallback.body.country,
      countryCode: fallback.body.country,
      region: '',
      city: '',
      org: '',
      timezone: '',
      source: 'api.country.is',
    };
  }

  return { ok: false, error: primary.error || fallback.error || 'lookup failed' };
}

class GeoCache {
  constructor({ cache = {}, now = () => Date.now() } = {}) {
    this.cache = cache || {};
    this.now = now;
  }

  get(ip) {
    const hit = this.cache[ip];
    if (!hit) return null;
    if (hit.ok) return hit;
    if (this.now() - (hit.failedAt || 0) > FAILURE_TTL_MS) return null;
    return hit;
  }

  set(ip, result) {
    this.cache[ip] = result.ok ? { ...result, at: this.now() } : { ...result, failedAt: this.now() };
    return this.cache[ip];
  }

  /** Look up only when not cached. Never throws. */
  async resolve(ip, { allowNetwork = true } = {}) {
    const cached = this.get(ip);
    if (cached) return cached;
    if (!allowNetwork) return { ok: false, error: 'network disabled' };

    const result = await lookupUncached(ip);
    return this.set(ip, result);
  }
}

/** "United Kingdom · London · AS16509 Amazon.com" — readable one-liner. */
function describe(geo) {
  if (!geo || !geo.ok) return '国家/地区未知';
  const parts = [geo.country];
  if (geo.city) parts.push(geo.city);
  else if (geo.region) parts.push(geo.region);
  const place = parts.filter(Boolean).join(' · ');
  return geo.org ? `${place}（${geo.org}）` : place;
}

module.exports = { lookupUncached, GeoCache, describe };
