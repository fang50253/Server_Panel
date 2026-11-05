'use strict';

/**
 * Session auth for the monitor dashboard.
 *
 * Same scheme as the mail panel (HMAC-signed cookie, no session table) but with
 * its own cookie name, password and secret. Two services, two credentials: a
 * stolen monitor cookie must not open the mail panel, and rotating one
 * password must not log the other out.
 */

const crypto = require('crypto');

const COOKIE = 'mon_session';
const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000; // 12h

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function sign(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

class Auth {
  constructor({ password, secret, ttlMs = DEFAULT_TTL_MS }) {
    this.password = password || '';
    this.secret = secret || '';
    this.ttlMs = ttlMs;
    this.enabled = Boolean(this.password && this.secret);
  }

  checkPassword(candidate) {
    if (!this.enabled) return false;
    const a = crypto.createHash('sha256').update(String(candidate || '')).digest();
    const b = crypto.createHash('sha256').update(this.password).digest();
    return crypto.timingSafeEqual(a, b);
  }

  issueToken(now = Date.now()) {
    const payload = String(now + this.ttlMs);
    return `${payload}.${sign(this.secret, payload)}`;
  }

  verifyToken(token, now = Date.now()) {
    if (!token || !this.secret) return false;
    const idx = token.lastIndexOf('.');
    if (idx === -1) return false;
    const payload = token.slice(0, idx);
    const mac = token.slice(idx + 1);
    const expected = sign(this.secret, payload);
    if (mac.length !== expected.length) return false;
    if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return false;
    const expiry = Number(payload);
    return Number.isFinite(expiry) && expiry > now;
  }

  parseCookies(header) {
    const out = {};
    for (const part of String(header || '').split(';')) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
    }
    return out;
  }

  isAuthed(req) {
    if (!this.enabled) return false;
    return this.verifyToken(this.parseCookies(req.headers.cookie)[COOKIE]);
  }

  cookieHeader(token) {
    const maxAge = Math.floor(this.ttlMs / 1000);
    return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
  }

  clearCookieHeader() {
    return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
  }

  csrfFor(req) {
    const session = this.parseCookies(req.headers.cookie)[COOKIE] || '';
    return b64url(crypto.createHmac('sha256', this.secret).update(`csrf:${session}`).digest());
  }

  checkCsrf(req, token) {
    const expected = this.csrfFor(req);
    if (!token || token.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  }
}

module.exports = { Auth, COOKIE };
