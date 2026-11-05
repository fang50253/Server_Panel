'use strict';

/**
 * Signed client for the mail panel's local send API.
 *
 * This is a self-contained copy of the signing logic instead of importing
 * /opt/mail-panel/examples/client.js. Two services, two independent deploy
 * trees: if the monitor is redeployed alone it must not break because the mail
 * panel moved. The protocol is documented in mail-panel/Mail_API.md and covered by
 * tests on both sides.
 */

const http = require('http');
const crypto = require('crypto');

class MailApiError extends Error {
  constructor(message, { status, code, body } = {}) {
    super(message);
    this.name = 'MailApiError';
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

function signingString({ keyId, timestamp, nonce, body }) {
  const digest = crypto.createHash('sha256').update(body).digest('hex');
  return `${keyId}\n${timestamp}\n${nonce}\n${digest}`;
}

function hmacHex(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

class MailApiClient {
  constructor({ socket, keyId, secret, timeoutMs = 20000 }) {
    if (!socket) throw new Error('socket is required');
    if (!keyId) throw new Error('keyId is required');
    if (!secret) throw new Error('secret is required');
    this.socket = socket;
    this.keyId = keyId;
    this.secret = secret;
    this.timeoutMs = timeoutMs;
  }

  /** POST /v1/send with a security-alert style template. */
  async send({ template, to, vars, idempotencyKey }) {
    const payload = { template, to, vars };
    if (idempotencyKey) payload.idempotencyKey = idempotencyKey;
    return this.request('POST', '/v1/send', payload);
  }

  async health() {
    return this.request('GET', '/v1/health');
  }

  request(method, path, payload) {
    const body = payload === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(payload), 'utf8');
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomBytes(16).toString('hex');
    const signature = hmacHex(
      this.secret,
      signingString({ keyId: this.keyId, timestamp, nonce, body }),
    );

    const headers = {
      'x-mail-key': this.keyId,
      'x-mail-timestamp': timestamp,
      'x-mail-nonce': nonce,
      'x-mail-signature': signature,
    };
    if (body.length) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = body.length;
    }

    return new Promise((resolve, reject) => {
      const req = http.request(
        { method, path, headers, socketPath: this.socket },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed = {};
            try {
              parsed = text ? JSON.parse(text) : {};
            } catch {
              parsed = { raw: text };
            }
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve(parsed);
              return;
            }
            reject(
              new MailApiError(parsed.message || `HTTP ${res.statusCode}`, {
                status: res.statusCode,
                code: parsed.error,
                body: parsed,
              }),
            );
          });
        },
      );

      req.setTimeout(this.timeoutMs, () => {
        req.destroy(new Error(`mail API timed out after ${this.timeoutMs}ms`));
      });
      req.on('error', reject);
      if (body.length) req.write(body);
      req.end();
    });
  }
}

module.exports = { MailApiClient, MailApiError, signingString, hmacHex };
