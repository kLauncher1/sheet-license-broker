import { createHash, createHmac, randomBytes } from 'node:crypto';
import { getMachineHwid } from './hwid.js';

export class BrokerError extends Error {
  constructor(message, statusCode, details) {
    super(message);
    this.name = 'BrokerError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

export class AuthenticationError extends BrokerError {
  constructor(message, statusCode, details) {
    super(message, statusCode, details);
    this.name = 'AuthenticationError';
  }
}

export class LicenseValidationError extends BrokerError {
  constructor(message, statusCode, details) {
    super(message, statusCode, details);
    this.name = 'LicenseValidationError';
  }
}

export class SheetLicenseClient {
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || 'http://127.0.0.1:9082').replace(/\/+$/, '');
    this.secretKey = options.secretKey;
    this.timeoutMs = options.timeoutMs || 10000;
  }

  computeBodyHash(body) {
    return createHash('sha256').update(body, 'utf8').digest('hex');
  }

  buildCanonicalString(method, path, timestamp, nonce, body) {
    const bHash = this.computeBodyHash(body);
    return `${method.toUpperCase().trim()}\n${path.trim()}\n${timestamp}\n${nonce}\n${bHash}`;
  }

  sign(method, path, timestamp, nonce, body) {
    if (!this.secretKey) return '';
    const canonical = this.buildCanonicalString(method, path, timestamp, nonce, body);
    return createHmac('sha256', this.secretKey).update(canonical, 'utf8').digest('hex');
  }

  async request(method, path, payload) {
    const url = `${this.baseUrl}${path}`;
    const bodyStr = payload !== undefined ? JSON.stringify(payload) : '';

    const headers = {
      Accept: 'application/json',
      'User-Agent': 'SheetLicenseClient-TS/0.4.0',
    };

    if (payload !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    if (this.secretKey) {
      const ts = Math.floor(Date.now() / 1000);
      const nonce = randomBytes(16).toString('hex');
      const sig = this.sign(method, path, ts, nonce, bodyStr);

      headers['X-Signature'] = sig;
      headers['X-Timestamp'] = String(ts);
      headers['X-Nonce'] = nonce;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(url, {
        method,
        headers,
        body: method !== 'GET' && bodyStr ? bodyStr : undefined,
        signal: controller.signal,
      });

      const text = await res.text();
      let data = {};
      try {
        if (text) data = JSON.parse(text);
      } catch {}

      if (!res.ok) {
        const errMsg = data.error || data.message || `HTTP ${res.status}`;
        if (res.status === 401) {
          if (String(errMsg).toLowerCase().includes('signature')) {
            throw new AuthenticationError(`Security signature failed: ${errMsg}`, res.status, data);
          }
          throw new LicenseValidationError(`License authorization failed: ${errMsg}`, res.status, data);
        }
        throw new BrokerError(`Broker error (${res.status}): ${errMsg}`, res.status, data);
      }

      return data;
    } catch (err) {
      if (err instanceof BrokerError) throw err;
      if (err.name === 'AbortError') {
        throw new BrokerError(`Request timed out after ${this.timeoutMs}ms`);
      }
      throw new BrokerError(`Network failure contacting broker: ${err.message}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async health() {
    return this.request('GET', '/health');
  }

  async ping() {
    return this.request('GET', '/api/proxy/ping');
  }

  async verifyLicense(licenseKey, hwid) {
    const targetHwid = hwid || getMachineHwid();
    return this.request('POST', '/api/licenses/validate', {
      license_key: licenseKey.trim(),
      hwid: targetHwid,
    });
  }

  async createLicense(days = 30, maxDevices = 1) {
    return this.request('POST', '/api/licenses', {
      days,
      max_devices: maxDevices,
    });
  }

  async revokeLicense(licenseKey, reason = '') {
    return this.request('POST', '/api/licenses/revoke', {
      license_key: licenseKey.trim(),
      reason,
    });
  }

  async addBlacklist(type, target, reason = '') {
    return this.request('POST', '/api/security/blacklist', {
      type,
      target,
      reason,
    });
  }

  async removeBlacklist(type, target) {
    return this.request('POST', '/api/security/blacklist/remove', {
      type,
      target,
    });
  }

  async registerUser(username, password, role = 'user') {
    return this.request('POST', '/api/users/register', {
      username,
      password,
      role,
    });
  }

  async loginUser(username, password) {
    return this.request('POST', '/api/users/login', {
      username,
      password,
    });
  }

  async putDoc(collection, id, payload) {
    return this.request('POST', '/api/docs', {
      action: 'put',
      collection,
      id,
      payload,
    });
  }

  async getDoc(collection, id) {
    return this.request('POST', '/api/docs', {
      action: 'get',
      collection,
      id,
    });
  }
}