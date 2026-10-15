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

export class RateLimitError extends BrokerError {
  constructor(message, statusCode, details, retryAfter = 0) {
    super(message, statusCode, details);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class SheetLicenseClient {
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || 'http://127.0.0.1:9082').replace(/\/+$/, '');
    this.secretKey = options.secretKey;
    this.tenantId = options.tenantId;
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
      'User-Agent': 'SheetLicenseClient-TS/0.5.0',
    };

    if (this.tenantId) {
      headers['X-Tenant-ID'] = this.tenantId;
    }

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
        if (res.status === 429) {
          const retryHeader = res.headers.get('Retry-After') || '0';
          const retryAfter = parseInt(retryHeader, 10) || 0;
          throw new RateLimitError(`Rate limit exceeded: ${errMsg}`, res.status, data, retryAfter);
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

  async isFeatureEnabled(licenseKey, feature) {
    const res = await this.request('POST', '/api/features/check', {
      license_key: licenseKey.trim(),
      feature: feature.trim(),
    });
    return Boolean(res.enabled);
  }

  async recordUsage(licenseKey, metric, units = 1, limit = 0, period = '') {
    const payload = {
      license_key: licenseKey.trim(),
      metric: metric.trim(),
      units,
      limit,
    };
    if (period) {
      payload.period = period.trim();
    }
    return this.request('POST', '/api/usage/record', payload);
  }

  async getUsage(licenseKey) {
    const quoted = encodeURIComponent(licenseKey.trim());
    const res = await this.request('GET', `/api/usage/stats?license_key=${quoted}`);
    return res.records || [];
  }

  async requestAttestationChallenge(licenseKey, hwid) {
    const targetHwid = hwid || getMachineHwid();
    return this.request('POST', '/api/attestation/challenge', {
      license_key: licenseKey.trim(),
      hwid: targetHwid.trim(),
    });
  }

  async verifyTPMAttestation(licenseKey, challengeId, quoteData, hwid) {
    const targetHwid = hwid || getMachineHwid();
    return this.request('POST', '/api/attestation/verify', {
      license_key: licenseKey.trim(),
      hwid: targetHwid.trim(),
      challenge_id: challengeId.trim(),
      attestation_type: 'tpm2',
      tpm_quote: quoteData,
    });
  }

  async reportTelemetry(licenseKey, report, hwid) {
    const targetHwid = hwid || getMachineHwid();
    return this.request('POST', '/api/attestation/telemetry', {
      license_key: licenseKey.trim(),
      hwid: targetHwid.trim(),
      report,
    });
  }

  async exportAuditToken(secretKey, limit = 500) {
    const payload = { limit };
    if (secretKey) {
      payload.secret_key = secretKey;
    }
    const res = await this.request('POST', '/api/security/audit/export', payload);
    return res.bundle;
  }

  async getClusterStatus() {
    return this.request('GET', '/api/consensus/status');
  }

  async getClusterPeers() {
    const res = await this.request('GET', '/api/consensus/peers');
    return res.peers || [];
  }

  async getStreamClients() {
    const res = await this.request('GET', '/api/stream/clients');
    return res.clients || [];
  }

  async sendKillSwitch(target, reason = 'Administrative remote termination directive', immediate = true) {
    return this.request('POST', '/api/stream/kill', {
      target,
      reason,
      immediate,
    });
  }

  async getStreamTelemetry() {
    const res = await this.request('GET', '/api/stream/telemetry');
    return res.telemetry;
  }

  async getZKPParams() {
    return this.request('GET', '/api/zkp/params');
  }

  async issueAnonymousCredential(params) {
    const hwid = params.hwid || getMachineHwid();
    return this.request('POST', '/api/zkp/credential/issue', {
      license_key: params.licenseKey,
      hwid,
      hwid_commitment: params.hwidCommitment,
      tier: params.tier || 'pro',
      valid_days: params.validDays || 30,
      scope: params.scope || 'production',
      tenant_id: this.tenantId || 'default',
    });
  }

  async verifyZKPProof(proof, requiredTier = 'free', epoch) {
    return this.request('POST', '/api/zkp/verify', {
      proof,
      required_tier: requiredTier,
      epoch: epoch || Math.floor(Date.now() / 3600000),
    });
  }

  async getZKPStatus() {
    const res = await this.request('GET', '/api/zkp/status');
    return res.zkp;
  }

  async getSSOStatus() {
    return this.request('GET', '/api/sso/status');
  }

  async introspectSessionToken(token, requiredScope) {
    return this.request('POST', '/api/sso/token/introspect', {
      token,
      required_scope: requiredScope,
    });
  }

  async listSCIMUsers(startIndex = 1, count = 50) {
    return this.request('GET', `/scim/v2/Users?startIndex=${startIndex}&count=${count}`);
  }
}