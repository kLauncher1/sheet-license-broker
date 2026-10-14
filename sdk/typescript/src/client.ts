import { createHash, createHmac, randomBytes } from 'node:crypto';
import { getMachineHwid } from './hwid.ts';
import type {
  BrokerClientOptions,
  DocumentResponse,
  HealthResponse,
  LicenseRecord,
  LicenseValidationResponse,
  UserAuthResponse,
} from './types.js';

export class BrokerError extends Error {
  public statusCode?: number;
  public details?: Record<string, unknown>;

  constructor(message: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message);
    this.name = 'BrokerError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

export class AuthenticationError extends BrokerError {
  constructor(message: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message, statusCode, details);
    this.name = 'AuthenticationError';
  }
}

export class LicenseValidationError extends BrokerError {
  constructor(message: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message, statusCode, details);
    this.name = 'LicenseValidationError';
  }
}

export class SheetLicenseClient {
  private readonly baseUrl: string;
  private readonly secretKey?: string;
  private readonly tenantId?: string;
  private readonly timeoutMs: number;

  constructor(options: BrokerClientOptions = {}) {
    this.baseUrl = (options.baseUrl || 'http://127.0.0.1:9082').replace(/\/+$/, '');
    this.secretKey = options.secretKey;
    this.tenantId = options.tenantId;
    this.timeoutMs = options.timeoutMs || 10000;
  }

  private computeBodyHash(body: string): string {
    return createHash('sha256').update(body, 'utf8').digest('hex');
  }

  private buildCanonicalString(method: string, path: string, timestamp: number, nonce: string, body: string): string {
    const bHash = this.computeBodyHash(body);
    return `${method.toUpperCase().trim()}\n${path.trim()}\n${timestamp}\n${nonce}\n${bHash}`;
  }

  private sign(method: string, path: string, timestamp: number, nonce: string, body: string): string {
    if (!this.secretKey) return '';
    const canonical = this.buildCanonicalString(method, path, timestamp, nonce, body);
    return createHmac('sha256', this.secretKey).update(canonical, 'utf8').digest('hex');
  }

  private async request<T>(method: string, path: string, payload?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const bodyStr = payload !== undefined ? JSON.stringify(payload) : '';

    const headers: Record<string, string> = {
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
      let data: any = {};
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

      return data as T;
    } catch (err: any) {
      if (err instanceof BrokerError) throw err;
      if (err.name === 'AbortError') {
        throw new BrokerError(`Request timed out after ${this.timeoutMs}ms`);
      }
      throw new BrokerError(`Network failure contacting broker: ${err.message}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Queries broker health status.
   */
  public async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>('GET', '/health');
  }

  /**
   * Performs an end-to-end ping check with the underlying Google Apps Script backend.
   */
  public async ping(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/proxy/ping');
  }

  /**
   * Validates a license key for the machine hardware ID.
   * If hwid is omitted, it is automatically resolved from the local system.
   */
  public async verifyLicense(licenseKey: string, hwid?: string): Promise<LicenseValidationResponse> {
    const targetHwid = hwid || getMachineHwid();
    return this.request<LicenseValidationResponse>('POST', '/api/licenses/validate', {
      license_key: licenseKey.trim(),
      hwid: targetHwid,
    });
  }

  /**
   * Issues a new license key with the requested duration in days.
   */
  public async createLicense(days: number = 30, maxDevices: number = 1): Promise<LicenseRecord> {
    return this.request<LicenseRecord>('POST', '/api/licenses', {
      days,
      max_devices: maxDevices,
    });
  }

  /**
   * Instantly revokes an active license key.
   */
  public async revokeLicense(licenseKey: string, reason: string = ''): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/licenses/revoke', {
      license_key: licenseKey.trim(),
      reason,
    });
  }

  /**
   * Adds a device HWID or license key to the blacklist.
   */
  public async addBlacklist(type: 'device' | 'license', target: string, reason: string = ''): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/security/blacklist', {
      type,
      target,
      reason,
    });
  }

  /**
   * Removes a device HWID or license key from the blacklist.
   */
  public async removeBlacklist(type: 'device' | 'license', target: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/security/blacklist/remove', {
      type,
      target,
    });
  }

  /**
   * Registers a user account with salted password hashing.
   */
  public async registerUser(username: string, password: string, role: string = 'user'): Promise<UserAuthResponse> {
    return this.request<UserAuthResponse>('POST', '/api/users/register', {
      username,
      password,
      role,
    });
  }

  /**
   * Authenticates user credentials.
   */
  public async loginUser(username: string, password: string): Promise<UserAuthResponse> {
    return this.request<UserAuthResponse>('POST', '/api/users/login', {
      username,
      password,
    });
  }

  /**
   * Writes a JSON document into the NoSQL KV store.
   */
  public async putDoc(collection: string, id: string, payload: Record<string, unknown>): Promise<DocumentResponse> {
    return this.request<DocumentResponse>('POST', '/api/docs', {
      action: 'put',
      collection,
      id,
      payload,
    });
  }

  /**
   * Retrieves a JSON document by ID from the NoSQL KV store.
   */
  public async getDoc(collection: string, id: string): Promise<DocumentResponse> {
    return this.request<DocumentResponse>('POST', '/api/docs', {
      action: 'get',
      collection,
      id,
    });
  }
}
