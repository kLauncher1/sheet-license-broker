import { createHash, createHmac, randomBytes } from 'node:crypto';
import { getMachineHwid } from './hwid.ts';
import type {
  AttestationChallengeResponse,
  AttestationVerifyResponse,
  AuditExportResponse,
  BrokerClientOptions,
  ClusterPeer,
  ClusterPeersResponse,
  ClusterStatusResponse,
  DocumentResponse,
  EncryptedAuditBundle,
  FeatureCheckResponse,
  HealthResponse,
  LicenseRecord,
  LicenseValidationResponse,
  StreamClientInfo,
  StreamClientsResponse,
  StreamKillResponse,
  StreamTelemetryResponse,
  TelemetryReport,
  TelemetryResponse,
  UsageRecord,
  UsageRecordResponse,
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

  /**
   * Checks whether a feature entitlement is enabled for a license key.
   */
  public async isFeatureEnabled(licenseKey: string, feature: string): Promise<boolean> {
    const res = await this.request<FeatureCheckResponse>('POST', '/api/features/check', {
      license_key: licenseKey.trim(),
      feature: feature.trim(),
    });
    return Boolean(res.enabled);
  }

  /**
   * Reports resource consumption units for a license key with quota check.
   */
  public async recordUsage(
    licenseKey: string,
    metric: string,
    units: number = 1,
    limit: number = 0,
    period: string = ''
  ): Promise<UsageRecordResponse> {
    const payload: Record<string, unknown> = {
      license_key: licenseKey.trim(),
      metric: metric.trim(),
      units,
      limit,
    };
    if (period) {
      payload.period = period.trim();
    }
    return this.request<UsageRecordResponse>('POST', '/api/usage/record', payload);
  }

  /**
   * Retrieves consumption records for all metered resources of a license key.
   */
  public async getUsage(licenseKey: string): Promise<UsageRecord[]> {
    const quoted = encodeURIComponent(licenseKey.trim());
    const res = await this.request<{ status: string; records: UsageRecord[] }>(
      'GET',
      `/api/usage/stats?license_key=${quoted}`
    );
    return res.records || [];
  }

  /**
   * Obtains a fresh single-use random nonce challenge for TPM/enclave binding.
   */
  public async requestAttestationChallenge(
    licenseKey: string,
    hwid?: string
  ): Promise<AttestationChallengeResponse> {
    const targetHwid = hwid || getMachineHwid();
    return this.request<AttestationChallengeResponse>('POST', '/api/attestation/challenge', {
      license_key: licenseKey.trim(),
      hwid: targetHwid.trim(),
    });
  }

  /**
   * Submits a signed TPM 2.0 PCR quote to attest hardware platform integrity.
   */
  public async verifyTPMAttestation(
    licenseKey: string,
    challengeId: string,
    quoteData: Record<string, unknown>,
    hwid?: string
  ): Promise<AttestationVerifyResponse> {
    const targetHwid = hwid || getMachineHwid();
    return this.request<AttestationVerifyResponse>('POST', '/api/attestation/verify', {
      license_key: licenseKey.trim(),
      hwid: targetHwid.trim(),
      challenge_id: challengeId.trim(),
      attestation_type: 'tpm2',
      tpm_quote: quoteData,
    });
  }

  /**
   * Transmits anti-debugging and memory integrity telemetry to broker.
   */
  public async reportTelemetry(
    licenseKey: string,
    report: TelemetryReport,
    hwid?: string
  ): Promise<TelemetryResponse> {
    const targetHwid = hwid || getMachineHwid();
    return this.request<TelemetryResponse>('POST', '/api/attestation/telemetry', {
      license_key: licenseKey.trim(),
      hwid: targetHwid.trim(),
      report,
    });
  }

  /**
   * Requests an encrypted audit bundle for enterprise compliance auditing pipelines.
   */
  public async exportAuditToken(
    secretKey?: string,
    limit: number = 500
  ): Promise<EncryptedAuditBundle> {
    const payload: Record<string, unknown> = { limit };
    if (secretKey) {
      payload.secret_key = secretKey;
    }
    const res = await this.request<AuditExportResponse>('POST', '/api/security/audit/export', payload);
    return res.bundle;
  }

  /**
   * Queries the broker's distributed Raft role, quorum health, and cluster topology.
   */
  public async getClusterStatus(): Promise<ClusterStatusResponse> {
    return this.request<ClusterStatusResponse>('GET', '/api/consensus/status');
  }

  /**
   * Retrieves active peer nodes in the consensus mesh.
   */
  public async getClusterPeers(): Promise<ClusterPeer[]> {
    const res = await this.request<ClusterPeersResponse>('GET', '/api/consensus/peers');
    return res.peers || [];
  }

  /**
   * Queries active WebSocket telemetry client sessions.
   */
  public async getStreamClients(): Promise<StreamClientInfo[]> {
    const res = await this.request<StreamClientsResponse>('GET', '/api/stream/clients');
    return res.clients || [];
  }

  /**
   * Dispatches an instantaneous remote kill-switch directive to targeted clients.
   */
  public async sendKillSwitch(
    target: string,
    reason: string = 'Administrative remote termination directive',
    immediate: boolean = true
  ): Promise<StreamKillResponse> {
    return this.request<StreamKillResponse>('POST', '/api/stream/kill', {
      target,
      reason,
      immediate,
    });
  }

  /**
   * Queries aggregate streaming telemetry and active client metrics.
   */
  public async getStreamTelemetry(): Promise<StreamTelemetryResponse['telemetry']> {
    const res = await this.request<StreamTelemetryResponse>('GET', '/api/stream/telemetry');
    return res.telemetry;
  }
}


