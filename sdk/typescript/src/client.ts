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
  AnonymousCredential,
  PedersenCommitmentPoint,
  ZKPParamsResponse,
  ZKPIssueResponse,
  ZKPProof,
  ZKPStatusResponse,
  ZKPVerificationResult,
  ZKPVerifyResponse,
  SSOStatusSummary,
  SessionTokenIntrospectResult,
  SCIMListUsersResult,
  PQCHybridSignature,
  PQCVerificationResult,
  PQCStatusSummary,
  AnomalyObservation,
  AnomalyRiskScore,
  AnomalyIncidentGraph,
  AnomalyTelemetrySummary,
  EnclaveAttestationResult,
  EnclaveHandshakeResponse,
  EnclaveEncryptedMessage,
  EnclaveTelemetry,
} from './types.js';

export { BrokerError, AuthenticationError, LicenseValidationError, RateLimitError } from './errors.js';
import { BrokerError, AuthenticationError, LicenseValidationError, RateLimitError } from './errors.js';

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

  /**
   * Fetches the public elliptic curve parameters and issuer public key.
   */
  public async getZKPParams(): Promise<ZKPParamsResponse> {
    return this.request<ZKPParamsResponse>('GET', '/api/zkp/params');
  }

  /**
   * Issues an issuer-signed anonymous credential for an authenticated license.
   */
  public async issueAnonymousCredential(params: {
    licenseKey: string;
    hwid?: string;
    hwidCommitment?: PedersenCommitmentPoint;
    tier?: string;
    validDays?: number;
    scope?: string;
  }): Promise<ZKPIssueResponse> {
    const hwid = params.hwid || getMachineHwid();
    return this.request<ZKPIssueResponse>('POST', '/api/zkp/credential/issue', {
      license_key: params.licenseKey,
      hwid,
      hwid_commitment: params.hwidCommitment,
      tier: params.tier || 'pro',
      valid_days: params.validDays || 30,
      scope: params.scope || 'production',
      tenant_id: this.tenantId || 'default',
    });
  }

  /**
   * Submits a zero-knowledge presentation proof for privacy-preserving entitlement access.
   */
  public async verifyZKPProof(
    proof: ZKPProof,
    requiredTier: string = 'free',
    epoch?: number
  ): Promise<ZKPVerifyResponse> {
    return this.request<ZKPVerifyResponse>('POST', '/api/zkp/verify', {
      proof,
      required_tier: requiredTier,
      epoch: epoch || Math.floor(Date.now() / 3600000),
    });
  }

  public async getZKPStatus(): Promise<ZKPStatusResponse['zkp']> {
    return (await this.request<ZKPStatusResponse>('GET', '/api/zkp/status')).zkp;
  }

  public async getSSOStatus(): Promise<SSOStatusSummary> {
    return this.request<SSOStatusSummary>('GET', '/api/sso/status');
  }

  /**
   * Validates an ephemeral session token and checks permissions.
   */
  public async introspectSessionToken(token: string, requiredScope?: string): Promise<SessionTokenIntrospectResult> {
    return this.request<SessionTokenIntrospectResult>('POST', '/api/sso/token/introspect', {
      token,
      required_scope: requiredScope,
    });
  }

  /**
   * Queries SCIM 2.0 directory users list with pagination.
   */
  public async listSCIMUsers(startIndex: number = 1, count: number = 50): Promise<SCIMListUsersResult> {
    return this.request<SCIMListUsersResult>('GET', `/scim/v2/Users?startIndex=${startIndex}&count=${count}`);
  }

  /**
   * Retrieves post-quantum cryptography parameters and active key info.
   */
  public async getPQCParams(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/pqc/params');
  }

  /**
   * Retrieves public keys for client-side lattice signature verification.
   */
  public async getPQCPublicKeys(): Promise<Array<Record<string, unknown>>> {
    const res = await this.request<{ status: string; count: number; keys: Array<Record<string, unknown>> }>('GET', '/api/pqc/keys');
    return res.keys || [];
  }

  /**
   * Issues a quantum-resistant hybrid signature over a payload for an authenticated license.
   */
  public async signPQCLicense(licenseKey: string, payload: string, hwid?: string): Promise<PQCHybridSignature> {
    const machineHwid = hwid || (await getMachineHwid());
    const res = await this.request<{ status: string; signature: PQCHybridSignature }>('POST', '/api/pqc/sign', {
      license_key: licenseKey,
      hwid: machineHwid,
      payload,
    });
    return res.signature;
  }

  /**
   * Verifies a dual classical and post-quantum lattice signature.
   */
  public async verifyPQCSignature(payload: string, signature: PQCHybridSignature): Promise<PQCVerificationResult> {
    const res = await this.request<{ status: string; result: PQCVerificationResult }>('POST', '/api/pqc/verify', {
      payload,
      signature,
    });
    return res.result;
  }

  /**
   * Requests an administrative PQC key rotation with grace window.
   */
  public async rotatePQCKey(algo?: string, graceDays: number = 7, reason: string = 'Routine rotation'): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/pqc/rotate', {
      algorithm: algo,
      grace_days: graceDays,
      reason,
    });
  }

  /**
   * Revokes a compromised PQC key by ID.
   */
  public async revokePQCKey(keyId: string, reason: string = 'Administrative revocation'): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/pqc/revoke', {
      key_id: keyId,
      reason,
    });
  }

  /**
   * Retrieves operational telemetry for the PQC engine.
   */
  public async getPQCStatus(): Promise<PQCStatusSummary> {
    const res = await this.request<{ status: string; pqc: PQCStatusSummary }>('GET', '/api/pqc/status');
    return res.pqc;
  }

  /**
   * Submits heartbeat or telemetry observation to behavioral anomaly detection engine.
   */
  public async recordAnomalyObservation(observation: AnomalyObservation): Promise<AnomalyRiskScore> {
    const hwid = observation.hwid || (await getMachineHwid());
    const res = await this.request<{ status: string; risk_score: AnomalyRiskScore }>('POST', '/api/anomaly/record', {
      ...observation,
      hwid,
    });
    return res.risk_score;
  }

  /**
   * Retrieves current adaptive risk score and factors for an entity.
   */
  public async getAnomalyRiskScore(licenseKey?: string, hwid?: string): Promise<AnomalyRiskScore> {
    const machineHwid = hwid || (!licenseKey ? await getMachineHwid() : '');
    const query = new URLSearchParams();
    if (licenseKey) query.set('license_key', licenseKey);
    if (machineHwid) query.set('hwid', machineHwid);
    return this.request<AnomalyRiskScore>('GET', `/api/anomaly/score?${query.toString()}`);
  }

  /**
   * Requests an escalation challenge token for an entity.
   */
  public async issueAnomalyChallenge(licenseKey?: string, hwid?: string): Promise<{ token: string; riskScore: AnomalyRiskScore }> {
    const machineHwid = hwid || (await getMachineHwid());
    const res = await this.request<{ status: string; challenge_token: string; risk_score: AnomalyRiskScore }>('POST', '/api/anomaly/challenge/issue', {
      license_key: licenseKey,
      hwid: machineHwid,
    });
    return { token: res.challenge_token, riskScore: res.risk_score };
  }

  /**
   * Submits challenge response token to clear escalation penalties.
   */
  public async verifyAnomalyChallenge(challengeToken: string): Promise<{ valid: boolean; riskScore: AnomalyRiskScore }> {
    const res = await this.request<{ status: string; valid: boolean; risk_score: AnomalyRiskScore }>('POST', '/api/anomaly/challenge/verify', {
      challenge_token: challengeToken,
    });
    return { valid: res.valid, riskScore: res.risk_score };
  }

  /**
   * Exports real-time topological incident graph for enterprise SIEM ingestion.
   */
  public async exportIncidentGraph(minScore?: number, limit?: number): Promise<AnomalyIncidentGraph> {
    const query = new URLSearchParams();
    if (minScore !== undefined) query.set('min_score', minScore.toString());
    if (limit !== undefined) query.set('limit', limit.toString());
    return this.request<AnomalyIncidentGraph>('GET', `/api/anomaly/graph?${query.toString()}`);
  }

  /**
   * Queries behavioral anomaly operational telemetry metrics.
   */
  public async getAnomalyStatus(): Promise<AnomalyTelemetrySummary> {
    return this.request<AnomalyTelemetrySummary>('GET', '/api/anomaly/status');
  }

  /**
   * Requests a single-use cryptographic challenge nonce for enclave attestation.
   */
  public async requestEnclaveChallenge(): Promise<string> {
    const res = await this.request<{ challenge: string; expires_in: number }>('POST', '/api/enclave/challenge');
    return res.challenge;
  }

  /**
   * Attests an Intel SGX or AMD SEV-SNP attestation quote against security policies.
   */
  public async attestEnclaveQuote(params: {
    platform: 'intel_sgx' | 'amd_sev_snp';
    quoteHex: string;
    nonce: string;
    policyId?: string;
  }): Promise<EnclaveAttestationResult> {
    const res = await this.request<{ valid: boolean; attestation: EnclaveAttestationResult }>('POST', '/api/enclave/attest', {
      platform: params.platform,
      quote: params.quoteHex,
      nonce: params.nonce,
      policy_id: params.policyId,
    });
    return res.attestation;
  }

  /**
   * Performs an enclave ECDH handshake and establishes an end-to-end encrypted session tunnel.
   */
  public async establishEnclaveTunnel(params: {
    platform: 'intel_sgx' | 'amd_sev_snp';
    quoteHex: string;
    nonce: string;
    clientPublicKey: string;
    policyId?: string;
  }): Promise<EnclaveHandshakeResponse> {
    return this.request<EnclaveHandshakeResponse>('POST', '/api/enclave/tunnel/handshake', {
      platform: params.platform,
      quote: params.quoteHex,
      nonce: params.nonce,
      policy_id: params.policyId,
      client_public_key: params.clientPublicKey,
    });
  }

  /**
   * Evaluates an encrypted license query inside the zero-plaintext confidential computing enclave tunnel.
   */
  public async evaluateEnclaveLicense(msg: EnclaveEncryptedMessage): Promise<EnclaveEncryptedMessage> {
    return this.request<EnclaveEncryptedMessage>('POST', '/api/enclave/tunnel/evaluate', {
      session_id: msg.session_id,
      sequence: msg.sequence,
      nonce: msg.nonce,
      payload: msg.payload,
    });
  }

  /**
   * Queries confidential computing operational telemetry and active policies.
   */
  public async getEnclaveStatus(): Promise<{ telemetry: EnclaveTelemetry; policies: any[] }> {
    return this.request<{ telemetry: EnclaveTelemetry; policies: any[] }>('GET', '/api/enclave/status');
  }
}
