import { createHash, createHmac, randomBytes } from 'node:crypto';
import { getMachineHwid } from './hwid.js';
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
  AnycastPOP,
  AnycastRoutingDecision,
  EdgeCacheTelemetry,
  AnycastStatusResponse,
  MarketplaceTransaction,
  MarketplaceStatus,
  MarketplaceSimulateRequest,
  MarketplaceSimulateResponse,
  MarketplaceTransactionFilter,
  AirgapDongleToken,
  AirgapIssueRequest,
  AirgapIssueResponse,
  AirgapVerifyRequest,
  AirgapVerifyResponse,
  AirgapActivationRequest,
  AirgapActivationResponse,
  AirgapRollbackState,
  AirgapUnlockRequest,
  AirgapStatus,
  ZeroTrustPeerRole,
  ZeroTrustPeerStatus,
  ZeroTrustPeerIdentity,
  ZeroTrustEnrollRequest,
  ZeroTrustEnrollResponse,
  ZeroTrustHSMSlotInfo,
  ZeroTrustStatus,
  ZeroTrustVerifyResponse,
  HealingStatus,
  HealingConsumeResponse,
  HealingTicket,
  HealingResumeResponse,
  HealingBorrowResponse,
  HealingRebalanceResponse,
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
        if (res.status === 429) {
          const retryHeader = res.headers.get('retry-after');
          const retryVal = retryHeader ? parseInt(retryHeader, 10) : (Number(data.retry_after) || 0);
          throw new RateLimitError(`Rate limit exceeded: ${errMsg}`, res.status, data, retryVal);
        }
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

  /**
   * Queries the nearest edge Anycast Point of Presence based on coordinates, country, or region.
   */
  public async getAnycastRoute(options?: {
    lat?: number;
    lon?: number;
    country?: string;
    region?: string;
  }): Promise<AnycastRoutingDecision> {
    const params = new URLSearchParams();
    if (options?.lat !== undefined) params.set('lat', String(options.lat));
    if (options?.lon !== undefined) params.set('lon', String(options.lon));
    if (options?.country) params.set('country', options.country);
    if (options?.region) params.set('region', options.region);

    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request<AnycastRoutingDecision>('GET', `/api/anycast/route${query}`);
  }

  /**
   * Reports an edge latency and packet loss probe to the Anycast routing engine.
   */
  public async reportAnycastProbe(probe: {
    targetPopId: string;
    rttLatencyMs: number;
    sourceRegion?: string;
    sourceIp?: string;
    packetLoss?: number;
    jitterMs?: number;
  }): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('POST', '/api/anycast/probe', {
      target_pop_id: probe.targetPopId,
      rtt_latency_ms: probe.rttLatencyMs,
      source_region: probe.sourceRegion || 'global',
      source_ip: probe.sourceIp || '',
      packet_loss: probe.packetLoss || 0,
      jitter_ms: probe.jitterMs || 0,
    });
  }

  /**
   * Retrieves overall Anycast status including POP health, partition isolation, and cache metrics.
   */
  public async getAnycastStatus(): Promise<AnycastStatusResponse> {
    return this.request<AnycastStatusResponse>('GET', '/api/anycast/status');
  }

  /**
   * Retrieves microsecond-level L1 edge cache performance telemetry.
   */
  public async getEdgeCacheStats(): Promise<EdgeCacheTelemetry> {
    return this.request<EdgeCacheTelemetry>('GET', '/api/anycast/cache/stats');
  }

  /**
   * Executes a fast sub-millisecond license check against the edge L1 cache.
   */
  public async fastVerifyLicense(licenseKey: string, hwid?: string): Promise<LicenseValidationResponse> {
    const machineHwid = hwid || (await getMachineHwid());
    return this.request<LicenseValidationResponse>('POST', '/api/anycast/verify', {
      license_key: licenseKey,
      hwid: machineHwid,
    });
  }

  /**
   * Retrieves diagnostic telemetry from the automated marketplace webhooks bridge.
   */
  public async getMarketplaceStatus(): Promise<MarketplaceStatus> {
    return this.request<MarketplaceStatus>('GET', '/api/marketplace/status');
  }

  /**
   * Sends a synthetic purchase or cancellation webhook to test automated provisioning and revocation.
   */
  public async simulateMarketplaceWebhook(req: MarketplaceSimulateRequest): Promise<MarketplaceSimulateResponse> {
    return this.request<MarketplaceSimulateResponse>('POST', '/api/marketplace/simulate', req);
  }

  /**
   * Retrieves the transaction audit ledger of processed marketplace webhook events.
   */
  public async listMarketplaceTransactions(filter?: MarketplaceTransactionFilter): Promise<MarketplaceTransaction[]> {
    let path = '/api/marketplace/transactions';
    if (filter) {
      const params = new URLSearchParams();
      if (filter.provider) params.set('provider', filter.provider);
      const email = filter.customer_email || filter.email;
      if (email) params.set('customer_email', email);
      if (filter.status) params.set('status', filter.status);
      if (filter.limit && filter.limit > 0) params.set('limit', String(filter.limit));
      const qs = params.toString();
      if (qs) path += `?${qs}`;
    }
    return this.request<MarketplaceTransaction[]>('GET', path);
  }

  /**
   * Retrieves operational telemetry for the air-gapped license vault.
   */
  public async getAirgapStatus(): Promise<AirgapStatus> {
    return this.request<AirgapStatus>('GET', '/api/airgap/status');
  }

  /**
   * Issues a cryptographically signed offline dongle token.
   */
  public async issueAirgapDongleToken(req: AirgapIssueRequest): Promise<AirgapIssueResponse> {
    const hwid = req.hwid || (await getMachineHwid());
    return this.request<AirgapIssueResponse>('POST', '/api/airgap/token/issue', {
      ...req,
      hwid,
    });
  }

  /**
   * Verifies an offline dongle token against the broker's master key and monotonic clock.
   */
  public async verifyAirgapDongleToken(token: string, hwid?: string, timestamp?: number): Promise<AirgapVerifyResponse> {
    const machineHwid = hwid || (await getMachineHwid());
    return this.request<AirgapVerifyResponse>('POST', '/api/airgap/token/verify', {
      token,
      hwid: machineHwid,
      timestamp: timestamp || Math.floor(Date.now() / 1000),
    });
  }

  /**
   * Submits an offline machine challenge and returns an activation response with QR payload.
   */
  public async requestAirgapActivation(req: AirgapActivationRequest): Promise<AirgapActivationResponse> {
    const hwid = req.hwid || (await getMachineHwid());
    const res = await this.request<{ status: string; activation: AirgapActivationResponse }>('POST', '/api/airgap/activate/request', {
      ...req,
      hwid,
    });
    return res.activation;
  }

  /**
   * Consumes an air-gap QR payload and returns the fulfilled offline DongleToken.
   */
  public async fulfillAirgapActivation(qrPayload: string): Promise<AirgapDongleToken> {
    const res = await this.request<{ status: string; token: AirgapDongleToken }>('POST', '/api/airgap/activate/fulfill', {
      qr_payload: qrPayload,
    });
    return res.token;
  }

  /**
   * Queries the monotonic clock and rollback tamper state for an HWID.
   */
  public async getAirgapRollbackState(hwid?: string): Promise<AirgapRollbackState> {
    const machineHwid = hwid || (await getMachineHwid());
    const res = await this.request<{ status: string; state: AirgapRollbackState }>('GET', `/api/airgap/rollback/state?hwid=${encodeURIComponent(machineHwid)}`);
    return res.state;
  }

  /**
   * Unlocks a tripped airgap vault using an administrative recovery token.
   */
  public async unlockAirgapRollback(req: AirgapUnlockRequest): Promise<AirgapRollbackState> {
    const res = await this.request<{ status: string; state: AirgapRollbackState }>('POST', '/api/airgap/rollback/unlock', req);
    return res.state;
  }

  /**
   * Retrieves high-level operational status of the Zero-Trust mesh and internal CA.
   */
  public async getZeroTrustStatus(): Promise<ZeroTrustStatus> {
    return this.request<ZeroTrustStatus>('GET', '/api/zerotrust/status');
  }

  /**
   * Lists all known enrolled Zero-Trust mesh peer nodes.
   */
  public async listZeroTrustPeers(): Promise<ZeroTrustPeerIdentity[]> {
    const res = await this.request<{ peers: ZeroTrustPeerIdentity[] }>('GET', '/api/zerotrust/peers');
    return res.peers;
  }

  /**
   * Enrolls a new peer node and issues an mTLS certificate signed by the internal CA.
   */
  public async enrollZeroTrustPeer(req: ZeroTrustEnrollRequest): Promise<ZeroTrustEnrollResponse> {
    const res = await this.request<{ status: string; enrollment: ZeroTrustEnrollResponse }>('POST', '/api/zerotrust/peers/enroll', req);
    return res.enrollment;
  }

  /**
   * Revokes a peer node certificate and marks its status as REVOKED in the internal CRL.
   */
  public async revokeZeroTrustPeer(nodeId: string, reason?: string): Promise<{ status: string; node_id: string; revoked: boolean; reason: string }> {
    return this.request<{ status: string; node_id: string; revoked: boolean; reason: string }>('POST', '/api/zerotrust/peers/revoke', {
      node_id: nodeId,
      reason: reason || 'Administrative revocation',
    });
  }

  /**
   * Rotates the internal Root CA while maintaining dual-trust continuity.
   */
  public async rotateZeroTrustCA(validityDays?: number): Promise<{ status: string; message: string; root_fingerprint: string; ca_expires_at: string }> {
    return this.request<{ status: string; message: string; root_fingerprint: string; ca_expires_at: string }>('POST', '/api/zerotrust/ca/rotate', {
      validity_days: validityDays || 365,
    });
  }

  /**
   * Queries hardware-backed key slot capabilities and operation counters.
   */
  public async getZeroTrustHSMStatus(): Promise<{ hsm_enabled: boolean; slots_count: number; slots: ZeroTrustHSMSlotInfo[] }> {
    return this.request<{ hsm_enabled: boolean; slots_count: number; slots: ZeroTrustHSMSlotInfo[] }>('GET', '/api/zerotrust/hsm/status');
  }

  /**
   * Cryptographically verifies whether a given peer identity is actively authorized.
   */
  public async verifyZeroTrustPeer(peer: Partial<ZeroTrustPeerIdentity>): Promise<ZeroTrustVerifyResponse> {
    return this.request<ZeroTrustVerifyResponse>('POST', '/api/zerotrust/verify', peer);
  }

  /**
   * Queries autonomous healing status including bucket telemetry, active tunnels, and quota pools.
   */
  public async getHealingStatus(): Promise<HealingStatus> {
    return this.request<HealingStatus>('GET', '/api/healing/status');
  }

  /**
   * Consumes capacity tokens from the real-time auto-scaling token bucket rate limiter.
   */
  public async consumeHealingBucket(tokens: number = 1.0): Promise<HealingConsumeResponse> {
    return this.request<HealingConsumeResponse>('POST', '/api/healing/bucket/consume', { tokens });
  }

  /**
   * Issues a cryptographically signed healing ticket allowing a client to resume an interrupted session.
   */
  public async issueHealingTicket(params: {
    sessionId?: string;
    clientId: string;
    hwid: string;
    tenantId?: string;
    lastAckSeq?: number;
    ttlSeconds?: number;
  }): Promise<HealingTicket> {
    return this.request<HealingTicket>('POST', '/api/healing/tunnel/ticket', {
      session_id: params.sessionId || '',
      client_id: params.clientId,
      hwid: params.hwid,
      tenant_id: params.tenantId || 'default',
      last_ack_seq: params.lastAckSeq || 0,
      ttl_seconds: params.ttlSeconds || 180,
    });
  }

  /**
   * Resumes an interrupted client connection tunnel and retrieves missed state synchronization events.
   */
  public async resumeHealingTunnel(ticket: HealingTicket): Promise<HealingResumeResponse> {
    return this.request<HealingResumeResponse>('POST', '/api/healing/tunnel/resume', ticket);
  }

  /**
   * Requests a dynamic quota borrowing lease between tenant pools.
   */
  public async borrowHealingQuota(params: {
    borrowerTenant: string;
    lenderTenant: string;
    amount: number;
    durationMinutes?: number;
  }): Promise<HealingBorrowResponse> {
    return this.request<HealingBorrowResponse>('POST', '/api/healing/quota/borrow', {
      borrower_tenant: params.borrowerTenant,
      lender_tenant: params.lenderTenant,
      amount: params.amount,
      duration_minutes: params.durationMinutes || 15,
    });
  }

  /**
   * Voluntarily returns a borrowed quota allocation before or upon expiration.
   */
  public async returnHealingQuota(leaseId: string): Promise<{ status: string; lease_id: string }> {
    return this.request<{ status: string; lease_id: string }>('POST', '/api/healing/quota/return', {
      lease_id: leaseId,
    });
  }

  /**
   * Preemptively recalls borrowed quota when lender tenant load surges.
   */
  public async recallHealingQuota(leaseId: string, reason?: string): Promise<{ status: string; lease_id: string }> {
    return this.request<{ status: string; lease_id: string }>('POST', '/api/healing/quota/recall', {
      lease_id: leaseId,
      reason: reason || 'Lender utilization surge',
    });
  }

  /**
   * Triggers an automated distributed quota rebalancing evaluation.
   */
  public async rebalanceHealingQuotas(): Promise<HealingRebalanceResponse> {
    return this.request<HealingRebalanceResponse>('POST', '/api/healing/quota/rebalance', {});
  }
}

