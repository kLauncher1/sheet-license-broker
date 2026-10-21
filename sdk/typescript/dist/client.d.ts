import type { AttestationChallengeResponse, AttestationVerifyResponse, BrokerClientOptions, ClusterPeer, ClusterStatusResponse, DocumentResponse, EncryptedAuditBundle, HealthResponse, LicenseRecord, LicenseValidationResponse, StreamClientInfo, StreamKillResponse, StreamTelemetryResponse, TelemetryReport, TelemetryResponse, UsageRecord, UsageRecordResponse, UserAuthResponse, PedersenCommitmentPoint, ZKPParamsResponse, ZKPIssueResponse, ZKPProof, ZKPStatusResponse, ZKPVerifyResponse, SSOStatusSummary, SessionTokenIntrospectResult, SCIMListUsersResult, PQCHybridSignature, PQCVerificationResult, PQCStatusSummary, AnomalyObservation, AnomalyRiskScore, AnomalyIncidentGraph, AnomalyTelemetrySummary, EnclaveAttestationResult, EnclaveHandshakeResponse, EnclaveEncryptedMessage, EnclaveTelemetry, AnycastRoutingDecision, EdgeCacheTelemetry, AnycastStatusResponse, MarketplaceTransaction, MarketplaceStatus, MarketplaceSimulateRequest, MarketplaceSimulateResponse, MarketplaceTransactionFilter, AirgapDongleToken, AirgapIssueRequest, AirgapIssueResponse, AirgapVerifyRequest, AirgapVerifyResponse, AirgapActivationRequest, AirgapActivationResponse, AirgapRollbackState, AirgapUnlockRequest, AirgapStatus, ZeroTrustPeerIdentity, ZeroTrustEnrollRequest, ZeroTrustEnrollResponse, ZeroTrustHSMSlotInfo, ZeroTrustStatus, ZeroTrustVerifyResponse } from './types.js';
export { BrokerError, AuthenticationError, LicenseValidationError, RateLimitError } from './errors.js';
export declare class SheetLicenseClient {
    private readonly baseUrl;
    private readonly secretKey?;
    private readonly tenantId?;
    private readonly timeoutMs;
    constructor(options?: BrokerClientOptions);
    private computeBodyHash;
    private buildCanonicalString;
    private sign;
    private request;
    /**
     * Queries broker health status.
     */
    health(): Promise<HealthResponse>;
    /**
     * Performs an end-to-end ping check with the underlying Google Apps Script backend.
     */
    ping(): Promise<Record<string, unknown>>;
    /**
     * Validates a license key for the machine hardware ID.
     * If hwid is omitted, it is automatically resolved from the local system.
     */
    verifyLicense(licenseKey: string, hwid?: string): Promise<LicenseValidationResponse>;
    /**
     * Issues a new license key with the requested duration in days.
     */
    createLicense(days?: number, maxDevices?: number): Promise<LicenseRecord>;
    /**
     * Instantly revokes an active license key.
     */
    revokeLicense(licenseKey: string, reason?: string): Promise<Record<string, unknown>>;
    /**
     * Adds a device HWID or license key to the blacklist.
     */
    addBlacklist(type: 'device' | 'license', target: string, reason?: string): Promise<Record<string, unknown>>;
    /**
     * Removes a device HWID or license key from the blacklist.
     */
    removeBlacklist(type: 'device' | 'license', target: string): Promise<Record<string, unknown>>;
    /**
     * Registers a user account with salted password hashing.
     */
    registerUser(username: string, password: string, role?: string): Promise<UserAuthResponse>;
    /**
     * Authenticates user credentials.
     */
    loginUser(username: string, password: string): Promise<UserAuthResponse>;
    /**
     * Writes a JSON document into the NoSQL KV store.
     */
    putDoc(collection: string, id: string, payload: Record<string, unknown>): Promise<DocumentResponse>;
    /**
     * Retrieves a JSON document by ID from the NoSQL KV store.
     */
    getDoc(collection: string, id: string): Promise<DocumentResponse>;
    /**
     * Checks whether a feature entitlement is enabled for a license key.
     */
    isFeatureEnabled(licenseKey: string, feature: string): Promise<boolean>;
    /**
     * Reports resource consumption units for a license key with quota check.
     */
    recordUsage(licenseKey: string, metric: string, units?: number, limit?: number, period?: string): Promise<UsageRecordResponse>;
    /**
     * Retrieves consumption records for all metered resources of a license key.
     */
    getUsage(licenseKey: string): Promise<UsageRecord[]>;
    /**
     * Obtains a fresh single-use random nonce challenge for TPM/enclave binding.
     */
    requestAttestationChallenge(licenseKey: string, hwid?: string): Promise<AttestationChallengeResponse>;
    /**
     * Submits a signed TPM 2.0 PCR quote to attest hardware platform integrity.
     */
    verifyTPMAttestation(licenseKey: string, challengeId: string, quoteData: Record<string, unknown>, hwid?: string): Promise<AttestationVerifyResponse>;
    /**
     * Transmits anti-debugging and memory integrity telemetry to broker.
     */
    reportTelemetry(licenseKey: string, report: TelemetryReport, hwid?: string): Promise<TelemetryResponse>;
    /**
     * Requests an encrypted audit bundle for enterprise compliance auditing pipelines.
     */
    exportAuditToken(secretKey?: string, limit?: number): Promise<EncryptedAuditBundle>;
    /**
     * Queries the broker's distributed Raft role, quorum health, and cluster topology.
     */
    getClusterStatus(): Promise<ClusterStatusResponse>;
    /**
     * Retrieves active peer nodes in the consensus mesh.
     */
    getClusterPeers(): Promise<ClusterPeer[]>;
    /**
     * Queries active WebSocket telemetry client sessions.
     */
    getStreamClients(): Promise<StreamClientInfo[]>;
    /**
     * Dispatches an instantaneous remote kill-switch directive to targeted clients.
     */
    sendKillSwitch(target: string, reason?: string, immediate?: boolean): Promise<StreamKillResponse>;
    /**
     * Queries aggregate streaming telemetry and active client metrics.
     */
    getStreamTelemetry(): Promise<StreamTelemetryResponse['telemetry']>;
    /**
     * Fetches the public elliptic curve parameters and issuer public key.
     */
    getZKPParams(): Promise<ZKPParamsResponse>;
    /**
     * Issues an issuer-signed anonymous credential for an authenticated license.
     */
    issueAnonymousCredential(params: {
        licenseKey: string;
        hwid?: string;
        hwidCommitment?: PedersenCommitmentPoint;
        tier?: string;
        validDays?: number;
        scope?: string;
    }): Promise<ZKPIssueResponse>;
    /**
     * Submits a zero-knowledge presentation proof for privacy-preserving entitlement access.
     */
    verifyZKPProof(proof: ZKPProof, requiredTier?: string, epoch?: number): Promise<ZKPVerifyResponse>;
    getZKPStatus(): Promise<ZKPStatusResponse['zkp']>;
    getSSOStatus(): Promise<SSOStatusSummary>;
    /**
     * Validates an ephemeral session token and checks permissions.
     */
    introspectSessionToken(token: string, requiredScope?: string): Promise<SessionTokenIntrospectResult>;
    /**
     * Queries SCIM 2.0 directory users list with pagination.
     */
    listSCIMUsers(startIndex?: number, count?: number): Promise<SCIMListUsersResult>;
    /**
     * Retrieves post-quantum cryptography parameters and active key info.
     */
    getPQCParams(): Promise<Record<string, unknown>>;
    /**
     * Retrieves public keys for client-side lattice signature verification.
     */
    getPQCPublicKeys(): Promise<Array<Record<string, unknown>>>;
    /**
     * Issues a quantum-resistant hybrid signature over a payload for an authenticated license.
     */
    signPQCLicense(licenseKey: string, payload: string, hwid?: string): Promise<PQCHybridSignature>;
    /**
     * Verifies a dual classical and post-quantum lattice signature.
     */
    verifyPQCSignature(payload: string, signature: PQCHybridSignature): Promise<PQCVerificationResult>;
    /**
     * Requests an administrative PQC key rotation with grace window.
     */
    rotatePQCKey(algo?: string, graceDays?: number, reason?: string): Promise<Record<string, unknown>>;
    /**
     * Revokes a compromised PQC key by ID.
     */
    revokePQCKey(keyId: string, reason?: string): Promise<Record<string, unknown>>;
    /**
     * Retrieves operational telemetry for the PQC engine.
     */
    getPQCStatus(): Promise<PQCStatusSummary>;
    /**
     * Submits heartbeat or telemetry observation to behavioral anomaly detection engine.
     */
    recordAnomalyObservation(observation: AnomalyObservation): Promise<AnomalyRiskScore>;
    /**
     * Retrieves current adaptive risk score and factors for an entity.
     */
    getAnomalyRiskScore(licenseKey?: string, hwid?: string): Promise<AnomalyRiskScore>;
    /**
     * Requests an escalation challenge token for an entity.
     */
    issueAnomalyChallenge(licenseKey?: string, hwid?: string): Promise<{
        token: string;
        riskScore: AnomalyRiskScore;
    }>;
    /**
     * Submits challenge response token to clear escalation penalties.
     */
    verifyAnomalyChallenge(challengeToken: string): Promise<{
        valid: boolean;
        riskScore: AnomalyRiskScore;
    }>;
    /**
     * Exports real-time topological incident graph for enterprise SIEM ingestion.
     */
    exportIncidentGraph(minScore?: number, limit?: number): Promise<AnomalyIncidentGraph>;
    /**
     * Queries behavioral anomaly operational telemetry metrics.
     */
    getAnomalyStatus(): Promise<AnomalyTelemetrySummary>;
    /**
     * Requests a single-use cryptographic challenge nonce for enclave attestation.
     */
    requestEnclaveChallenge(): Promise<string>;
    /**
     * Attests an Intel SGX or AMD SEV-SNP attestation quote against security policies.
     */
    attestEnclaveQuote(params: {
        platform: 'intel_sgx' | 'amd_sev_snp';
        quoteHex: string;
        nonce: string;
        policyId?: string;
    }): Promise<EnclaveAttestationResult>;
    /**
     * Performs an enclave ECDH handshake and establishes an end-to-end encrypted session tunnel.
     */
    establishEnclaveTunnel(params: {
        platform: 'intel_sgx' | 'amd_sev_snp';
        quoteHex: string;
        nonce: string;
        clientPublicKey: string;
        policyId?: string;
    }): Promise<EnclaveHandshakeResponse>;
    /**
     * Evaluates an encrypted license query inside the zero-plaintext confidential computing enclave tunnel.
     */
    evaluateEnclaveLicense(msg: EnclaveEncryptedMessage): Promise<EnclaveEncryptedMessage>;
    /**
     * Queries confidential computing operational telemetry and active policies.
     */
    getEnclaveStatus(): Promise<{
        telemetry: EnclaveTelemetry;
        policies: any[];
    }>;
    /**
     * Queries the nearest edge Anycast Point of Presence based on coordinates, country, or region.
     */
    getAnycastRoute(options?: {
        lat?: number;
        lon?: number;
        country?: string;
        region?: string;
    }): Promise<AnycastRoutingDecision>;
    /**
     * Reports an edge latency and packet loss probe to the Anycast routing engine.
     */
    reportAnycastProbe(probe: {
        targetPopId: string;
        rttLatencyMs: number;
        sourceRegion?: string;
        sourceIp?: string;
        packetLoss?: number;
        jitterMs?: number;
    }): Promise<Record<string, unknown>>;
    /**
     * Retrieves overall Anycast status including POP health, partition isolation, and cache metrics.
     */
    getAnycastStatus(): Promise<AnycastStatusResponse>;
    /**
     * Retrieves microsecond-level L1 edge cache performance telemetry.
     */
    getEdgeCacheStats(): Promise<EdgeCacheTelemetry>;
    /**
     * Executes a fast sub-millisecond license check against the edge L1 cache.
     */
    fastVerifyLicense(licenseKey: string, hwid?: string): Promise<LicenseValidationResponse>;
    /**
     * Retrieves diagnostic telemetry from the automated marketplace webhooks bridge.
     */
    getMarketplaceStatus(): Promise<MarketplaceStatus>;
    /**
     * Sends a synthetic purchase or cancellation webhook to test automated provisioning and revocation.
     */
    simulateMarketplaceWebhook(req: MarketplaceSimulateRequest): Promise<MarketplaceSimulateResponse>;
    /**
     * Retrieves the transaction audit ledger of processed marketplace webhook events.
     */
    listMarketplaceTransactions(filter?: MarketplaceTransactionFilter): Promise<MarketplaceTransaction[]>;
    /**
     * Retrieves operational telemetry for the air-gapped license vault.
     */
    getAirgapStatus(): Promise<AirgapStatus>;
    /**
     * Issues a cryptographically signed offline dongle token.
     */
    issueAirgapDongleToken(req: AirgapIssueRequest): Promise<AirgapIssueResponse>;
    /**
     * Verifies an offline dongle token against the broker's master key and monotonic clock.
     */
    verifyAirgapDongleToken(token: string, hwid?: string, timestamp?: number): Promise<AirgapVerifyResponse>;
    /**
     * Submits an offline machine challenge and returns an activation response with QR payload.
     */
    requestAirgapActivation(req: AirgapActivationRequest): Promise<AirgapActivationResponse>;
    /**
     * Consumes an air-gap QR payload and returns the fulfilled offline DongleToken.
     */
    fulfillAirgapActivation(qrPayload: string): Promise<AirgapDongleToken>;
    /**
     * Queries the monotonic clock and rollback tamper state for an HWID.
     */
    getAirgapRollbackState(hwid?: string): Promise<AirgapRollbackState>;
    /**
     * Unlocks a tripped airgap vault using an administrative recovery token.
     */
    unlockAirgapRollback(req: AirgapUnlockRequest): Promise<AirgapRollbackState>;
    /**
     * Retrieves high-level operational status of the Zero-Trust mesh and internal CA.
     */
    getZeroTrustStatus(): Promise<ZeroTrustStatus>;
    /**
     * Lists all known enrolled Zero-Trust mesh peer nodes.
     */
    listZeroTrustPeers(): Promise<ZeroTrustPeerIdentity[]>;
    /**
     * Enrolls a new peer node and issues an mTLS certificate signed by the internal CA.
     */
    enrollZeroTrustPeer(req: ZeroTrustEnrollRequest): Promise<ZeroTrustEnrollResponse>;
    /**
     * Revokes a peer node certificate and marks its status as REVOKED in the internal CRL.
     */
    revokeZeroTrustPeer(nodeId: string, reason?: string): Promise<{ status: string; node_id: string; revoked: boolean; reason: string }>;
    /**
     * Rotates the internal Root CA while maintaining dual-trust continuity.
     */
    rotateZeroTrustCA(validityDays?: number): Promise<{ status: string; message: string; root_fingerprint: string; ca_expires_at: string }>;
    /**
     * Queries hardware-backed key slot capabilities and operation counters.
     */
    getZeroTrustHSMStatus(): Promise<{ hsm_enabled: boolean; slots_count: number; slots: ZeroTrustHSMSlotInfo[] }>;
    /**
     * Cryptographically verifies whether a given peer identity is actively authorized.
     */
    verifyZeroTrustPeer(peer: Partial<ZeroTrustPeerIdentity>): Promise<ZeroTrustVerifyResponse>;
}
//# sourceMappingURL=client.d.ts.map