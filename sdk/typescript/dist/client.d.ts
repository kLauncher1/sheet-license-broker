import type { AttestationChallengeResponse, AttestationVerifyResponse, BrokerClientOptions, ClusterPeer, ClusterStatusResponse, DocumentResponse, EncryptedAuditBundle, HealthResponse, LicenseRecord, LicenseValidationResponse, StreamClientInfo, StreamKillResponse, StreamTelemetryResponse, TelemetryReport, TelemetryResponse, UsageRecord, UsageRecordResponse, UserAuthResponse, PedersenCommitmentPoint, ZKPParamsResponse, ZKPIssueResponse, ZKPProof, ZKPStatusResponse, ZKPVerifyResponse, SSOStatusSummary, SessionTokenIntrospectResult, SCIMListUsersResult, PQCHybridSignature, PQCVerificationResult, PQCStatusSummary, AnomalyObservation, AnomalyRiskScore, AnomalyIncidentGraph, AnomalyTelemetrySummary, EnclaveAttestationResult, EnclaveAttestationToken, EnclaveTokenVerifyResult, EnclaveIsolatedDecryptionRequest, EnclaveIsolatedDecryptionResult, EnclaveHandshakeResponse, EnclaveEncryptedMessage, EnclaveTelemetry, AnycastRoutingDecision, EdgeCacheTelemetry, AnycastStatusResponse, MarketplaceTransaction, MarketplaceStatus, MarketplaceSimulateRequest, MarketplaceSimulateResponse, MarketplaceTransactionFilter, AirgapDongleToken, AirgapIssueRequest, AirgapIssueResponse, AirgapVerifyResponse, AirgapActivationRequest, AirgapActivationResponse, AirgapRollbackState, AirgapUnlockRequest, AirgapStatus, ZeroTrustPeerIdentity, ZeroTrustEnrollRequest, ZeroTrustEnrollResponse, ZeroTrustHSMSlotInfo, ZeroTrustStatus, ZeroTrustVerifyResponse, HealingStatus, HealingConsumeResponse, HealingTicket, HealingResumeResponse, HealingBorrowResponse, HealingRebalanceResponse, HSMSlotInfo, HSMVaultStatus, HSMKeyDerivationRequest, HSMKeyDerivationResponse, HSMEnvelopeEncryptRequest, HSMEnvelopeEncryptResponse, HSMEnvelopeDecryptRequest, HSMEnvelopeDecryptResponse, HSMSelfTestResult, HSMFIPS140AuditReport, MLKEMStatus, MLKEMPublicKey, MLKEMEncapsulationResult, HybridHandshakeRequest, HybridHandshakeResponse, HybridSessionVerification, TransparencyLogEntry, TransparencyWitnessSignature, TransparencySTH, TransparencyInclusionProof, TransparencyConsistencyProof, TransparencyStatus, DevicePostureReport, PostureVectorScores, QuarantinedDevice, StepUpChallenge, PostureStatus, CloudProvider, MultiCloudRoutingToken, HealthProbeResult, SyncDelta, SyncVoucher, FailoverEvent, MultiCloudStatus } from './types.js';
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
     * Submits an Intel TDX Quote v4 for cryptographic and policy verification.
     */
    verifyTDXQuote(params: {
        quoteHex: string;
        nonce: string;
        policyId?: string;
    }): Promise<EnclaveAttestationResult>;
    /**
     * Requests an immutable signed attestation token binding hardware measurements and SVN.
     */
    issueAttestationToken(params: {
        platform?: 'intel_sgx' | 'amd_sev_snp' | 'intel_tdx';
        measurement: string;
        rtmr0?: string;
        svn: number;
        debug?: boolean;
        nonce: string;
        enclavePubKey?: string;
        ttlSeconds?: number;
    }): Promise<EnclaveAttestationToken>;
    /**
     * Validates an attestation token against minimum SVN and debug posture requirements.
     */
    verifyAttestationToken(params: {
        tokenId?: string;
        token?: EnclaveAttestationToken;
        minSVN?: number;
        allowDebug?: boolean;
    }): Promise<EnclaveTokenVerifyResult>;
    /**
     * Requests hardware-isolated memory execution and sensitive license evaluation.
     */
    executeIsolatedDecryption(params: EnclaveIsolatedDecryptionRequest): Promise<EnclaveIsolatedDecryptionResult>;
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
    revokeZeroTrustPeer(nodeId: string, reason?: string): Promise<{
        status: string;
        node_id: string;
        revoked: boolean;
        reason: string;
    }>;
    /**
     * Rotates the internal Root CA while maintaining dual-trust continuity.
     */
    rotateZeroTrustCA(validityDays?: number): Promise<{
        status: string;
        message: string;
        root_fingerprint: string;
        ca_expires_at: string;
    }>;
    /**
     * Queries hardware-backed key slot capabilities and operation counters.
     */
    getZeroTrustHSMStatus(): Promise<{
        hsm_enabled: boolean;
        slots_count: number;
        slots: ZeroTrustHSMSlotInfo[];
    }>;
    /**
     * Cryptographically verifies whether a given peer identity is actively authorized.
     */
    verifyZeroTrustPeer(peer: Partial<ZeroTrustPeerIdentity>): Promise<ZeroTrustVerifyResponse>;
    /**
     * Queries autonomous healing status including bucket telemetry, active tunnels, and quota pools.
     */
    getHealingStatus(): Promise<HealingStatus>;
    /**
     * Consumes capacity tokens from the real-time auto-scaling token bucket rate limiter.
     */
    consumeHealingBucket(tokens?: number): Promise<HealingConsumeResponse>;
    /**
     * Issues a cryptographically signed healing ticket allowing a client to resume an interrupted session.
     */
    issueHealingTicket(params: {
        sessionId?: string;
        clientId: string;
        hwid: string;
        tenantId?: string;
        lastAckSeq?: number;
        ttlSeconds?: number;
    }): Promise<HealingTicket>;
    /**
     * Resumes an interrupted client connection tunnel and retrieves missed state synchronization events.
     */
    resumeHealingTunnel(ticket: HealingTicket): Promise<HealingResumeResponse>;
    /**
     * Requests a dynamic quota borrowing lease between tenant pools.
     */
    borrowHealingQuota(params: {
        borrowerTenant: string;
        lenderTenant: string;
        amount: number;
        durationMinutes?: number;
    }): Promise<HealingBorrowResponse>;
    /**
     * Voluntarily returns a borrowed quota allocation before or upon expiration.
     */
    returnHealingQuota(leaseId: string): Promise<{
        status: string;
        lease_id: string;
    }>;
    /**
     * Preemptively recalls borrowed quota when lender tenant load surges.
     */
    recallHealingQuota(leaseId: string, reason?: string): Promise<{
        status: string;
        lease_id: string;
    }>;
    /**
     * Triggers an automated distributed quota rebalancing evaluation.
     */
    rebalanceHealingQuotas(): Promise<HealingRebalanceResponse>;
    /**
     * Queries real-time telemetry, FIPS 140-3 certification level, and operational status of the HSM vault.
     */
    getHsmStatus(): Promise<HSMVaultStatus>;
    /**
     * Lists all provisioned PKCS#11 hardware slots and token descriptors.
     */
    listHsmSlots(): Promise<{
        slots: HSMSlotInfo[];
    }>;
    /**
     * Authenticates an ephemeral session against a hardware slot token using constant-time PIN evaluation.
     */
    hsmLogin(slotId: number, pin: string, userType?: 'USER' | 'SO'): Promise<{
        authenticated: boolean;
        slot_id: number;
        user_type: string;
    }>;
    /**
     * Revokes an active authenticated session on the specified slot.
     */
    hsmLogout(slotId?: number): Promise<{
        logged_out: boolean;
        slot_id: number;
    }>;
    /**
     * Derives a dedicated envelope or storage encryption key inside the hardware cryptoki boundary using HKDF-SHA256.
     */
    deriveHsmKey(params: HSMKeyDerivationRequest): Promise<HSMKeyDerivationResponse>;
    /**
     * Performs authenticated AES-256-GCM envelope encryption under an HSM-derived key.
     */
    encryptHsmEnvelope(params: HSMEnvelopeEncryptRequest): Promise<HSMEnvelopeEncryptResponse>;
    /**
     * Performs authenticated AES-256-GCM envelope decryption and verification under an HSM-derived key.
     */
    decryptHsmEnvelope(params: HSMEnvelopeDecryptRequest): Promise<HSMEnvelopeDecryptResponse>;
    /**
     * Triggers on-demand FIPS 140-3 Known Answer Tests (KAT) for all approved cryptographic primitives.
     */
    runHsmSelfTest(): Promise<{
        self_tests: HSMSelfTestResult[];
        count: number;
    }>;
    /**
     * Retrieves the formal FIPS 140-3 Level 4 compliance audit report and certification evidence.
     */
    getHsmFipsReport(): Promise<HSMFIPS140AuditReport>;
    /**
     * Simulates an environmental or physical tamper sensor trip, latching hardware zeroization.
     */
    simulateHsmTamper(sensorId?: string): Promise<{
        tamper_latched: boolean;
        sensor_id: string;
        zeroized: boolean;
    }>;
    /**
     * Performs immediate administrative zeroization across all hardware slots and key registers.
     */
    zeroizeHsm(): Promise<{
        zeroized: boolean;
    }>;
    /**
     * Queries real-time operational status and telemetry for ML-KEM.
     */
    getMLKEMStatus(): Promise<MLKEMStatus>;
    /**
     * Lists all registered public encapsulation keys.
     */
    listMLKEMKeys(): Promise<MLKEMPublicKey[]>;
    /**
     * Generates and registers a new lattice keypair (ML-KEM-768 or ML-KEM-1024).
     */
    generateMLKEMKey(algorithm?: string): Promise<MLKEMPublicKey>;
    /**
     * Encapsulates a shared secret against the specified (or default) public key.
     */
    encapsulateMLKEM(keyId?: string): Promise<MLKEMEncapsulationResult>;
    /**
     * Decapsulates a ciphertext using the server-side private key.
     */
    decapsulateMLKEM(keyId: string, ciphertextHex: string): Promise<string>;
    /**
     * Executes a post-quantum hybrid key exchange handshake (ECDH P-256 + ML-KEM).
     */
    hybridKEMHandshake(req: HybridHandshakeRequest): Promise<HybridHandshakeResponse>;
    /**
     * Verifies an active ephemeral hybrid session.
     */
    verifyHybridKEMSession(sessionId: string): Promise<HybridSessionVerification>;
    /**
     * Queries real-time status and telemetry for the RFC 6962 verifiable transparency log.
     */
    getTransparencyStatus(): Promise<TransparencyStatus>;
    /**
     * Appends an audit event to the transparency log and issues an updated Signed Tree Head (STH).
     */
    appendTransparencyEntry(action: string, tenantId?: string, payload?: any): Promise<{
        status: string;
        entry: TransparencyLogEntry;
        sth: TransparencySTH;
    }>;
    /**
     * Queries the latest Signed Tree Head (STH) with multi-party witness co-signatures.
     */
    getTransparencySTH(): Promise<TransparencySTH>;
    /**
     * Queries a slice of entries from the transparency log.
     */
    getTransparencyEntries(start?: number, count?: number): Promise<{
        start: number;
        count: number;
        entries: TransparencyLogEntry[];
    }>;
    /**
     * Retrieves an RFC 6962 inclusion proof for a leaf index in a tree size.
     */
    getTransparencyInclusionProof(index: number, treeSize: number): Promise<TransparencyInclusionProof>;
    /**
     * Cryptographically verifies an inclusion proof payload on the broker.
     */
    verifyTransparencyInclusionProof(proof: TransparencyInclusionProof): Promise<{
        verified: boolean;
        leaf_index: number;
        tree_size: number;
    }>;
    /**
     * Retrieves an RFC 6962 consistency proof between two tree heads.
     */
    getTransparencyConsistencyProof(first: number, second: number): Promise<TransparencyConsistencyProof>;
    /**
     * Cryptographically verifies a consistency proof payload on the broker.
     */
    verifyTransparencyConsistencyProof(proof: TransparencyConsistencyProof): Promise<{
        verified: boolean;
        first_size: number;
        second_size: number;
    }>;
    /**
     * Requests a multi-party witness node to co-sign the active tree head.
     */
    cosignTransparencySTH(witnessId: string): Promise<TransparencyWitnessSignature>;
    /**
     * Lists all registered witness node identifiers.
     */
    listTransparencyWitnesses(): Promise<string[]>;
    /**
     * Queries real-time status and telemetry for the adaptive zero-trust device posture engine.
     */
    getPostureStatus(): Promise<PostureStatus>;
    /**
     * Submits client device posture telemetry and evaluates vector confidence scores.
     */
    evaluateDevicePosture(report: DevicePostureReport): Promise<PostureVectorScores>;
    /**
     * Queries currently quarantined devices, optionally filtered by tenant.
     */
    getQuarantinedDevices(tenantId?: string): Promise<QuarantinedDevice[]>;
    /**
     * Manually releases an endpoint from quarantine isolation.
     */
    releaseDeviceQuarantine(deviceId: string, tenantId?: string): Promise<boolean>;
    /**
     * Issues a time-bound step-up authentication challenge for remediation.
     */
    issueDeviceStepUpChallenge(deviceId: string, tenantId?: string, actions?: string[]): Promise<StepUpChallenge>;
    /**
     * Submits challenge proof for step-up verification.
     */
    verifyDeviceStepUpChallenge(challengeId: string, nonce: string): Promise<boolean>;
    /**
     * Queries latest posture scores and quarantine state for an endpoint.
     */
    getDevicePosture(deviceId: string, tenantId?: string): Promise<{
        scores: PostureVectorScores;
        quarantined: boolean;
        quarantine?: QuarantinedDevice;
    }>;
    /**
     * Queries real-time telemetry and operational stats for multi-cloud active-active routing.
     */
    getMultiCloudStatus(): Promise<MultiCloudStatus>;
    /**
     * Returns all registered cloud edge providers.
     */
    listMultiCloudProviders(): Promise<CloudProvider[]>;
    /**
     * Evaluates client geo parameters and returns optimal provider and signed routing token.
     */
    routeMultiCloud(clientRegion?: string, clientIp?: string): Promise<{
        provider: CloudProvider;
        token: MultiCloudRoutingToken;
    }>;
    /**
     * Records a synthetic or real-time health probe result.
     */
    submitMultiCloudProbe(probe: HealthProbeResult): Promise<FailoverEvent | null>;
    /**
     * Commits an atomic state mutation for cross-cloud zero-packet-loss synchronization.
     */
    submitMultiCloudDelta(originProvider: string, action: string, payload: any): Promise<SyncDelta>;
    /**
     * Queries uncommitted deltas for a partitioned or recovering cloud provider.
     */
    getMultiCloudPendingSync(providerId: string, limit?: number): Promise<SyncDelta[]>;
    /**
     * Acknowledges delta commitment by a cloud provider with optional voucher.
     */
    acknowledgeMultiCloudSync(providerId: string, deltaId: string, voucher?: SyncVoucher): Promise<boolean>;
    /**
     * Triggers an administrative failover drill.
     */
    simulateMultiCloudFailover(providerId: string, reason?: string): Promise<FailoverEvent>;
}
//# sourceMappingURL=client.d.ts.map