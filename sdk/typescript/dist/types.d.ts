/**
 * Type definitions for Sheet License Broker Client SDK.
 */
export interface BrokerClientOptions {
    /**
     * Base URL of the running sheet-license-broker gateway instance.
     * Defaults to http://127.0.0.1:9082.
     */
    baseUrl?: string;
    /**
     * Optional shared HMAC-SHA256 secret key for anti-tamper request signing.
     */
    secretKey?: string;
    /**
     * Optional tenant identifier attached via X-Tenant-ID header.
     */
    tenantId?: string;
    /**
     * Request timeout in milliseconds. Defaults to 10000 (10 seconds).
     */
    timeoutMs?: number;
}
export interface LicenseRecord {
    key: string;
    created_at: string;
    expires_at: string;
    days: number;
    max_devices: number;
    bound_devices: string[];
    status: 'active' | 'revoked' | 'expired';
}
export interface LicenseValidationResponse {
    valid: boolean;
    message?: string;
    error?: string;
    source?: 'memory' | 'gas';
    tier?: string;
    features?: string[];
    license?: LicenseRecord;
}
export interface UsageRecord {
    key: string;
    metric: string;
    period: string;
    count: number;
    limit: number;
    updated_at?: string;
}
export interface FeatureCheckResponse {
    status: string;
    license_key: string;
    feature: string;
    enabled: boolean;
    tier: string;
}
export interface UsageRecordResponse {
    status: string;
    record: UsageRecord;
    exceeded: boolean;
}
export interface UserAuthResponse {
    username?: string;
    role?: string;
    created_at?: string;
    authenticated?: boolean;
    error?: string;
}
export interface HealthResponse {
    status: string;
    service: string;
    version: string;
    timestamp: string;
    proxy?: Record<string, unknown>;
    security?: {
        hmac_enforced: boolean;
        nonce_window: string;
    };
}
export interface DocumentResponse {
    success?: boolean;
    action?: string;
    collection?: string;
    id?: string;
    payload?: Record<string, unknown>;
    error?: string;
}
export interface AttestationChallengeResponse {
    status: string;
    challenge_id: string;
    nonce: string;
    expires_at: string;
}
export interface AttestationRecord {
    license_key: string;
    hwid: string;
    attestation_type: string;
    trust_level: string;
    pcr_digest?: string;
    ak_public_hash?: string;
    last_nonce?: string;
    verified_at?: string;
    tamper_score: number;
    details?: string;
}
export interface AttestationVerifyResponse {
    status: string;
    record: AttestationRecord;
}
export interface TelemetryReport {
    debugger_present: boolean;
    memory_integrity: boolean;
    sandbox_detected?: boolean;
    hooks_detected?: boolean;
    process_checksum?: string;
    execution_uptime_s?: number;
}
export interface TelemetryResponse {
    status: string;
    tamper_score: number;
    tampered: boolean;
    trust_level: string;
    details?: string;
}
export interface EncryptedAuditBundle {
    bundle_id: string;
    version: string;
    created_at: string;
    record_count: number;
    algorithm: string;
    key_fingerprint: string;
    nonce_hex: string;
    ciphertext_hex: string;
    hmac_signature: string;
}
export interface AuditExportResponse {
    status: string;
    bundle: EncryptedAuditBundle;
}
export interface ClusterPeer {
    id: string;
    address: string;
    region?: string;
    role?: string;
    active: boolean;
    latency_ms?: number;
}
export interface ClusterStatusResponse {
    node_id: string;
    region: string;
    role: string;
    current_term: number;
    leader_id: string;
    has_quorum: boolean;
    quorum_size: number;
    active_peers: number;
    merkle_digest: string;
    peers?: ClusterPeer[];
}
export interface ClusterPeersResponse {
    status: string;
    peers: ClusterPeer[];
}
export interface StreamClientInfo {
    id: string;
    license_key?: string;
    hwid?: string;
    tenant_id?: string;
    remote_addr?: string;
    connected_at?: string;
    last_heartbeat?: string;
    latency_ms?: number;
}
export interface StreamClientsResponse {
    status: string;
    count: number;
    clients: StreamClientInfo[];
}
export interface StreamKillResponse {
    status: string;
    target: string;
    signaled_clients: number;
    message: string;
}
export interface StreamTelemetryResponse {
    status: string;
    telemetry: {
        active_connections: number;
        unique_licenses: number;
        unique_devices: number;
        total_heartbeats: number;
        total_revocations: number;
        uptime_seconds: number;
        clients?: StreamClientInfo[];
    };
}
export interface PedersenCommitmentPoint {
    x: string;
    y: string;
}
export interface AnonymousCredential {
    id: string;
    hwid_commitment: PedersenCommitmentPoint;
    tier: number;
    max_seats: number;
    expires_at: number;
    scope: string;
    tenant_id: string;
    issued_at: number;
    sig_r?: string;
    sig_s?: string;
}
export interface ZKPProof {
    ax: string;
    ay: string;
    sv: string;
    sr: string;
    hwid_commitment: PedersenCommitmentPoint;
    credential_id: string;
    claimed_tier: number;
    max_seats: number;
    expires_at: number;
    scope: string;
    tenant_id: string;
    nullifier: string;
    epoch: number;
    sig_r?: string;
    sig_s?: string;
    challenge: string;
}
export interface ZKPVerificationResult {
    valid: boolean;
    claimed_tier: number;
    tier_name: string;
    tenant_id: string;
    nullifier: string;
    epoch: number;
    expires_at: string;
    hwid_commitment: string;
    reason?: string;
}
export interface ZKPParamsResponse {
    status: string;
    curve: string;
    generator_g: {
        x: string;
        y: string;
    };
    generator_h: {
        x: string;
        y: string;
    };
    order_n: string;
    issuer_public_key: {
        x: string;
        y: string;
        hex: string;
    };
}
export interface ZKPIssueResponse {
    status: string;
    credential: AnonymousCredential;
    blinding_factor?: string;
}
export interface ZKPVerifyResponse {
    status: string;
    valid: boolean;
    details?: ZKPVerificationResult;
    reason?: string;
}
export interface ZKPStatusResponse {
    status: string;
    zkp: {
        total_credentials_issued: number;
        total_proofs_verified: number;
        total_proofs_rejected: number;
        spent_nullifiers_count: number;
        issuer_public_key: string;
        active_epoch: number;
    };
}
export interface SSOStatusSummary {
    total_idps: number;
    active_directory_users: number;
    deprovisioned_users: number;
    allocated_license_seats: number;
    supported_protocols: string[];
}
export interface SessionTokenIntrospectResult {
    active: boolean;
    authorized?: boolean;
    claims?: {
        session_id: string;
        user_id: string;
        email: string;
        tenant_id: string;
        role: string;
        scopes: string[];
        iat: number;
        exp: number;
    };
    error?: string;
}
export interface SCIMUserResource {
    schemas: string[];
    id: string;
    userName: string;
    displayName?: string;
    active: boolean;
    tenantId?: string;
    licenseKey?: string;
    roles?: Array<{
        value: string;
        display?: string;
        primary?: boolean;
    }>;
    emails?: Array<{
        value: string;
        type?: string;
        primary?: boolean;
    }>;
}
export interface SCIMListUsersResult {
    schemas: string[];
    totalResults: number;
    startIndex: number;
    itemsPerPage: number;
    Resources: SCIMUserResource[];
}
export interface PQCHybridSignature {
    algorithm: string;
    key_id: string;
    classical_sig: string;
    quantum_sig: string;
    timestamp: string;
    epoch?: number;
    payload_hash?: string;
}
export interface PQCVerificationResult {
    valid: boolean;
    algorithm: string;
    key_id: string;
    classical_valid: boolean;
    quantum_valid: boolean;
    grace_active?: boolean;
    error_message?: string;
    latency_ns?: number;
}
export interface PQCStatusSummary {
    active_key_id: string;
    default_algorithm: string;
    total_keys: number;
    rotated_keys_in_grace: number;
    revoked_keys: number;
    total_rotations: number;
    verified_signatures: number;
    rejected_signatures: number;
    supported_algorithms: string[];
}
export interface AnomalyObservation {
    license_key?: string;
    hwid?: string;
    ip?: string;
    country?: string;
    region?: string;
    asn?: string;
    user_agent?: string;
    action?: string;
    timestamp?: string;
    latency_ms?: number;
    metadata?: Record<string, string>;
}
export interface AnomalyRiskFactor {
    code: string;
    description: string;
    severity: number;
    detected_at: string;
}
export interface AnomalyRiskScore {
    entity_id: string;
    score: number;
    level: 'low' | 'medium' | 'high' | 'critical';
    factors: AnomalyRiskFactor[];
    challenge_escalation: boolean;
    challenge_type: string;
    challenge_token?: string;
    challenge_expires_at?: string;
    quarantine_triggered: boolean;
    evaluated_at: string;
}
export interface AnomalyGraphNode {
    id: string;
    type: string;
    label: string;
    risk_score: number;
    properties?: Record<string, any>;
}
export interface AnomalyGraphEdge {
    source: string;
    target: string;
    relation: string;
    weight: number;
    timestamp: string;
}
export interface AnomalyIncidentGraph {
    format: string;
    generated_at: string;
    total_nodes: number;
    total_edges: number;
    nodes: AnomalyGraphNode[];
    edges: AnomalyGraphEdge[];
}
export interface AnomalyTelemetrySummary {
    total_observations: number;
    active_monitored_entities: number;
    anomalies_detected: number;
    challenges_issued: number;
    challenges_cleared: number;
    active_quarantines: number;
    last_anomaly_detected_at?: string;
}
export interface EnclaveAttestationResult {
    valid: boolean;
    platform: 'intel_sgx' | 'amd_sev_snp';
    mr_enclave?: string;
    mr_signer?: string;
    measurement?: string;
    svn: number;
    debug: boolean;
    report_data_hex: string;
    error_message?: string;
    verified_at: string;
}
export interface EnclaveHandshakeResponse {
    established: boolean;
    session_id: string;
    broker_public_key: string;
    expires_at: string;
}
export interface EnclaveEncryptedMessage {
    session_id: string;
    sequence: number;
    nonce: string;
    payload: string;
}
export interface EnclaveEvalVerdict {
    valid: boolean;
    license_key: string;
    tier?: string;
    features?: string[];
    expires_at?: string;
    enclave_platform: string;
    zero_plaintext_guarantee: boolean;
    evaluated_at: string;
    message?: string;
}
export interface EnclaveTelemetry {
    verified_quotes: number;
    active_tunnels: number;
    total_evaluations: number;
    failed_attestations: number;
    quotes_by_platform: Record<string, number>;
    active_policies_count: number;
}
export interface AnycastPOP {
    id: string;
    name: string;
    region: string;
    country: string;
    latitude: number;
    longitude: number;
    endpoint_url?: string;
    weight?: number;
    status: 'healthy' | 'degraded' | 'offline';
    last_seen?: string;
    average_rtt_ms?: number;
}
export interface AnycastRoutingDecision {
    selected_pop: AnycastPOP;
    fallback_pops?: AnycastPOP[];
    estimated_latency_ms: number;
    signed_routing_token: string;
    timestamp: string;
    client_ip?: string;
}
export interface EdgeCacheTelemetry {
    hits: number;
    misses: number;
    revalidations: number;
    lookup_latency_us: number;
    cached_tier_entries: number;
    hit_ratio: number;
}
export interface PartitionStateInfo {
    region_id: string;
    status: 'normal' | 'partitioned' | 'healing';
    isolated_since?: string;
    local_lease_duration: number;
    recovery_sync_status: string;
    last_probe_time: string;
    mitigation_token?: string;
}
export interface AnycastStatusResponse {
    pops: AnycastPOP[];
    pop_count: number;
    cache_stats: EdgeCacheTelemetry;
    is_partitioned: boolean;
    partition_states: PartitionStateInfo[];
    edge_routing_enabled: boolean;
}
export interface MarketplaceTransaction {
    id: string;
    event_id: string;
    provider: string;
    action: string;
    customer_email: string;
    license_key: string;
    tier: string;
    seats: number;
    status: string;
    error_message?: string;
    processed_at: string;
}
export interface MarketplaceStatus {
    enabled: boolean;
    supported_providers: string[];
    total_processed_events: number;
    total_provisioned: number;
    total_revoked: number;
    total_duplicates: number;
    total_failed: number;
    recent_transactions: number;
    stripe_configured: boolean;
    lemon_squeezy_configured: boolean;
    paddle_configured: boolean;
    timestamp: string;
}
export interface MarketplaceSimulateRequest {
    provider?: string;
    event_type?: string;
    action?: 'provision' | 'revoke' | string;
    customer_email: string;
    customer_name?: string;
    license_key?: string;
    tier?: string;
    seats?: number;
    days_valid?: number;
    order_id?: string;
    metadata?: Record<string, string>;
}
export interface MarketplaceSimulateResponse {
    status: string;
    event?: Record<string, any>;
    transaction: MarketplaceTransaction;
}
export interface MarketplaceTransactionFilter {
    provider?: string;
    customer_email?: string;
    email?: string;
    status?: string;
    limit?: number;
}
export interface AirgapDongleToken {
    token_id: string;
    license_key: string;
    hwid: string;
    tier: string;
    features?: string[];
    max_devices: number;
    issued_at: number;
    expires_at: number;
    counter: number;
    signature: string;
    public_key?: string;
}
export interface AirgapIssueRequest {
    license_key: string;
    hwid?: string;
    tier?: string;
    days_valid?: number;
    max_devices?: number;
    features?: string[];
}
export interface AirgapIssueResponse {
    status: string;
    token: AirgapDongleToken;
    dongle_token: string;
    qr_payload: string;
}
export interface AirgapVerifyRequest {
    token: string;
    hwid?: string;
    timestamp?: number;
}
export interface AirgapVerifyResponse {
    status: string;
    valid: boolean;
    token?: AirgapDongleToken;
    error?: string;
}
export interface AirgapActivationRequest {
    request_id?: string;
    license_key: string;
    hwid?: string;
    current_timestamp?: number;
    nonce?: string;
    hardware_fingerprint?: string;
}
export interface AirgapActivationResponse {
    request_id: string;
    license_key: string;
    hwid: string;
    dongle_token: string;
    qr_payload: string;
    valid_until: number;
    counter: number;
    status: string;
    signature: string;
}
export interface AirgapRollbackState {
    vault_id: string;
    hwid: string;
    high_water_mark: number;
    monotonic_counter: number;
    tampered: boolean;
    tampered_reason?: string;
    tripped_at?: number;
    unlocked_at?: number;
}
export interface AirgapUnlockRequest {
    vault_id: string;
    hwid: string;
    nonce: string;
    timestamp: number;
    admin_signature: string;
}
export interface AirgapStatus {
    vault_active: boolean;
    master_public_key: string;
    admin_public_key: string;
    total_issued_tokens: number;
    total_verified_tokens: number;
    total_activations: number;
    rollback_tripped_count: number;
    last_high_water_mark: number;
    tracked_vaults: number;
    timestamp: string;
}
export type ZeroTrustPeerRole = 'cluster_peer' | 'worker_node' | 'admin_agent' | 'edge_gateway';
export type ZeroTrustPeerStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
export interface ZeroTrustPeerIdentity {
    node_id: string;
    role: ZeroTrustPeerRole;
    common_name: string;
    spiffe_id?: string;
    serial_number: string;
    fingerprint_sha256: string;
    dns_names?: string[];
    ip_addresses?: string[];
    issued_at?: string;
    expires_at: string;
    status: ZeroTrustPeerStatus;
    revoked_at?: string;
    revocation_reason?: string;
}
export interface ZeroTrustEnrollRequest {
    node_id: string;
    role?: ZeroTrustPeerRole;
    dns_names?: string[];
    ip_addresses?: string[];
    validity_days?: number;
}
export interface ZeroTrustEnrollResponse {
    node_id: string;
    role: ZeroTrustPeerRole;
    certificate_pem: string;
    private_key_pem: string;
    root_ca_pem: string;
    serial_number: string;
    fingerprint_sha256: string;
    expires_at: string;
}
export interface ZeroTrustHSMSlotInfo {
    slot_id: number;
    label: string;
    algorithm: string;
    key_present: boolean;
    public_key_pem: string;
    operations_count: number;
    zeroized: boolean;
}
export interface ZeroTrustStatus {
    ca_initialized: boolean;
    ca_root_fingerprint: string;
    ca_expires_at: string;
    active_peers_count: number;
    revoked_peers_count: number;
    mtls_enforced: boolean;
    hsm_enabled: boolean;
    hsm_slots_count: number;
    slots?: ZeroTrustHSMSlotInfo[];
    timestamp: string;
}
export interface ZeroTrustVerifyResponse {
    valid: boolean;
    reason: string;
    node_id: string;
}
export interface TokenBucketStats {
    current_tokens: number;
    capacity: number;
    base_capacity: number;
    refill_rate: number;
    load_score: number;
    scale_multiplier: number;
    mode: string;
    last_refill: string;
}
export interface HealingTicket {
    session_id: string;
    client_id: string;
    hwid: string;
    tenant_id: string;
    issued_at: string;
    expires_at: string;
    last_ack_seq: number;
    signature: string;
}
export interface HealingSession {
    session_id: string;
    client_id: string;
    hwid: string;
    tenant_id: string;
    state: string;
    connected_at: string;
    last_heartbeat: string;
    disconnected_at?: string;
    grace_expires_at?: string;
    missed_events_count: number;
}
export interface DeltaEvent {
    sequence: number;
    tenant_id: string;
    client_id: string;
    event_type: string;
    payload: string;
    timestamp: string;
}
export interface QuotaPool {
    tenant_id: string;
    total_quota: number;
    used_quota: number;
    borrowed_in: number;
    lent_out: number;
    available_quota: number;
    utilization: number;
}
export interface QuotaLease {
    lease_id: string;
    borrower_tenant: string;
    lender_tenant: string;
    amount: number;
    borrowed_at: string;
    expires_at: string;
    status: string;
    recall_reason?: string;
}
export interface QuotaRebalanceEvent {
    timestamp: string;
    action: string;
    borrower_tenant: string;
    lender_tenant: string;
    amount: number;
    reason: string;
    status: string;
}
export interface HealingStatus {
    bucket: TokenBucketStats;
    active_tunnels: number;
    suspended_tunnels: number;
    total_missed_events: number;
    quota_pools: QuotaPool[];
    active_leases: QuotaLease[];
    recent_rebalances: QuotaRebalanceEvent[];
}
export interface HealingConsumeResponse {
    allowed: boolean;
    stats: TokenBucketStats;
}
export interface HealingResumeResponse {
    status: string;
    session: HealingSession;
    missed_events: DeltaEvent[];
    missed_count: number;
}
export interface HealingBorrowResponse {
    status: string;
    lease: QuotaLease;
}
export interface HealingRebalanceResponse {
    status: string;
    events: QuotaRebalanceEvent[];
}
export interface HSMSlotInfo {
    slot_id: number;
    description: string;
    manufacturer_id: string;
    hardware_version: string;
    firmware_version: string;
    mechanisms: string[];
    token_present: boolean;
    removable: boolean;
    hardware_slot: boolean;
}
export interface HSMTokenInfo {
    slot_id: number;
    label: string;
    manufacturer_id: string;
    model: string;
    serial_number: string;
    max_session_count: number;
    session_count: number;
    max_pin_len: number;
    min_pin_len: number;
    total_private_memory: number;
    free_private_memory: number;
    fips_level: string;
    user_pin_initialized: boolean;
    user_pin_locked: boolean;
    so_pin_locked: boolean;
    tamper_detected: boolean;
    initialized_at: string;
}
export interface HSMVaultStatus {
    initialized: boolean;
    hardware_available: boolean;
    fips_level: string;
    slots_total: number;
    active_sessions: number;
    tamper_detected: boolean;
    locked_out: boolean;
    master_key_present: boolean;
    operations_count: number;
    last_self_test: string;
    uptime_seconds: number;
}
export interface HSMKeyDerivationRequest {
    slot_id: number;
    purpose: string;
    context: string;
    salt_hex?: string;
    key_length_bits?: number;
}
export interface HSMKeyDerivationResponse {
    slot_id: number;
    purpose: string;
    derived_key_handle: number;
    fingerprint: string;
    key_length_bits: number;
    algorithm: string;
    derived_at: string;
}
export interface HSMEnvelopeEncryptRequest {
    slot_id: number;
    plaintext: string;
    associated_data?: string;
    purpose?: string;
}
export interface HSMEnvelopeEncryptResponse {
    slot_id: number;
    ciphertext_hex: string;
    nonce_hex: string;
    key_fingerprint: string;
    algorithm: string;
    encrypted_at: string;
}
export interface HSMEnvelopeDecryptRequest {
    slot_id: number;
    ciphertext_hex: string;
    nonce_hex: string;
    associated_data?: string;
    purpose?: string;
}
export interface HSMEnvelopeDecryptResponse {
    slot_id: number;
    plaintext: string;
    authenticated: boolean;
    decrypted_at: string;
}
export interface HSMSelfTestResult {
    test_name: string;
    passed: boolean;
    execution_time_us: number;
    algorithm_tested: string;
    details: string;
}
export interface HSMFIPS140AuditReport {
    certification_level: string;
    hardware_model: string;
    serial_number: string;
    firmware_revision: string;
    tamper_state: string;
    active_slots: number;
    kat_passed: boolean;
    self_tests: HSMSelfTestResult[];
    zeroize_on_tamper: boolean;
    generated_at: string;
}
export interface MLKEMStatus {
    initialized: boolean;
    active_keys_count: number;
    default_algorithm: string;
    active_sessions_count: number;
    quantum_enforced: boolean;
    total_encapsulations: number;
    total_decapsulations: number;
    total_handshakes: number;
    fallback_attempts: number;
    fallback_rejected: number;
    last_handshake_at?: string;
    uptime_seconds: number;
}
export interface MLKEMPublicKey {
    key_id: string;
    algorithm: string;
    fingerprint: string;
    raw_hex: string;
    created_at: string;
}
export interface MLKEMEncapsulationResult {
    key_id: string;
    algorithm: string;
    ciphertext_hex: string;
    shared_secret_hex: string;
    encapsulated_at: string;
}
export interface MLKEMDecapsulationResponse {
    key_id: string;
    shared_secret_hex: string;
}
export interface HybridHandshakeRequest {
    client_ecdh_pub_hex: string;
    client_mlkem_key_id?: string;
    requested_mode?: 'hybrid' | 'pqc-only' | 'classical-fallback' | string;
    algorithm?: string;
    client_nonce?: string;
}
export interface HybridHandshakeResponse {
    session_id: string;
    server_ecdh_pub_hex: string;
    ciphertext_hex: string;
    auth_tag_hex: string;
    agreed_mode: string;
    algorithm: string;
    quantum_resistant: boolean;
    expires_at: string;
}
export interface HybridSessionVerification {
    valid: boolean;
    session_id: string;
    agreed_mode: string;
    algorithm: string;
    quantum_resistant: boolean;
    created_at?: string;
    expires_at?: string;
}
//# sourceMappingURL=types.d.ts.map