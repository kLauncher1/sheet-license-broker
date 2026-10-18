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
  generator_g: { x: string; y: string };
  generator_h: { x: string; y: string };
  order_n: string;
  issuer_public_key: { x: string; y: string; hex: string };
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
  roles?: Array<{ value: string; display?: string; primary?: boolean }>;
  emails?: Array<{ value: string; type?: string; primary?: boolean }>;
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


