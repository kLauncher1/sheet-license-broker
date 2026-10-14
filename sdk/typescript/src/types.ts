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


