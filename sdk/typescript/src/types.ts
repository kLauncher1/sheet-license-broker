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
  license?: LicenseRecord;
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
