import type {
  BrokerClientOptions,
  DocumentResponse,
  HealthResponse,
  LicenseRecord,
  LicenseValidationResponse,
  UserAuthResponse,
} from './types.js';

export declare class BrokerError extends Error {
  statusCode?: number;
  details?: Record<string, unknown>;
  constructor(message: string, statusCode?: number, details?: Record<string, unknown>);
}

export declare class AuthenticationError extends BrokerError {}
export declare class LicenseValidationError extends BrokerError {}

export declare class SheetLicenseClient {
  constructor(options?: BrokerClientOptions);
  health(): Promise<HealthResponse>;
  ping(): Promise<Record<string, unknown>>;
  verifyLicense(licenseKey: string, hwid?: string): Promise<LicenseValidationResponse>;
  createLicense(days?: number, maxDevices?: number): Promise<LicenseRecord>;
  revokeLicense(licenseKey: string, reason?: string): Promise<Record<string, unknown>>;
  addBlacklist(type: 'device' | 'license', target: string, reason?: string): Promise<Record<string, unknown>>;
  removeBlacklist(type: 'device' | 'license', target: string): Promise<Record<string, unknown>>;
  registerUser(username: string, password: string, role?: string): Promise<UserAuthResponse>;
  loginUser(username: string, password: string): Promise<UserAuthResponse>;
  putDoc(collection: string, id: string, payload: Record<string, unknown>): Promise<DocumentResponse>;
  getDoc(collection: string, id: string): Promise<DocumentResponse>;
}