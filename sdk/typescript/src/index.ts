/**
 * Sheet License Broker - Official TypeScript / JavaScript Client SDK
 */

export {
  AuthenticationError,
  BrokerError,
  LicenseValidationError,
  RateLimitError,
  SheetLicenseClient,
} from './client.js';

export { getMachineHwid } from './hwid.js';

export type {
  BrokerClientOptions,
  DocumentResponse,
  HealthResponse,
  LicenseRecord,
  LicenseValidationResponse,
  UserAuthResponse,
  AnonymousCredential,
  PedersenCommitmentPoint,
  ZKPParamsResponse,
  ZKPIssueResponse,
  ZKPProof,
  ZKPStatusResponse,
  ZKPVerificationResult,
  ZKPVerifyResponse,
} from './types.js';
