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
} from './types.js';
