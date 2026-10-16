export class BrokerError extends Error {
  public statusCode?: number;
  public details?: Record<string, unknown>;

  constructor(message: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message);
    this.name = 'BrokerError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

export class AuthenticationError extends BrokerError {
  constructor(message: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message, statusCode, details);
    this.name = 'AuthenticationError';
  }
}

export class LicenseValidationError extends BrokerError {
  constructor(message: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message, statusCode, details);
    this.name = 'LicenseValidationError';
  }
}

export class RateLimitError extends BrokerError {
  constructor(message: string, statusCode?: number, details?: Record<string, unknown>) {
    super(message, statusCode, details);
    this.name = 'RateLimitError';
  }
}
