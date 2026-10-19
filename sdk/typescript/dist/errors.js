export class BrokerError extends Error {
    statusCode;
    details;
    constructor(message, statusCode, details) {
        super(message);
        this.name = 'BrokerError';
        this.statusCode = statusCode;
        this.details = details;
    }
}
export class AuthenticationError extends BrokerError {
    constructor(message, statusCode, details) {
        super(message, statusCode, details);
        this.name = 'AuthenticationError';
    }
}
export class LicenseValidationError extends BrokerError {
    constructor(message, statusCode, details) {
        super(message, statusCode, details);
        this.name = 'LicenseValidationError';
    }
}
export class RateLimitError extends BrokerError {
    retryAfter;
    constructor(message, statusCode, details, retryAfter = 0) {
        super(message, statusCode, details);
        this.name = 'RateLimitError';
        this.retryAfter = retryAfter;
    }
}
//# sourceMappingURL=errors.js.map