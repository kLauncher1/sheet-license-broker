export declare class BrokerError extends Error {
    statusCode?: number;
    details?: Record<string, unknown>;
    constructor(message: string, statusCode?: number, details?: Record<string, unknown>);
}
export declare class AuthenticationError extends BrokerError {
    constructor(message: string, statusCode?: number, details?: Record<string, unknown>);
}
export declare class LicenseValidationError extends BrokerError {
    constructor(message: string, statusCode?: number, details?: Record<string, unknown>);
}
export declare class RateLimitError extends BrokerError {
    constructor(message: string, statusCode?: number, details?: Record<string, unknown>);
}
//# sourceMappingURL=errors.d.ts.map