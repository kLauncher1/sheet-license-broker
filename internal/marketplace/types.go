package marketplace

import (
	"errors"
	"time"
)

// Supported marketplace/reseller providers
const (
	ProviderStripe       = "stripe"
	ProviderLemonSqueezy = "lemonsqueezy"
	ProviderPaddle       = "paddle"
)

// Normalized action types
const (
	ActionProvision = "provision"
	ActionRevoke    = "revoke"
	ActionUpdate    = "update"
	ActionIgnore    = "ignore"
)

// Common error definitions
var (
	ErrUnsupportedProvider = errors.New("unsupported marketplace provider")
	ErrInvalidSignature    = errors.New("invalid webhook signature")
	ErrMissingSignature    = errors.New("missing webhook signature header")
	ErrTimestampDrift      = errors.New("webhook timestamp outside tolerance window")
	ErrDuplicateEvent      = errors.New("duplicate webhook event already processed")
	ErrMissingCustomer     = errors.New("missing customer identifier or email")
	ErrInvalidPayload      = errors.New("malformed or unparseable webhook payload")
)

// NormalizedEvent represents a normalized, provider-agnostic purchase, renewal, or cancellation event.
type NormalizedEvent struct {
	EventID        string            `json:"event_id"`
	Provider       string            `json:"provider"`
	EventType      string            `json:"event_type"`
	Action         string            `json:"action"` // "provision", "revoke", "update", "ignore"
	CustomerEmail  string            `json:"customer_email"`
	CustomerName   string            `json:"customer_name,omitempty"`
	LicenseKey     string            `json:"license_key,omitempty"`
	Tier           string            `json:"tier"`
	Seats          int               `json:"seats"`
	DaysValid      int               `json:"days_valid"`
	Features       []string          `json:"features,omitempty"`
	OrderID        string            `json:"order_id,omitempty"`
	SubscriptionID string            `json:"subscription_id,omitempty"`
	AmountCents    int64             `json:"amount_cents,omitempty"`
	Currency       string            `json:"currency,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

// TransactionRecord captures an audit/history record of processed webhook transactions.
type TransactionRecord struct {
	ID            string    `json:"id"`
	EventID       string    `json:"event_id"`
	Provider      string    `json:"provider"`
	Action        string    `json:"action"`
	CustomerEmail string    `json:"customer_email"`
	LicenseKey    string    `json:"license_key"`
	Tier          string    `json:"tier"`
	Seats         int       `json:"seats"`
	Status        string    `json:"status"` // "PROVISIONED", "REVOKED", "SKIPPED", "DUPLICATE", "FAILED"
	ErrorMessage  string    `json:"error_message,omitempty"`
	ProcessedAt   time.Time `json:"processed_at"`
}

// MarketplaceConfig holds webhook secrets and provisioning defaults.
type MarketplaceConfig struct {
	StripeWebhookSecret       string
	LemonSqueezyWebhookSecret string
	PaddleWebhookSecret       string
	DefaultDaysValid          int
	DefaultTier               string
	DefaultSeats              int
	ToleranceSeconds          int // replay window (default: 300s)
}

// MarketplaceStatus represents diagnostic telemetry.
type MarketplaceStatus struct {
	SupportedProviders     []string  `json:"supported_providers"`
	TotalProcessedEvents   int64     `json:"total_processed_events"`
	TotalProvisioned       int64     `json:"total_provisioned"`
	TotalRevoked           int64     `json:"total_revoked"`
	TotalDuplicates        int64     `json:"total_duplicates"`
	TotalFailed            int64     `json:"total_failed"`
	RecentTransactions     int       `json:"recent_transactions"`
	StripeConfigured       bool      `json:"stripe_configured"`
	LemonSqueezyConfigured bool      `json:"lemon_squeezy_configured"`
	PaddleConfigured       bool      `json:"paddle_configured"`
	Timestamp              time.Time `json:"timestamp"`
}
