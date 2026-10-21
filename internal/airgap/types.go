package airgap

import (
	"errors"
	"time"
)

// Sentinel errors for air-gapped license vault and offline dongle emulation.
var (
	ErrInvalidToken             = errors.New("invalid or malformed airgap dongle token")
	ErrTokenExpired             = errors.New("airgap dongle token has expired")
	ErrTamperedSignature        = errors.New("invalid or tampered cryptographic signature")
	ErrClockRollback            = errors.New("system clock rollback detected; vault tripped")
	ErrVaultTampered            = errors.New("airgap vault is locked due to clock tampering")
	ErrInvalidActivationPayload = errors.New("invalid airgap activation payload")
	ErrInvalidUnlockToken       = errors.New("invalid administrative unlock token")
	ErrHWIDMismatch             = errors.New("machine hardware ID does not match bound dongle token")
	ErrInvalidCounter           = errors.New("monotonic counter sequence violation")
	ErrCorruptedQRPayload       = errors.New("corrupted or truncated QR payload checksum")
)

// DongleToken represents a cryptographically signed offline time-bound license token.
type DongleToken struct {
	TokenID    string   `json:"token_id"`
	LicenseKey string   `json:"license_key"`
	HWID       string   `json:"hwid"`
	Tier       string   `json:"tier"`
	Features   []string `json:"features,omitempty"`
	MaxDevices int      `json:"max_devices"`
	IssuedAt   int64    `json:"issued_at"`
	ExpiresAt  int64    `json:"expires_at"`
	Counter    int64    `json:"counter"`
	Signature  string   `json:"signature"`
	PublicKey  string   `json:"public_key"`
}

// IssueTokenRequest defines parameters for generating a new offline dongle token.
type IssueTokenRequest struct {
	LicenseKey string   `json:"license_key"`
	HWID       string   `json:"hwid"`
	Tier       string   `json:"tier"`
	DaysValid  int      `json:"days_valid"`
	MaxDevices int      `json:"max_devices"`
	Features   []string `json:"features,omitempty"`
}

// ActivationRequest encapsulates an air-gapped machine's offline activation challenge.
type ActivationRequest struct {
	RequestID           string `json:"request_id"`
	LicenseKey          string `json:"license_key"`
	HWID                string `json:"hwid"`
	CurrentTimestamp    int64  `json:"current_timestamp"`
	Nonce               string `json:"nonce"`
	HardwareFingerprint string `json:"hardware_fingerprint,omitempty"`
	Signature           string `json:"signature,omitempty"`
}

// ActivationResponse encapsulates the fulfilled activation data delivered via QR code or file.
type ActivationResponse struct {
	RequestID   string `json:"request_id"`
	LicenseKey  string `json:"license_key"`
	HWID        string `json:"hwid"`
	DongleToken string `json:"dongle_token"`
	QRPayload   string `json:"qr_payload"`
	ValidUntil  int64  `json:"valid_until"`
	Counter     int64  `json:"counter"`
	Status      string `json:"status"`
	Signature   string `json:"signature"`
}

// RollbackState represents the monotonic clock and tamper status for a given vault or hardware ID.
type RollbackState struct {
	VaultID          string `json:"vault_id"`
	HWID             string `json:"hwid"`
	HighWaterMark    int64  `json:"high_water_mark"`
	MonotonicCounter int64  `json:"monotonic_counter"`
	Tampered         bool   `json:"tampered"`
	TamperedReason   string `json:"tampered_reason,omitempty"`
	TrippedAt        int64  `json:"tripped_at,omitempty"`
	UnlockedAt       int64  `json:"unlocked_at,omitempty"`
}

// UnlockToken represents an administrative recovery token signed by the master admin key.
type UnlockToken struct {
	VaultID        string `json:"vault_id"`
	HWID           string `json:"hwid"`
	Nonce          string `json:"nonce"`
	Timestamp      int64  `json:"timestamp"`
	AdminSignature string `json:"admin_signature"`
}

// UnlockRequest defines parameters for restoring a tripped airgap vault.
type UnlockRequest struct {
	VaultID        string `json:"vault_id"`
	HWID           string `json:"hwid"`
	Nonce          string `json:"nonce"`
	Timestamp      int64  `json:"timestamp"`
	AdminSignature string `json:"admin_signature"`
}

// AirgapStatus encapsulates operational telemetry and diagnostic metrics for the air-gap subsystem.
type AirgapStatus struct {
	VaultActive          bool      `json:"vault_active"`
	MasterPublicKey      string    `json:"master_public_key"`
	AdminPublicKey       string    `json:"admin_public_key"`
	TotalIssuedTokens    int64     `json:"total_issued_tokens"`
	TotalVerifiedTokens  int64     `json:"total_verified_tokens"`
	TotalActivations     int64     `json:"total_activations"`
	RollbackTrippedCount int64     `json:"rollback_tripped_count"`
	LastHighWaterMark    int64     `json:"last_high_water_mark"`
	TrackedVaults        int       `json:"tracked_vaults"`
	Timestamp            time.Time `json:"timestamp"`
}
