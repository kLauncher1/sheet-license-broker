package proxy

import (
	"errors"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrLicenseInvalid    = errors.New("invalid or expired license")
)

// ProxyConfig defines construction options for the proxy coordinator.
type ProxyConfig struct {
	WebAppURL        string
	StandbyWebAppURL string
	OfflineMode      bool
	CacheTTL         time.Duration
	GlobalWebhookURL string
	GlobalSecret     string
	SpoolPath        string
	SpoolSecret      string
	DiscordAlertURL  string
	SlackAlertURL    string
	AutoFailover     bool
	NodeID           string
	ClusterRegion    string
	ClusterAddress   string
	ClusterPeers     []string
	StripeWebhookSecret       string
	LemonSqueezyWebhookSecret string
	PaddleWebhookSecret       string
}

// VerifyResult captures the unified result of a license check.
type VerifyResult struct {
	Valid      bool     `json:"valid"`
	LicenseKey string   `json:"license_key"`
	HWIDBound  string   `json:"hwid_bound"`
	ExpiresAt  string   `json:"expires_at"`
	Tier       string   `json:"tier,omitempty"`
	Features   []string `json:"features,omitempty"`
	Source     string   `json:"source"` // "cache", "remote_gas", "local_fallback", "offline_cache"
	Message    string   `json:"message,omitempty"`
}

// LicenseResult captures unified license creation outcome.
type LicenseResult struct {
	LicenseKey string   `json:"license_key"`
	ExpiresAt  string   `json:"expires_at"`
	Status     string   `json:"status"`
	Tier       string   `json:"tier,omitempty"`
	Features   []string `json:"features,omitempty"`
	Source     string   `json:"source"`
}
