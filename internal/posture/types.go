package posture

import (
	"time"
)

// PostureTier classifies the client device trust level.
type PostureTier string

const (
	PostureTierHealthy    PostureTier = "healthy"
	PostureTierWarning    PostureTier = "warning"
	PostureTierQuarantine PostureTier = "quarantine"
)

// OSVectorReport encapsulates operating system version and security patch telemetry.
type OSVectorReport struct {
	OSName             string `json:"os_name"`
	OSVersion          string `json:"os_version"`
	KernelVersion      string `json:"kernel_version"`
	PatchLevelDays     int    `json:"patch_level_days"`
	MinPatchLevelDays  int    `json:"min_patch_level_days"`
}

// HardwareVectorReport captures hardware-level root of trust and firmware security.
type HardwareVectorReport struct {
	SecureBootEnabled    bool   `json:"secure_boot_enabled"`
	TPMPresent           bool   `json:"tpm_present"`
	TPMVersion           string `json:"tpm_version"`
	DiskEncryptionActive bool   `json:"disk_encryption_active"`
}

// EndpointVectorReport details local anti-malware and host firewall defenses.
type EndpointVectorReport struct {
	AntivirusActive     bool `json:"antivirus_active"`
	DefinitionsAgeDays  int  `json:"definitions_age_days"`
	RealtimeProtection  bool `json:"realtime_protection"`
	FirewallEnabled     bool `json:"firewall_enabled"`
}

// IntegrityVectorReport audits execution runtime anti-tamper and anti-debugging signals.
type IntegrityVectorReport struct {
	DebuggerAttached       bool `json:"debugger_attached"`
	RootedOrJailbroken     bool `json:"rooted_or_jailbroken"`
	VirtualizationDetected bool `json:"virtualization_detected"`
	CodeIntegrityVerified  bool `json:"code_integrity_verified"`
}

// DevicePostureReport represents the comprehensive client-submitted posture payload.
type DevicePostureReport struct {
	DeviceID        string                `json:"device_id"`
	TenantID        string                `json:"tenant_id"`
	HWID            string                `json:"hwid"`
	OS              OSVectorReport        `json:"os"`
	Hardware        HardwareVectorReport  `json:"hardware"`
	Endpoint        EndpointVectorReport  `json:"endpoint"`
	Integrity       IntegrityVectorReport `json:"integrity"`
	Timestamp       int64                 `json:"timestamp"`
	ClientNonce     string                `json:"client_nonce"`
	ClientSignature string                `json:"client_signature"`
}

// PostureVectorScores details the evaluation breakdown, confidence score, and findings.
type PostureVectorScores struct {
	DeviceID            string      `json:"device_id"`
	TenantID            string      `json:"tenant_id"`
	OSScore             float64     `json:"os_score"`
	HardwareScore       float64     `json:"hardware_score"`
	EndpointScore       float64     `json:"endpoint_score"`
	IntegrityScore      float64     `json:"integrity_score"`
	CompositeScore      float64     `json:"composite_score"`
	Tier                PostureTier `json:"tier"`
	Violations          []string    `json:"violations"`
	Remediations        []string    `json:"remediations"`
	DegradedModeAllowed bool        `json:"degraded_mode_allowed"`
	EvaluatedAt         time.Time   `json:"evaluated_at"`
}

// StepUpChallenge represents a cryptographic challenge issued for step-up authentication.
type StepUpChallenge struct {
	ChallengeID     string    `json:"challenge_id"`
	DeviceID        string    `json:"device_id"`
	TenantID        string    `json:"tenant_id"`
	Nonce           string    `json:"nonce"`
	RequiredActions []string  `json:"required_actions"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Completed       bool      `json:"completed"`
}

// QuarantinedDevice stores metadata for an isolated untrusted device.
type QuarantinedDevice struct {
	DeviceID            string      `json:"device_id"`
	TenantID            string      `json:"tenant_id"`
	HWID                string      `json:"hwid"`
	Reason              string      `json:"reason"`
	CompositeScore      float64     `json:"composite_score"`
	Tier                PostureTier `json:"tier"`
	Violations          []string    `json:"violations"`
	QuarantinedAt       time.Time   `json:"quarantined_at"`
	DegradedModeAllowed bool        `json:"degraded_mode_allowed"`
	RemediationSteps    []string    `json:"remediation_steps"`
}

// PostureStatus provides an operational summary of device health and quarantine states.
type PostureStatus struct {
	ActivePolicies     int                   `json:"active_policies"`
	TotalEvaluations   int64                 `json:"total_evaluations"`
	HealthyCount       int64                 `json:"healthy_count"`
	WarningCount       int64                 `json:"warning_count"`
	QuarantineCount    int64                 `json:"quarantine_count"`
	DegradedCount      int64                 `json:"degraded_count"`
	RecentEvaluations  []PostureVectorScores `json:"recent_evaluations"`
	QuarantinedDevices []QuarantinedDevice   `json:"quarantined_devices"`
	Version            string                `json:"version"`
}
