package attestation

import (
	"time"
)

// AttestationType defines the hardware or platform attestation mechanism used.
type AttestationType string

const (
	TypeTPM2            AttestationType = "tpm2"
	TypeSecureEnclave   AttestationType = "secure_enclave"
	TypeWindowsHello    AttestationType = "windows_hello"
	TypeSoftwareEmulate AttestationType = "software_emulated"
)

// TrustLevel represents the verified hardware security status of an endpoint.
type TrustLevel string

const (
	TrustUnverified       TrustLevel = "unverified"
	TrustAttestedHardware TrustLevel = "attested_hardware"
	TrustAttestedEnclave  TrustLevel = "attested_enclave"
	TrustSoftwareGrace    TrustLevel = "software_grace"
	TrustTampered         TrustLevel = "tampered"
)

// PCRQuote models a TPM 2.0 PCR quote structure signed by an Attestation Key (AK).
type PCRQuote struct {
	PCRValues       map[int]string `json:"pcr_values"`        // PCR index -> hex-encoded SHA-256 digest
	PCRSelection    []int          `json:"pcr_selection"`     // Selected PCR bank indices (e.g. [0, 1, 2, 7])
	CompositeDigest string         `json:"composite_digest"`  // Hex-encoded SHA-256 digest over PCRs + Nonce
	Signature       string         `json:"signature"`         // Hex-encoded ECDSA or RSA signature over composite
	AKPublicKeyPEM  string         `json:"ak_public_key_pem"` // PEM-encoded public Attestation Key
}

// EnclaveAttestation models an Apple Secure Enclave or Windows Hello cryptographic assertion.
type EnclaveAttestation struct {
	EnclaveType   AttestationType `json:"enclave_type"`    // "secure_enclave" or "windows_hello"
	PublicKeyPEM  string          `json:"public_key_pem"`  // Hardware-bound public key PEM
	AttestReceipt string          `json:"attest_receipt"`  // Base64-encoded platform attestation certificate/receipt
	Signature     string          `json:"signature"`       // Hex-encoded signature over Nonce
	Counter       uint64          `json:"counter"`         // Monotonic counter preventing replay
}

// TelemetryReport encapsulates client-side anti-debugging and memory integrity telemetry.
type TelemetryReport struct {
	DebuggerPresent  bool      `json:"debugger_present"`  // Is PEB BeingDebugged or CheckRemoteDebuggerPresent true?
	MemoryIntegrity  bool      `json:"memory_integrity"`  // Are code sections unmodified from disk binary?
	SandboxDetected  bool      `json:"sandbox_detected"`  // Are known sandbox artifacts or hypervisors detected?
	HooksDetected    bool      `json:"hooks_detected"`    // Are standard win32/libc syscalls hooked or detoured?
	ProcessChecksum  string    `json:"process_checksum"`  // SHA-256 hash of active memory text section
	ExecutionUptimeS int64     `json:"execution_uptime_s"`// Client uptime in seconds
	Timestamp        time.Time `json:"timestamp"`
}

// AttestationChallenge stores a single-use cryptographically random challenge for quote binding.
type AttestationChallenge struct {
	ChallengeID string    `json:"challenge_id"`
	LicenseKey  string    `json:"license_key"`
	HWID        string    `json:"hwid"`
	Nonce       string    `json:"nonce"`      // 32-byte hex-encoded random nonce
	ExpiresAt   time.Time `json:"expires_at"`
	Consumed    bool      `json:"consumed"`
}

// AttestationRecord records the verified attestation state for a license and hardware device.
type AttestationRecord struct {
	LicenseKey      string          `json:"license_key"`
	HWID            string          `json:"hwid"`
	AttestationType AttestationType `json:"attestation_type"`
	TrustLevel      TrustLevel      `json:"trust_level"`
	PCRDigest       string          `json:"pcr_digest,omitempty"`
	AKPublicHash    string          `json:"ak_public_hash"`
	LastNonce       string          `json:"last_nonce"`
	VerifiedAt      time.Time       `json:"verified_at"`
	TamperScore     int             `json:"tamper_score"` // 0 = pristine, 100 = critical tamper
	Details         string          `json:"details,omitempty"`
}
