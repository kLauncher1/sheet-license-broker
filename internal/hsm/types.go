package hsm

import (
	"time"
)

// Cryptoki mechanism definitions adhering to PKCS#11 v2.40 / v3.0 standards.
const (
	CKM_RSA_PKCS               = 0x00000001
	CKM_RSA_PKCS_OAEP          = 0x00000009
	CKM_ECDSA                  = 0x00001041
	CKM_ECDSA_SHA256           = 0x00001042
	CKM_AES_KEY_GEN            = 0x00001080
	CKM_AES_CBC_PAD            = 0x00001085
	CKM_AES_GCM                = 0x00001087
	CKM_SHA256_HMAC            = 0x00000251
	CKM_HKDF_DERIVE            = 0x00000392
	CKM_GENERIC_SECRET_KEY_GEN = 0x00000350
)

// Cryptoki object classes.
const (
	CKO_DATA         = 0x00000000
	CKO_CERTIFICATE  = 0x00000001
	CKO_PUBLIC_KEY   = 0x00000002
	CKO_PRIVATE_KEY  = 0x00000003
	CKO_SECRET_KEY   = 0x00000004
	CKO_HW_FEATURE   = 0x00000005
)

// Cryptoki key types.
const (
	CKK_RSA            = 0x00000000
	CKK_EC             = 0x00000003
	CKK_AES            = 0x0000001F
	CKK_GENERIC_SECRET = 0x00000010
)

// Cryptoki user types for PIN authentication.
const (
	CKU_SO   = 0x00000000 // Security Officer (Admin)
	CKU_USER = 0x00000001 // Regular Application User
)

// Cryptoki session states.
const (
	CKS_RO_PUBLIC_SESSION  = "RO_PUBLIC"
	CKS_RO_USER_FUNCTIONS  = "RO_USER"
	CKS_RW_PUBLIC_SESSION  = "RW_PUBLIC"
	CKS_RW_USER_FUNCTIONS  = "RW_USER"
	CKS_RW_SO_FUNCTIONS    = "RW_SO"
)

// Cryptoki error return codes.
const (
	CKR_OK                    = 0x00000000
	CKR_PIN_INCORRECT         = 0x000000A0
	CKR_PIN_LOCKED            = 0x000000A4
	CKR_SESSION_HANDLE_INVALID= 0x000000B3
	CKR_SLOT_ID_INVALID       = 0x00000003
	CKR_OBJECT_HANDLE_INVALID = 0x00000082
	CKR_MECHANISM_INVALID     = 0x00000070
	CKR_DEVICE_ERROR          = 0x00000030
	CKR_TAMPER_DETECTED       = 0x000000F0
)

// FIPS 140-3 Security Levels.
const (
	FIPSLevel1 = "FIPS_140_3_LEVEL_1"
	FIPSLevel2 = "FIPS_140_3_LEVEL_2"
	FIPSLevel3 = "FIPS_140_3_LEVEL_3"
	FIPSLevel4 = "FIPS_140_3_LEVEL_4"
)

// SlotInfo represents hardware cryptographic boundary metadata.
type SlotInfo struct {
	SlotID          int      `json:"slot_id"`
	Description     string   `json:"description"`
	ManufacturerID  string   `json:"manufacturer_id"`
	HardwareVersion string   `json:"hardware_version"`
	FirmwareVersion string   `json:"firmware_version"`
	Mechanisms      []string `json:"mechanisms"`
	TokenPresent    bool     `json:"token_present"`
	Removable       bool     `json:"removable"`
	HardwareSlot    bool     `json:"hardware_slot"`
}

// TokenInfo represents a cryptographic token hosted within a hardware slot.
type TokenInfo struct {
	SlotID             int       `json:"slot_id"`
	Label              string    `json:"label"`
	ManufacturerID     string    `json:"manufacturer_id"`
	Model              string    `json:"model"`
	SerialNumber       string    `json:"serial_number"`
	MaxSessionCount    int       `json:"max_session_count"`
	SessionCount       int       `json:"session_count"`
	MaxPinLen          int       `json:"max_pin_len"`
	MinPinLen          int       `json:"min_pin_len"`
	TotalPrivateMemory int       `json:"total_private_memory"`
	FreePrivateMemory  int       `json:"free_private_memory"`
	FIPSLevel          string    `json:"fips_level"`
	UserPinInitialized bool      `json:"user_pin_initialized"`
	UserPinLocked      bool      `json:"user_pin_locked"`
	SOPinLocked        bool      `json:"so_pin_locked"`
	TamperDetected     bool      `json:"tamper_detected"`
	InitializedAt      time.Time `json:"initialized_at"`
}

// SessionInfo represents an active session between an application and a token.
type SessionInfo struct {
	SessionHandle uint64    `json:"session_handle"`
	SlotID        int       `json:"slot_id"`
	State         string    `json:"state"`
	UserType      string    `json:"user_type,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	LastAccess    time.Time `json:"last_access"`
}

// ObjectAttributes models persistent or session cryptographic object attributes.
type ObjectAttributes struct {
	Handle       uint64 `json:"handle"`
	Class        uint32 `json:"class"`
	KeyType      uint32 `json:"key_type"`
	Label        string `json:"label"`
	Extractable  bool   `json:"extractable"`
	Sensitive    bool   `json:"sensitive"`
	TokenObject  bool   `json:"token_object"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Fingerprint  string `json:"fingerprint"`
}

// SelfTestResult stores Known Answer Test (KAT) verification telemetry.
type SelfTestResult struct {
	TestName         string `json:"test_name"`
	Passed           bool   `json:"passed"`
	ExecutionTimeUs  int64  `json:"execution_time_us"`
	AlgorithmTested  string `json:"algorithm_tested"`
	Details          string `json:"details"`
}

// FIPS140AuditReport provides structured certification and self-test evidence.
type FIPS140AuditReport struct {
	CertificationLevel string           `json:"certification_level"`
	HardwareModel      string           `json:"hardware_model"`
	SerialNumber       string           `json:"serial_number"`
	FirmwareRevision   string           `json:"firmware_revision"`
	TamperState        string           `json:"tamper_state"`
	ActiveSlots        int              `json:"active_slots"`
	KATPassed          bool             `json:"kat_passed"`
	SelfTests          []SelfTestResult `json:"self_tests"`
	ZeroizeOnTamper    bool             `json:"zeroize_on_tamper"`
	GeneratedAt        time.Time        `json:"generated_at"`
}

// HSMVaultStatus reports the comprehensive real-time status of the HSM engine.
type HSMVaultStatus struct {
	Initialized       bool      `json:"initialized"`
	HardwareAvailable bool      `json:"hardware_available"`
	FIPSLevel         string    `json:"fips_level"`
	SlotsTotal        int       `json:"slots_total"`
	ActiveSessions    int       `json:"active_sessions"`
	TamperDetected    bool      `json:"tamper_detected"`
	LockedOut         bool      `json:"locked_out"`
	MasterKeyPresent  bool      `json:"master_key_present"`
	OperationsCount   int64     `json:"operations_count"`
	LastSelfTest      time.Time `json:"last_self_test"`
	UptimeSeconds     int64     `json:"uptime_seconds"`
}

// KeyDerivationRequest specifies parameters for deriving keys within the HSM.
type KeyDerivationRequest struct {
	SlotID       int    `json:"slot_id"`
	Purpose      string `json:"purpose"`
	Context      string `json:"context"`
	SaltHex      string `json:"salt_hex,omitempty"`
	KeyLengthBits int   `json:"key_length_bits,omitempty"`
}

// KeyDerivationResponse contains metadata about a hardware-derived master key.
type KeyDerivationResponse struct {
	SlotID           int       `json:"slot_id"`
	Purpose          string    `json:"purpose"`
	DerivedKeyHandle uint64    `json:"derived_key_handle"`
	Fingerprint      string    `json:"fingerprint"`
	KeyLengthBits    int       `json:"key_length_bits"`
	Algorithm        string    `json:"algorithm"`
	DerivedAt        time.Time `json:"derived_at"`
}

// EnvelopeEncryptRequest specifies payload to encrypt under an HSM envelope.
type EnvelopeEncryptRequest struct {
	SlotID         int    `json:"slot_id"`
	Plaintext      string `json:"plaintext"`
	AssociatedData string `json:"associated_data,omitempty"`
	Purpose        string `json:"purpose,omitempty"`
}

// EnvelopeEncryptResponse holds an authenticated ciphertext generated by the HSM.
type EnvelopeEncryptResponse struct {
	SlotID         int       `json:"slot_id"`
	CiphertextHex  string    `json:"ciphertext_hex"`
	NonceHex       string    `json:"nonce_hex"`
	KeyFingerprint string    `json:"key_fingerprint"`
	Algorithm      string    `json:"algorithm"`
	EncryptedAt    time.Time `json:"encrypted_at"`
}

// EnvelopeDecryptRequest specifies an HSM envelope ciphertext for decryption.
type EnvelopeDecryptRequest struct {
	SlotID         int    `json:"slot_id"`
	CiphertextHex  string `json:"ciphertext_hex"`
	NonceHex       string `json:"nonce_hex"`
	AssociatedData string `json:"associated_data,omitempty"`
	Purpose        string `json:"purpose,omitempty"`
}

// EnvelopeDecryptResponse holds decrypted plaintext from the HSM envelope.
type EnvelopeDecryptResponse struct {
	SlotID        int       `json:"slot_id"`
	Plaintext     string    `json:"plaintext"`
	Authenticated bool      `json:"authenticated"`
	DecryptedAt   time.Time `json:"decrypted_at"`
}
