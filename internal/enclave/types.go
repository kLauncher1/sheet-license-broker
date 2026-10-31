package enclave

import (
	"time"
)

// PlatformType identifies the hardware confidential computing environment.
type PlatformType string

const (
	PlatformSGX    PlatformType = "intel_sgx"
	PlatformSEVSNP PlatformType = "amd_sev_snp"
	PlatformTDX    PlatformType = "intel_tdx"
)

// SGXReport represents the core measured properties of an Intel SGX enclave.
type SGXReport struct {
	CPUSVN     [16]byte `json:"cpu_svn"`
	MiscSelect uint32   `json:"misc_select"`
	Attributes [16]byte `json:"attributes"` // bit 0 = initialized, bit 1 = debug
	MREnclave  [32]byte `json:"mr_enclave"` // SHA-256 measurement of code/pages
	MRSigner   [32]byte `json:"mr_signer"`  // SHA-256 measurement of signer key
	ISVProdID  uint16   `json:"isv_prod_id"`
	ISVSVN     uint16   `json:"isv_svn"`
	ReportData [64]byte `json:"report_data"` // 64 bytes user-supplied data (e.g., nonce/key hash)
}

// SGXQuoteV3 models an Intel SGX ECDSA Quote (version 3/4).
type SGXQuoteV3 struct {
	Version            uint16    `json:"version"`
	AttestationKeyType uint16    `json:"attestation_key_type"`
	TeeType            uint32    `json:"tee_type"`
	QESVN              uint16    `json:"qe_svn"`
	PCESVN             uint16    `json:"pce_svn"`
	VendorID           [16]byte  `json:"vendor_id"`
	UserData           [20]byte  `json:"user_data"`
	EnclaveReport      SGXReport `json:"enclave_report"`
	Signature          []byte    `json:"signature"`
	AttestationKey     []byte    `json:"attestation_key"` // ECDSA P-256 public key (64 bytes: X || Y)
}

// SEVSNPReport models an AMD Secure Encrypted Virtualization-Secure Nested Paging attestation report.
type SEVSNPReport struct {
	Version        uint32   `json:"version"`
	GuestSVN       uint32   `json:"guest_svn"`
	Policy         uint64   `json:"policy"` // bit 19 = debug disallowed
	FamilyID       [16]byte `json:"family_id"`
	ImageID        [16]byte `json:"image_id"`
	VMPL           uint32   `json:"vmpl"`
	SignatureAlgo  uint32   `json:"signature_algo"`
	CurrentTCB     uint64   `json:"current_tcb"`
	ReportData     [64]byte `json:"report_data"`
	Measurement    [48]byte `json:"measurement"` // SHA-384 or SHA-256 launch measurement
	HostData       [32]byte `json:"host_data"`
	IDKeyDigest    [48]byte `json:"id_key_digest"`
	AuthorKeyDigest [48]byte `json:"author_key_digest"`
	ReportID       [32]byte `json:"report_id"`
	ReportIDMA     [32]byte `json:"report_id_ma"`
	ReportTCB      uint64   `json:"report_tcb"`
	ChipID         [64]byte `json:"chip_id"`
	Signature      []byte   `json:"signature"`
}

// TDXReport models the Trust Domain execution report from Intel TDX hardware.
type TDXReport struct {
	TeeType        uint32      `json:"tee_type"`        // 0x00000081 (Intel TDX)
	TeeTcbSvn      [16]byte    `json:"tee_tcb_svn"`     // Security Version Numbers of TDX TEE components
	MRSeam         [48]byte    `json:"mr_seam"`         // SHA-384 measurement of Intel SEAM module
	MRSignerSeam   [48]byte    `json:"mr_signer_seam"`  // SHA-384 measurement of SEAM signer
	SeamAttributes [8]byte     `json:"seam_attributes"` // Attributes of SEAM module
	TDAttributes   [8]byte     `json:"td_attributes"`   // Bit 0: DEBUG (must be 0 in production), Bit 30: PKS
	XFAM           [8]byte     `json:"xfam"`            // Extended Features Allowed Mask
	MRTD           [48]byte    `json:"mrtd"`            // SHA-384 initial guest memory & vCPU measurement
	RTMR           [4][48]byte `json:"rtmr"`            // 4 Runtime Measurement Registers (SHA-384)
	ReportData     [64]byte    `json:"report_data"`     // 64-byte user report data (e.g., nonce / key binding)
}

// TDXQuoteV4 represents an Intel TDX Quote (Version 4 format).
type TDXQuoteV4 struct {
	Version            uint16    `json:"version"`              // 4
	AttestationKeyType uint16    `json:"attestation_key_type"` // 2 = ECDSA P-256, 3 = ECDSA P-384
	TeeType            uint32    `json:"tee_type"`             // 0x00000081
	QESVN              uint16    `json:"qe_svn"`
	PCESVN             uint16    `json:"pce_svn"`
	VendorID           [16]byte  `json:"vendor_id"`
	UserData           [20]byte  `json:"user_data"`
	Report             TDXReport `json:"report"`
	Signature          []byte    `json:"signature"`
	AttestationKey     []byte    `json:"attestation_key"` // ECDSA public key
}

// EnclavePolicy defines authorization constraints for acceptable hardware enclaves.
type EnclavePolicy struct {
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	Platform            PlatformType `json:"platform"`
	AllowedMREnclaves   []string     `json:"allowed_mr_enclaves,omitempty"`   // Hex-encoded SHA-256
	AllowedMRSigners    []string     `json:"allowed_mr_signers,omitempty"`    // Hex-encoded SHA-256
	AllowedMeasurements []string     `json:"allowed_measurements,omitempty"`  // Hex-encoded launch digests
	MinISVSVN           uint16       `json:"min_isv_svn"`
	MinGuestSVN         uint32       `json:"min_guest_svn"`
	AllowDebug          bool         `json:"allow_debug"`                     // Strict false in production
	RequiredHostData    string       `json:"required_host_data,omitempty"`
	CreatedAt           time.Time    `json:"created_at"`
	UpdatedAt           time.Time    `json:"updated_at"`
}

// AttestationResult contains the outcome of an enclave quote verification.
type AttestationResult struct {
	Valid          bool         `json:"valid"`
	Platform       PlatformType `json:"platform"`
	MREnclave      string       `json:"mr_enclave,omitempty"`
	MRSigner       string       `json:"mr_signer,omitempty"`
	Measurement    string       `json:"measurement,omitempty"`
	MRTD           string       `json:"mrtd,omitempty"`
	RTMR0          string       `json:"rtmr0,omitempty"`
	SVN            uint32       `json:"svn"`
	Debug          bool         `json:"debug"`
	ReportDataHex  string       `json:"report_data_hex"`
	ErrorMessage   string       `json:"error_message,omitempty"`
	VerifiedAt     time.Time    `json:"verified_at"`
}

// EncryptedTunnelMessage represents an encrypted packet transmitted across the enclave tunnel.
type EncryptedTunnelMessage struct {
	SessionID  string `json:"session_id"`
	Sequence   uint64 `json:"sequence"`
	NonceHex   string `json:"nonce_hex"`      // 12-byte GCM nonce in hex
	PayloadHex string `json:"payload_hex"`    // Ciphertext + 16-byte authentication tag in hex
}

// EnclaveEvalPayload models the plaintext query decrypted strictly in zero-plaintext enclave memory.
type EnclaveEvalPayload struct {
	LicenseKey       string `json:"license_key"`
	HWID             string `json:"hwid"`
	RequestedFeature string `json:"requested_feature,omitempty"`
	Timestamp        int64  `json:"timestamp"`
}

// EnclaveEvalResponse models the evaluation verdict before re-encryption for the client enclave.
type EnclaveEvalResponse struct {
	Valid                   bool     `json:"valid"`
	LicenseKey              string   `json:"license_key"`
	Tier                    string   `json:"tier,omitempty"`
	Features                []string `json:"features,omitempty"`
	ExpiresAt               string   `json:"expires_at,omitempty"`
	EnclavePlatform         string   `json:"enclave_platform"`
	ZeroPlaintextGuarantee bool     `json:"zero_plaintext_guarantee"`
	EvaluatedAt             string   `json:"evaluated_at"`
	Message                 string   `json:"message,omitempty"`
}

// EnclaveTelemetry captures operational statistics across the confidential computing subsystem.
type EnclaveTelemetry struct {
	VerifiedQuotes      int64            `json:"verified_quotes"`
	ActiveTunnels       int64            `json:"active_tunnels"`
	TotalEvaluations    int64            `json:"total_evaluations"`
	FailedAttestations  int64            `json:"failed_attestations"`
	QuotesByPlatform    map[string]int64 `json:"quotes_by_platform"`
	ActivePoliciesCount int              `json:"active_policies_count"`
	ActiveTokensCount   int              `json:"active_tokens_count"`
	IsolatedDecryptions int64            `json:"isolated_decryptions"`
}

// AttestationToken represents a signed binding between hardware measurements, SVN, nonce, and session.
type AttestationToken struct {
	TokenID        string       `json:"token_id"`
	Platform       PlatformType `json:"platform"`
	Measurement    string       `json:"measurement"`    // Hex measurement (SEV launch digest or TDX MRTD)
	RTMR0          string       `json:"rtmr0,omitempty"` // TDX RTMR[0]
	SVN            uint32       `json:"svn"`            // GuestSVN or TeeTcbSvn
	DebugAllowed   bool         `json:"debug_allowed"`
	ChallengeNonce string       `json:"challenge_nonce"`
	EnclavePubKey  string       `json:"enclave_pub_key,omitempty"` // Hex public key
	IssuedAt       time.Time    `json:"issued_at"`
	ExpiresAt      time.Time    `json:"expires_at"`
	Signature      string       `json:"signature"` // Hex HMAC-SHA256 signature by Broker Root
}

// TokenVerifyResult models the outcome of validating an attestation token.
type TokenVerifyResult struct {
	Valid        bool              `json:"valid"`
	Token        *AttestationToken `json:"token,omitempty"`
	Platform     PlatformType      `json:"platform,omitempty"`
	SVN          uint32            `json:"svn,omitempty"`
	Measurement  string            `json:"measurement,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
}

// IsolatedDecryptionRequest specifies an encrypted license payload to be decrypted
// strictly inside attested hardware-isolated enclave memory.
type IsolatedDecryptionRequest struct {
	Platform            PlatformType `json:"platform"`
	EnclaveToken        string       `json:"attestation_token"`
	EncryptedPayloadHex string       `json:"encrypted_payload_hex"`
	NonceHex            string       `json:"nonce_hex"`
	SessionID           string       `json:"session_id,omitempty"`
}

// IsolatedDecryptionResult reports the outcome of the in-enclave evaluation without exposing cleartext.
type IsolatedDecryptionResult struct {
	Success               bool         `json:"success"`
	LicenseKeyMasked      string       `json:"license_key_masked"`
	Tier                  string       `json:"tier"`
	Features              []string     `json:"features"`
	ExpiresAt             string       `json:"expires_at"`
	Platform              PlatformType `json:"platform"`
	SVN                   uint32       `json:"svn"`
	HardwareIsolated      bool         `json:"hardware_isolated"`
	MemoryZeroized        bool         `json:"memory_zeroized"`
	ExecutionTimeMicrosec int64        `json:"execution_time_us"`
	EvaluationDigest      string       `json:"evaluation_digest"` // SHA-256 of verdict
	EvaluatedAt           time.Time    `json:"evaluated_at"`
	ErrorMessage          string       `json:"error_message,omitempty"`
}
