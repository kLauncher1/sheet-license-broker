package enclave

import (
	"time"
)

// PlatformType identifies the hardware confidential computing environment.
type PlatformType string

const (
	PlatformSGX    PlatformType = "intel_sgx"
	PlatformSEVSNP PlatformType = "amd_sev_snp"
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
}
