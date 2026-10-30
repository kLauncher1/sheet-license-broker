package mlkem

import (
	"crypto/ecdsa"
	"time"
)

// Supported ML-KEM algorithm identifiers and hybrid exchange modes.
const (
	AlgoMLKEM768            = "ML-KEM-768"
	AlgoMLKEM1024           = "ML-KEM-1024"
	AlgoHybridP256MLKEM768  = "Hybrid-ECDH-P256-MLKEM768"
	AlgoHybridP256MLKEM1024 = "Hybrid-ECDH-P256-MLKEM1024"
	ModeHybrid              = "hybrid"
	ModePQC                 = "pqc-only"
	ModeFallback            = "classical-fallback"
)

// Mathematical constants for NIST FIPS 203 (CRYSTALS-Kyber / ML-KEM).
const (
	DegreeN  = 256  // Ring dimension N = 256
	ModulusQ = 3329 // Modulus q = 3329
)

// Poly represents a polynomial in R_q = Z_q[X]/(X^256 + 1).
type Poly [DegreeN]int16

// PolyVec represents a vector of polynomials in R_q.
type PolyVec []Poly

// Params defines the lattice parameters for an ML-KEM security parameter set.
type Params struct {
	Name string
	K    int // Vector dimension (3 for 768, 4 for 1024)
	Eta1 int // CBD noise parameter 1
	Eta2 int // CBD noise parameter 2
	Du   int // Compression bit width for vector u
	Dv   int // Compression bit width for polynomial v
}

// GetParams returns the NIST FIPS 203 lattice parameters for the requested algorithm.
func GetParams(algo string) Params {
	switch algo {
	case AlgoMLKEM1024, AlgoHybridP256MLKEM1024:
		return Params{
			Name: AlgoMLKEM1024,
			K:    4,
			Eta1: 2,
			Eta2: 2,
			Du:   11,
			Dv:   5,
		}
	default: // Default is ML-KEM-768 (NIST Security Category 3)
		return Params{
			Name: AlgoMLKEM768,
			K:    3,
			Eta1: 2,
			Eta2: 2,
			Du:   10,
			Dv:   4,
		}
	}
}

// PublicKey represents an ML-KEM public encapsulation key.
type PublicKey struct {
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"algorithm"`
	Fingerprint string    `json:"fingerprint"`
	T           PolyVec   `json:"-"`
	Rho         [32]byte  `json:"-"`
	H_ek        [32]byte  `json:"-"`
	RawHex      string    `json:"raw_hex"`
	CreatedAt   time.Time `json:"created_at"`
}

// PrivateKey represents an ML-KEM private decapsulation key.
type PrivateKey struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	S         PolyVec    `json:"-"`
	PublicKey *PublicKey `json:"public_key"`
	H_ek      [32]byte   `json:"-"`
	Z         [32]byte   `json:"-"` // Implicit rejection pseudorandom seed
	CreatedAt time.Time  `json:"created_at"`
}

// EncapsulationResult holds the ciphertext and established shared secret.
type EncapsulationResult struct {
	KeyID           string    `json:"key_id"`
	Algorithm       string    `json:"algorithm"`
	CiphertextHex   string    `json:"ciphertext_hex"`
	SharedSecretHex string    `json:"shared_secret_hex"`
	EncapsulatedAt  time.Time `json:"encapsulated_at"`
}

// HybridHandshakeRequest represents client parameters for post-quantum hybrid exchange.
type HybridHandshakeRequest struct {
	ClientECDHPublicKey string `json:"client_ecdh_pub_hex"`
	ClientMLKEMKeyID    string `json:"client_mlkem_key_id,omitempty"`
	RequestedMode       string `json:"requested_mode,omitempty"`
	Algorithm           string `json:"algorithm,omitempty"`
	ClientNonce         string `json:"client_nonce,omitempty"`
}

// HybridHandshakeResponse represents server confirmation for hybrid session establishment.
type HybridHandshakeResponse struct {
	SessionID           string    `json:"session_id"`
	ServerECDHPublicKey string    `json:"server_ecdh_pub_hex"`
	CiphertextHex       string    `json:"ciphertext_hex"`
	AuthTagHex          string    `json:"auth_tag_hex"`
	AgreedMode          string    `json:"agreed_mode"`
	Algorithm           string    `json:"algorithm"`
	QuantumResistant    bool      `json:"quantum_resistant"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// HybridSession represents an active ephemeral session with forward secrecy.
type HybridSession struct {
	SessionID        string    `json:"session_id"`
	AgreedMode       string    `json:"agreed_mode"`
	Algorithm        string    `json:"algorithm"`
	QuantumResistant bool      `json:"quantum_resistant"`
	SessionKeyHex    string    `json:"-"`
	SessionKeyBytes  []byte    `json:"-"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// MLKEMStatus represents real-time operational telemetry for ML-KEM and hybrid exchange.
type MLKEMStatus struct {
	Initialized          bool      `json:"initialized"`
	ActiveKeysCount      int       `json:"active_keys_count"`
	DefaultAlgorithm     string    `json:"default_algorithm"`
	ActiveSessionsCount  int       `json:"active_sessions_count"`
	QuantumEnforced      bool      `json:"quantum_enforced"`
	TotalEncapsulations  int64     `json:"total_encapsulations"`
	TotalDecapsulations  int64     `json:"total_decapsulations"`
	TotalHandshakes      int64     `json:"total_handshakes"`
	FallbackAttempts     int64     `json:"fallback_attempts"`
	FallbackRejected     int64     `json:"fallback_rejected"`
	LastHandshakeAt      time.Time `json:"last_handshake_at,omitempty"`
	UptimeSeconds        int64     `json:"uptime_seconds"`
}

// EphemeralECDHKeyPair holds ephemeral P-256 ECDH keys.
type EphemeralECDHKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
}
