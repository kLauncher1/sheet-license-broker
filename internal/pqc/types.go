package pqc

import (
	"crypto/ecdsa"
	"time"
)

// Supported Post-Quantum Cryptography algorithms and hybrid modes.
const (
	AlgoMLDSA44        = "ML-DSA-44"
	AlgoMLDSA65        = "ML-DSA-65"
	AlgoMLDSA87        = "ML-DSA-87"
	AlgoHybridP256     = "Hybrid-P256-MLDSA65"
	AlgoHybridHMAC     = "Hybrid-HMAC-MLDSA44"
)

// Mathematical constants for ML-DSA (NIST FIPS 204 / CRYSTALS-Dilithium).
const (
	DegreeN = 256     // Polynomial ring degree N = 256
	ModulusQ = 8380417 // Prime modulus q = 2^23 - 2^13 + 1
	PowerD   = 13      // Dropped bits in Power2Round
)

// Poly represents a single polynomial in R_q = Z_q[X]/(X^256 + 1).
type Poly [DegreeN]int32

// PolyVec represents a vector of polynomials in R_q.
type PolyVec []Poly

// Params holds the structural lattice parameters for an ML-DSA security level.
type Params struct {
	Name    string
	K       int   // Matrix height
	L       int   // Matrix width
	Eta     int32 // Secret vector bound
	Gamma1  int32 // Masking vector bound (2^17 or 2^19)
	Gamma2  int32 // Low-order rounding modulus ((q-1)/88 or (q-1)/32)
	Beta    int32 // Rejection sampling bound
	Tau     int   // Number of +/- 1 coefficients in challenge polynomial
	Omega   int   // Maximum number of 1s in hint vector
}

// GetParams returns the NIST FIPS 204 parameters for the requested algorithm.
func GetParams(algo string) Params {
	switch algo {
	case AlgoMLDSA44, AlgoHybridHMAC:
		return Params{
			Name:   AlgoMLDSA44,
			K:      4,
			L:      4,
			Eta:    2,
			Gamma1: 1 << 17, // 131072
			Gamma2: (ModulusQ - 1) / 88, // 95232
			Beta:   78,
			Tau:    39,
			Omega:  80,
		}
	case AlgoMLDSA87:
		return Params{
			Name:   AlgoMLDSA87,
			K:      8,
			L:      7,
			Eta:    2,
			Gamma1: 1 << 19, // 524288
			Gamma2: (ModulusQ - 1) / 32, // 261888
			Beta:   120,
			Tau:    60,
			Omega:  75,
		}
	default: // Default is ML-DSA-65 (NIST Level 3)
		return Params{
			Name:   AlgoMLDSA65,
			K:      6,
			L:      5,
			Eta:    4,
			Gamma1: 1 << 19, // 524288
			Gamma2: (ModulusQ - 1) / 32, // 261888
			Beta:   196,
			Tau:    49,
			Omega:  55,
		}
	}
}

// MLDSAPublicKey represents an ML-DSA lattice public key.
type MLDSAPublicKey struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	Rho       [32]byte  `json:"-"`
	T1        PolyVec   `json:"-"`
	RawHex    string    `json:"raw_hex"`
	CreatedAt time.Time `json:"created_at"`
}

// MLDSAPrivateKey represents an ML-DSA lattice private key.
type MLDSAPrivateKey struct {
	KeyID     string          `json:"key_id"`
	Algorithm string          `json:"algorithm"`
	Rho       [32]byte        `json:"-"`
	K         [32]byte        `json:"-"`
	S1        PolyVec         `json:"-"`
	S2        PolyVec         `json:"-"`
	T0        PolyVec         `json:"-"`
	PublicKey *MLDSAPublicKey `json:"public_key"`
}

// MLDSASignature represents a serialized lattice digital signature (c, z, h).
type MLDSASignature struct {
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Challenge [32]byte  `json:"challenge"`
	Z         PolyVec   `json:"-"`
	Hints     [][]int   `json:"hints"`
	RawHex    string    `json:"raw_hex"`
}

// HybridSignature holds dual classical and quantum-resistant signature tokens.
type HybridSignature struct {
	Algorithm    string    `json:"algorithm"`
	KeyID        string    `json:"key_id"`
	ClassicalSig string    `json:"classical_sig"` // ECDSA DER hex or HMAC hex
	QuantumSig   string    `json:"quantum_sig"`   // Raw ML-DSA signature hex
	Timestamp    string    `json:"timestamp"`
	Epoch        uint64    `json:"epoch"`
	PayloadHash  string    `json:"payload_hash"`
}

// HybridKeyPair binds a classical key pair with an ML-DSA post-quantum key pair.
type HybridKeyPair struct {
	KeyID         string             `json:"key_id"`
	Algorithm     string             `json:"algorithm"`
	ECDSAKey      *ecdsa.PrivateKey  `json:"-"`
	HMACSecret    []byte             `json:"-"`
	MLDSAKey      *MLDSAPrivateKey   `json:"-"`
	MLDSAPublic   *MLDSAPublicKey    `json:"mldsa_public"`
	ECDSAPublicX  string             `json:"ecdsa_public_x,omitempty"`
	ECDSAPublicY  string             `json:"ecdsa_public_y,omitempty"`
	Status        string             `json:"status"` // active, rotated, revoked
	CreatedAt     time.Time          `json:"created_at"`
	RotatedAt     *time.Time         `json:"rotated_at,omitempty"`
	GraceUntil    *time.Time         `json:"grace_until,omitempty"`
	RevokedAt     *time.Time         `json:"revoked_at,omitempty"`
	RevokeReason  string             `json:"revoke_reason,omitempty"`
}

// KeyRotationRecord documents key rotation history for audit trails.
type KeyRotationRecord struct {
	OldKeyID     string    `json:"old_key_id"`
	NewKeyID     string    `json:"new_key_id"`
	Algorithm    string    `json:"algorithm"`
	RotatedAt    time.Time `json:"rotated_at"`
	GraceUntil   time.Time `json:"grace_until"`
	Reason       string    `json:"reason"`
	Status       string    `json:"status"`
}

// PQCVerificationResult summarizes the outcome of a hybrid or quantum signature check.
type PQCVerificationResult struct {
	Valid          bool   `json:"valid"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id"`
	ClassicalValid bool   `json:"classical_valid"`
	QuantumValid   bool   `json:"quantum_valid"`
	GraceActive    bool   `json:"grace_active"`
	ErrorMessage   string `json:"error_message,omitempty"`
	LatencyNs      int64  `json:"latency_ns"`
}

// PQCStatusSummary provides operational health telemetry for the PQC engine.
type PQCStatusSummary struct {
	ActiveKeyID        string   `json:"active_key_id"`
	DefaultAlgorithm   string   `json:"default_algorithm"`
	TotalKeys          int      `json:"total_keys"`
	RotatedKeysInGrace int      `json:"rotated_keys_in_grace"`
	RevokedKeys        int      `json:"revoked_keys"`
	TotalRotations     int      `json:"total_rotations"`
	VerifiedCount      uint64   `json:"verified_signatures"`
	RejectedCount      uint64   `json:"rejected_signatures"`
	SupportedAlgorithms []string `json:"supported_algorithms"`
}
