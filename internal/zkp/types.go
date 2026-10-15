package zkp

import (
	"crypto/ecdsa"
	"math/big"
	"time"
)

// Tier constants for privacy-preserving entitlements.
const (
	TierFree       = 1
	TierPro        = 2
	TierEnterprise = 3
)

// TierName maps integer tier levels to human-readable names.
func TierName(tier int) string {
	switch tier {
	case TierEnterprise:
		return "enterprise"
	case TierPro:
		return "pro"
	default:
		return "free"
	}
}

// ParseTier parses a string tier name into its integer level.
func ParseTier(name string) int {
	switch name {
	case "enterprise":
		return TierEnterprise
	case "pro":
		return TierPro
	default:
		return TierFree
	}
}

// CurveParams holds the elliptic curve generators G and H for Pedersen commitments.
type CurveParams struct {
	Gx, Gy *big.Int // Standard base generator G
	Hx, Hy *big.Int // Second independent generator H (unknown discrete log)
	N      *big.Int // Order of the curve group
}

// PedersenCommitment represents an elliptic curve point C = v*G + r*H.
type PedersenCommitment struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// AnonymousCredential represents an issuer-signed entitlement credential.
type AnonymousCredential struct {
	ID             string              `json:"id"`
	HWIDCommitment *PedersenCommitment `json:"hwid_commitment"`
	Tier           int                 `json:"tier"`
	MaxSeats       int                 `json:"max_seats"`
	ExpiresAt      int64               `json:"expires_at"`
	Scope          string              `json:"scope"`
	TenantID       string              `json:"tenant_id"`
	IssuedAt       int64               `json:"issued_at"`
	SignatureR     *big.Int            `json:"sig_r"`
	SignatureS     *big.Int            `json:"sig_s"`
}

// ZKPProof contains the non-interactive zero-knowledge presentation proof.
type ZKPProof struct {
	// HWID Proof of Knowledge components
	AnnouncementX *big.Int `json:"ax"`
	AnnouncementY *big.Int `json:"ay"`
	ResponseV     *big.Int `json:"sv"` // response for secret value v
	ResponseR     *big.Int `json:"sr"` // response for blinding factor r

	// Entitlement presentation proof components
	HWIDCommitment *PedersenCommitment `json:"hwid_commitment"`
	CredentialID   string              `json:"credential_id"`
	ClaimedTier    int                 `json:"claimed_tier"`
	MaxSeats       int                 `json:"max_seats"`
	ExpiresAt      int64               `json:"expires_at"`
	Scope          string              `json:"scope"`
	TenantID       string              `json:"tenant_id"`
	Nullifier      string              `json:"nullifier"`
	Epoch          int64               `json:"epoch"`

	// Issuer signature attached to credential
	SignatureR *big.Int `json:"sig_r"`
	SignatureS *big.Int `json:"sig_s"`

	// Fiat-Shamir challenge
	Challenge *big.Int `json:"challenge"`
}

// VerificationResult contains the outcome of zero-knowledge proof verification.
type VerificationResult struct {
	Valid          bool      `json:"valid"`
	ClaimedTier    int       `json:"claimed_tier"`
	TierName       string    `json:"tier_name"`
	TenantID       string    `json:"tenant_id"`
	Nullifier      string    `json:"nullifier"`
	Epoch          int64     `json:"epoch"`
	ExpiresAt      time.Time `json:"expires_at"`
	HWIDCommitment string    `json:"hwid_commitment"`
	Reason         string    `json:"reason,omitempty"`
}

// ZKPStatusSummary provides telemetry and statistics on ZKP verifications.
type ZKPStatusSummary struct {
	TotalCredentialsIssued int64  `json:"total_credentials_issued"`
	TotalProofsVerified    int64  `json:"total_proofs_verified"`
	TotalProofsRejected    int64  `json:"total_proofs_rejected"`
	SpentNullifiersCount   int    `json:"spent_nullifiers_count"`
	IssuerPublicKeyHex     string `json:"issuer_public_key"`
	ActiveEpoch            int64  `json:"active_epoch"`
}

// KeyPair represents the broker's master signing key for anonymous credentials.
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}
