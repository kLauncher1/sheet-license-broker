package zkp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Verifier coordinates zero-knowledge verification, credential issuance, and nullifier tracking.
type Verifier struct {
	mu                 sync.RWMutex
	issuerKey          *KeyPair
	spentNullifiers    map[string]int64 // nullifier -> epoch spent
	credentialsIssued  atomic.Int64
	proofsVerified     atomic.Int64
	proofsRejected     atomic.Int64
}

// NewVerifier initializes a ZKP verifier with a newly generated or pre-configured issuer key.
func NewVerifier(key *KeyPair) (*Verifier, error) {
	if key == nil {
		curve := elliptic.P256()
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate issuer key: %w", err)
		}
		key = &KeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
	}
	return &Verifier{
		issuerKey:       key,
		spentNullifiers: make(map[string]int64),
	}, nil
}

// IssuerPublicKey returns the public key of the credential issuer.
func (v *Verifier) IssuerPublicKey() *ecdsa.PublicKey {
	return v.issuerKey.PublicKey
}

// IssuerPublicKeyHex returns the uncompressed hex encoding of the issuer's public key.
func (v *Verifier) IssuerPublicKeyHex() string {
	pub := v.issuerKey.PublicKey
	if pub == nil || pub.X == nil || pub.Y == nil {
		return ""
	}
	return fmt.Sprintf("%064x%064x", pub.X, pub.Y)
}

// IssueCredential creates an issuer-signed AnonymousCredential for an authenticated license.
func (v *Verifier) IssueCredential(
	hwidCommitment *PedersenCommitment,
	tier int,
	maxSeats int,
	validDays int,
	scope string,
	tenantID string,
) (*AnonymousCredential, error) {
	if hwidCommitment == nil || hwidCommitment.X == nil || hwidCommitment.Y == nil {
		return nil, fmt.Errorf("invalid HWID commitment")
	}
	if tier <= 0 {
		tier = TierFree
	}
	if maxSeats <= 0 {
		maxSeats = 1
	}
	if validDays <= 0 {
		validDays = 30
	}
	if scope == "" {
		scope = "default"
	}
	if tenantID == "" {
		tenantID = "default"
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(validDays) * 24 * time.Hour).Unix()

	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	credID := fmt.Sprintf("cred-%d-%s", now.Unix(), hex.EncodeToString(randBytes))

	digest := computeCredentialDigest(hwidCommitment, tier, maxSeats, expiresAt, scope, tenantID, credID)
	r, s, err := ecdsa.Sign(rand.Reader, v.issuerKey.PrivateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	cred := &AnonymousCredential{
		ID:             credID,
		HWIDCommitment: hwidCommitment,
		Tier:           tier,
		MaxSeats:       maxSeats,
		ExpiresAt:      expiresAt,
		Scope:          scope,
		TenantID:       tenantID,
		IssuedAt:       now.Unix(),
		SignatureR:     r,
		SignatureS:     s,
	}

	v.credentialsIssued.Add(1)
	return cred, nil
}

// VerifyProof verifies a zero-knowledge presentation proof against required entitlements.
func (v *Verifier) VerifyProof(
	proof *ZKPProof,
	requiredTier int,
	currentEpoch int64,
) *VerificationResult {
	res := &VerificationResult{
		Valid:       false,
		ClaimedTier: 0,
		TierName:    "unknown",
	}

	if proof == nil {
		v.proofsRejected.Add(1)
		res.Reason = "proof payload is nil"
		return res
	}

	res.ClaimedTier = proof.ClaimedTier
	res.TierName = TierName(proof.ClaimedTier)
	res.TenantID = proof.TenantID
	res.Nullifier = proof.Nullifier
	res.Epoch = proof.Epoch
	res.ExpiresAt = time.Unix(proof.ExpiresAt, 0).UTC()
	if proof.HWIDCommitment != nil {
		res.HWIDCommitment = proof.HWIDCommitment.String()
	}

	// 1. Expiration validity check
	nowEpoch := time.Now().UTC().Unix()
	if proof.ExpiresAt <= nowEpoch {
		v.proofsRejected.Add(1)
		res.Reason = fmt.Sprintf("credential expired at %s", res.ExpiresAt.Format(time.RFC3339))
		return res
	}

	// 2. Entitlement tier check
	if proof.ClaimedTier < requiredTier {
		v.proofsRejected.Add(1)
		res.Reason = fmt.Sprintf("insufficient tier: claimed %s (%d), required %s (%d)",
			TierName(proof.ClaimedTier), proof.ClaimedTier, TierName(requiredTier), requiredTier)
		return res
	}

	// 3. Nullifier double-spending prevention check
	v.mu.Lock()
	if spentEpoch, exists := v.spentNullifiers[proof.Nullifier]; exists {
		v.mu.Unlock()
		v.proofsRejected.Add(1)
		res.Reason = fmt.Sprintf("nullifier already spent for epoch %d (anti-replay triggered)", spentEpoch)
		return res
	}
	v.mu.Unlock()

	// 4. Fiat-Shamir challenge reconstruction & check
	_, cp := GetCurve()
	expectedChallenge := computeFiatShamirChallenge(
		cp,
		proof.HWIDCommitment,
		proof.AnnouncementX, proof.AnnouncementY,
		proof.CredentialID,
		proof.ClaimedTier,
		proof.ExpiresAt,
		proof.Nullifier,
		proof.Epoch,
		proof.TenantID,
	)

	if proof.Challenge == nil || expectedChallenge.Cmp(proof.Challenge) != 0 {
		v.proofsRejected.Add(1)
		res.Reason = "fiat-shamir challenge mismatch"
		return res
	}

	// 5. Sigma protocol announcement relation check:
	// Check: sv*G + sr*H == A + c*C
	curve, _ := GetCurve()
	svGx, svGy := curve.ScalarMult(cp.Gx, cp.Gy, proof.ResponseV.Bytes())
	srHx, srHy := curve.ScalarMult(cp.Hx, cp.Hy, proof.ResponseR.Bytes())
	lhsX, lhsY := curve.Add(svGx, svGy, srHx, srHy)

	if proof.HWIDCommitment == nil || proof.HWIDCommitment.X == nil || proof.HWIDCommitment.Y == nil {
		v.proofsRejected.Add(1)
		res.Reason = "missing HWID commitment point"
		return res
	}

	cCx, cCy := curve.ScalarMult(proof.HWIDCommitment.X, proof.HWIDCommitment.Y, proof.Challenge.Bytes())
	rhsX, rhsY := curve.Add(proof.AnnouncementX, proof.AnnouncementY, cCx, cCy)

	if lhsX.Cmp(rhsX) != 0 || lhsY.Cmp(rhsY) != 0 {
		v.proofsRejected.Add(1)
		res.Reason = "sigma proof announcement relation invalid (knowledge proof failed)"
		return res
	}

	// 6. Issuer ECDSA signature verification
	digest := computeCredentialDigest(
		proof.HWIDCommitment,
		proof.ClaimedTier,
		proof.MaxSeats,
		proof.ExpiresAt,
		proof.Scope,
		proof.TenantID,
		proof.CredentialID,
	)

	if !ecdsa.Verify(v.issuerKey.PublicKey, digest, proof.SignatureR, proof.SignatureS) {
		v.proofsRejected.Add(1)
		res.Reason = "invalid issuer credential signature"
		return res
	}

	// 7. Mark nullifier as spent for this epoch
	v.mu.Lock()
	v.spentNullifiers[proof.Nullifier] = proof.Epoch
	v.mu.Unlock()

	v.proofsVerified.Add(1)
	res.Valid = true
	return res
}

// CheckNullifier reports whether a nullifier has already been recorded as spent.
func (v *Verifier) CheckNullifier(nullifier string) (bool, int64) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	epoch, exists := v.spentNullifiers[nullifier]
	return exists, epoch
}

// Status returns a telemetry summary of the verifier state.
func (v *Verifier) Status() ZKPStatusSummary {
	v.mu.RLock()
	spentCount := len(v.spentNullifiers)
	v.mu.RUnlock()

	return ZKPStatusSummary{
		TotalCredentialsIssued: v.credentialsIssued.Load(),
		TotalProofsVerified:    v.proofsVerified.Load(),
		TotalProofsRejected:    v.proofsRejected.Load(),
		SpentNullifiersCount:   spentCount,
		IssuerPublicKeyHex:     v.IssuerPublicKeyHex(),
		ActiveEpoch:            time.Now().Unix() / 3600, // hourly epoch
	}
}

// computeCredentialDigest produces the SHA-256 payload digest for ECDSA signature.
func computeCredentialDigest(
	comm *PedersenCommitment,
	tier int,
	maxSeats int,
	expiresAt int64,
	scope string,
	tenantID string,
	credID string,
) []byte {
	h := sha256.New()
	if comm != nil && comm.X != nil && comm.Y != nil {
		h.Write(comm.X.Bytes())
		h.Write(comm.Y.Bytes())
	}
	h.Write([]byte(fmt.Sprintf("%d:%d:%d:%s:%s:%s", tier, maxSeats, expiresAt, scope, tenantID, credID)))
	return h.Sum(nil)
}
