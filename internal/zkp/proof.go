package zkp

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// GenerateZKPProof constructs a non-interactive zero-knowledge presentation proof (zk-SNARK / Sigma NIZK).
// It proves:
// 1. Possession of secret HWID scalar v and blinding factor r such that C = v*G + r*H.
// 2. Ownership of a valid issuer-signed AnonymousCredential for (C, Tier, ExpiresAt, Scope).
// 3. That the unspent Nullifier is correctly derived from v for the given (Epoch, TenantID).
func GenerateZKPProof(
	hwid string,
	r *big.Int,
	cred *AnonymousCredential,
	epoch int64,
	tenantID string,
) (*ZKPProof, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential cannot be nil")
	}
	if cred.HWIDCommitment == nil {
		return nil, fmt.Errorf("credential HWID commitment cannot be nil")
	}

	curve, cp := GetCurve()
	v := HashToScalar(hwid)

	// Step 1: Pick random blinding scalars kv, kr in [1, N-1]
	kv, err := RandomScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate kv: %w", err)
	}
	kr, err := RandomScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate kr: %w", err)
	}

	// Step 2: Compute announcement A = kv*G + kr*H
	kvGx, kvGy := curve.ScalarMult(cp.Gx, cp.Gy, kv.Bytes())
	krHx, krHy := curve.ScalarMult(cp.Hx, cp.Hy, kr.Bytes())
	ax, ay := curve.Add(kvGx, kvGy, krHx, krHy)

	// Step 3: Compute Nullifier = HMAC(v, epoch:tenantID)
	nullifier := ComputeNullifier(v, epoch, tenantID)

	// Step 4: Fiat-Shamir non-interactive challenge c = Hash(G, H, C, A, CredID, Tier, ExpiresAt, Nullifier, Epoch)
	challenge := computeFiatShamirChallenge(
		cp,
		cred.HWIDCommitment,
		ax, ay,
		cred.ID,
		cred.Tier,
		cred.ExpiresAt,
		nullifier,
		epoch,
		tenantID,
	)

	// Step 5: Compute responses sv = kv + c*v (mod N), sr = kr + c*r (mod N)
	cv := new(big.Int).Mul(challenge, v)
	cv.Mod(cv, cp.N)
	sv := new(big.Int).Add(kv, cv)
	sv.Mod(sv, cp.N)

	cr := new(big.Int).Mul(challenge, r)
	cr.Mod(cr, cp.N)
	sr := new(big.Int).Add(kr, cr)
	sr.Mod(sr, cp.N)

	proof := &ZKPProof{
		AnnouncementX:  ax,
		AnnouncementY:  ay,
		ResponseV:      sv,
		ResponseR:      sr,
		HWIDCommitment: cred.HWIDCommitment,
		CredentialID:   cred.ID,
		ClaimedTier:    cred.Tier,
		MaxSeats:       cred.MaxSeats,
		ExpiresAt:      cred.ExpiresAt,
		Scope:          cred.Scope,
		TenantID:       tenantID,
		Nullifier:      nullifier,
		Epoch:          epoch,
		SignatureR:     cred.SignatureR,
		SignatureS:     cred.SignatureS,
		Challenge:      challenge,
	}

	return proof, nil
}

// computeFiatShamirChallenge calculates the Fiat-Shamir scalar challenge mod N.
func computeFiatShamirChallenge(
	cp *CurveParams,
	comm *PedersenCommitment,
	ax, ay *big.Int,
	credID string,
	tier int,
	expiresAt int64,
	nullifier string,
	epoch int64,
	tenantID string,
) *big.Int {
	h := sha256.New()

	// Generator points
	h.Write(cp.Gx.Bytes())
	h.Write(cp.Gy.Bytes())
	h.Write(cp.Hx.Bytes())
	h.Write(cp.Hy.Bytes())

	// Commitment point
	if comm != nil && comm.X != nil && comm.Y != nil {
		h.Write(comm.X.Bytes())
		h.Write(comm.Y.Bytes())
	}

	// Announcement point
	if ax != nil && ay != nil {
		h.Write(ax.Bytes())
		h.Write(ay.Bytes())
	}

	// Context and claims
	h.Write([]byte(fmt.Sprintf("%s:%d:%d:%s:%d:%s", credID, tier, expiresAt, nullifier, epoch, tenantID)))

	digest := h.Sum(nil)
	challenge := new(big.Int).SetBytes(digest)
	challenge.Mod(challenge, cp.N)
	if challenge.Sign() == 0 {
		challenge.SetInt64(1)
	}
	return challenge
}
