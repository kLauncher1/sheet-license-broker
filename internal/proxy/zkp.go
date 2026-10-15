package proxy

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/zkp"
)

func (p *Proxy) initZKP() {
	v, err := zkp.NewVerifier(nil)
	if err == nil {
		p.zkpVerifier = v
	}
}

// ZKPVerifier returns the underlying zero-knowledge proof verifier engine.
func (p *Proxy) ZKPVerifier() *zkp.Verifier {
	return p.zkpVerifier
}

// IssueAnonymousCredential creates a privacy-preserving credential for a valid license.
func (p *Proxy) IssueAnonymousCredential(
	ctx context.Context,
	licenseKey string,
	hwidCommitment *zkp.PedersenCommitment,
	hwidRaw string,
	requestedTier string,
	validDays int,
	scope string,
	tenantID string,
) (*zkp.AnonymousCredential, *big.Int, error) {
	if p.zkpVerifier == nil {
		return nil, nil, fmt.Errorf("ZKP verifier engine not initialized")
	}

	// 1. Verify that licenseKey is valid and not revoked
	licRes, err := p.VerifyLicense(ctx, licenseKey, hwidRaw)
	if err != nil || !licRes.Valid {
		return nil, nil, fmt.Errorf("cannot issue anonymous credential: license verification failed (%v)", err)
	}

	// 2. Resolve HWID commitment
	var rScalar *big.Int
	comm := hwidCommitment
	if comm == nil || comm.X == nil || comm.Y == nil {
		if hwidRaw == "" {
			return nil, nil, fmt.Errorf("either hwid_commitment or raw hwid is required")
		}
		var err error
		rScalar, err = zkp.RandomScalar()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate blinding factor: %w", err)
		}
		vScalar := zkp.HashToScalar(hwidRaw)
		comm = zkp.CommitPedersen(vScalar, rScalar)
	}

	// 3. Resolve tier level
	tier := zkp.ParseTier(requestedTier)
	if tier == zkp.TierFree && licRes.Tier != "" {
		tier = zkp.ParseTier(licRes.Tier)
	}

	if validDays <= 0 {
		validDays = 30
	}
	if scope == "" {
		scope = "production"
	}
	if tenantID == "" {
		tenantID = "default"
	}

	cred, err := p.zkpVerifier.IssueCredential(comm, tier, 1, validDays, scope, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("credential issuance failed: %w", err)
	}

	return cred, rScalar, nil
}

// VerifyZKPProof checks an anonymous presentation proof without revealing the raw license or HWID.
func (p *Proxy) VerifyZKPProof(
	ctx context.Context,
	proof *zkp.ZKPProof,
	requiredTier string,
	epoch int64,
) *zkp.VerificationResult {
	if p.zkpVerifier == nil {
		return &zkp.VerificationResult{
			Valid:  false,
			Reason: "ZKP verifier engine not initialized",
		}
	}

	if epoch <= 0 {
		epoch = time.Now().UTC().Unix() / 3600
	}

	tierLevel := zkp.ParseTier(requiredTier)
	res := p.zkpVerifier.VerifyProof(proof, tierLevel, epoch)

	// If verification failed due to replay or forgery, log audit event
	if !res.Valid && p.auditCollector != nil {
		p.auditCollector.Record(audit.AuditRecord{
			EventType: "ZKP_PROOF_REJECTED",
			Severity:  "WARNING",
			TenantID:  res.TenantID,
			HWID:      proof.Nullifier,
			ActorIP:   "127.0.0.1",
			Details:   fmt.Sprintf("reason=%s claimed_tier=%d epoch=%d", res.Reason, res.ClaimedTier, epoch),
		})
	}

	return res
}

// GetZKPStatus returns a telemetry summary of the ZKP engine.
func (p *Proxy) GetZKPStatus() zkp.ZKPStatusSummary {
	if p.zkpVerifier == nil {
		return zkp.ZKPStatusSummary{}
	}
	return p.zkpVerifier.Status()
}

// CheckNullifier reports whether a nullifier is spent.
func (p *Proxy) CheckNullifier(nullifier string) (bool, int64) {
	if p.zkpVerifier == nil {
		return false, 0
	}
	return p.zkpVerifier.CheckNullifier(nullifier)
}
