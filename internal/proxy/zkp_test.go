package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/zkp"
)

func TestProxyZKPAnonymousCredentialIssuance(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	lic, err := p.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	hwid := "HWID-PROXY-TEST-001"
	cred, rScalar, err := p.IssueAnonymousCredential(ctx, lic.LicenseKey, nil, hwid, "pro", 30, "production", "default")
	if err != nil {
		t.Fatalf("Failed to issue anonymous credential: %v", err)
	}

	if cred == nil || cred.HWIDCommitment == nil {
		t.Fatalf("Issued credential or HWID commitment is nil")
	}
	if rScalar == nil {
		t.Fatalf("Expected generated blinding factor rScalar, got nil")
	}
	if cred.Tier != zkp.TierPro {
		t.Errorf("Expected Pro tier (%d), got %d", zkp.TierPro, cred.Tier)
	}

	epoch := time.Now().Unix() / 3600
	proof, err := zkp.GenerateZKPProof(hwid, rScalar, cred, epoch, "default")
	if err != nil {
		t.Fatalf("Failed to generate ZKP proof: %v", err)
	}

	res := p.VerifyZKPProof(ctx, proof, "pro", epoch)
	if !res.Valid {
		t.Fatalf("ZKP proof verification failed: %s", res.Reason)
	}
	if res.TierName != "pro" {
		t.Errorf("Expected tier name 'pro', got '%s'", res.TierName)
	}

	// Verify status telemetry
	status := p.GetZKPStatus()
	if status.TotalCredentialsIssued < 1 {
		t.Errorf("Expected at least 1 credential issued, got %d", status.TotalCredentialsIssued)
	}
	if status.TotalProofsVerified < 1 {
		t.Errorf("Expected at least 1 proof verified, got %d", status.TotalProofsVerified)
	}

	// Verify replay attack detection
	resReplay := p.VerifyZKPProof(ctx, proof, "pro", epoch)
	if resReplay.Valid {
		t.Errorf("Expected duplicate nullifier presentation to be rejected")
	}
}
