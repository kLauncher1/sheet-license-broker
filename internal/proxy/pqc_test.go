package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/pqc"
)

func TestProxyPQCWorkflow(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()

	// 1. Initial status check
	status := p.GetPQCStatus()
	if status.ActiveKeyID == "" {
		t.Fatalf("expected non-empty active key ID")
	}
	if status.DefaultAlgorithm != pqc.AlgoHybridP256 {
		t.Fatalf("expected default algorithm %s, got %s", pqc.AlgoHybridP256, status.DefaultAlgorithm)
	}

	// 2. Create valid license to test signature issuance
	lic, err := p.CreateLicense(ctx, 30, 2)
	if err != nil {
		t.Fatalf("failed to create license: %v", err)
	}

	payload := []byte(`{"client":"desktop-app","tier":"enterprise","quota":1000}`)

	// 1. Signing with nonexistent license must fail
	_, err = p.PQCSignLicense(ctx, "LIC-NONEXISTENT-9999", "HWID-ANY", payload)
	if err == nil {
		t.Fatalf("expected signature issuance to fail on invalid license key")
	}

	// 2. Bind license to primary device
	hwid := "HWID-PROD-ENCLAVE-9988"
	vRes, err := p.VerifyLicense(ctx, lic.LicenseKey, hwid)
	if err != nil || !vRes.Valid {
		t.Fatalf("failed to verify and bind license: %v", err)
	}

	// 3. Signing with mismatched HWID against device-locked license must fail
	_, err = p.PQCSignLicense(ctx, lic.LicenseKey, "HWID-WRONG-DEVICE", payload)
	if err == nil {
		t.Fatalf("expected signature issuance to fail on mismatched device HWID")
	}

	// Now issue hybrid signature
	sig, err := p.PQCSignLicense(ctx, lic.LicenseKey, hwid, payload)
	if err != nil {
		t.Fatalf("failed to sign license payload: %v", err)
	}
	if sig.KeyID == "" || sig.ClassicalSig == "" || sig.QuantumSig == "" {
		t.Fatalf("signature components missing: %+v", sig)
	}

	// 3. Verify hybrid signature via Proxy
	checkRes := p.PQCVerifyHybrid(sig, payload)
	if !checkRes.Valid {
		t.Fatalf("PQC hybrid verification failed: %s", checkRes.ErrorMessage)
	}
	if !checkRes.ClassicalValid || !checkRes.QuantumValid {
		t.Fatalf("expected both classical and quantum to be valid: %+v", checkRes)
	}

	// 4. Test Key Rotation
	rotRecord, err := p.PQCRotateKey(ctx, pqc.AlgoHybridHMAC, 2*time.Hour, "scheduled quarterly rotation")
	if err != nil {
		t.Fatalf("failed to rotate PQC key: %v", err)
	}
	if rotRecord.NewKeyID == "" || rotRecord.OldKeyID == "" {
		t.Fatalf("invalid rotation record: %+v", rotRecord)
	}

	// Signature from old key must still verify under grace period
	graceRes := p.PQCVerifyHybrid(sig, payload)
	if !graceRes.Valid {
		t.Fatalf("old key verification in grace window failed: %s", graceRes.ErrorMessage)
	}
	if !graceRes.GraceActive {
		t.Fatalf("expected grace_active to be true")
	}

	// 5. Test Key Revocation
	if err := p.PQCRevokeKey(ctx, rotRecord.OldKeyID, "compromised key in red-team audit"); err != nil {
		t.Fatalf("failed to revoke old key: %v", err)
	}

	revokedRes := p.PQCVerifyHybrid(sig, payload)
	if revokedRes.Valid {
		t.Fatalf("revoked key signature must be rejected")
	}

	// 6. Final Status Telemetry
	finalStatus := p.GetPQCStatus()
	if finalStatus.TotalRotations < 1 {
		t.Fatalf("expected total rotations >= 1, got %d", finalStatus.TotalRotations)
	}
	if finalStatus.RevokedKeys < 1 {
		t.Fatalf("expected revoked keys >= 1, got %d", finalStatus.RevokedKeys)
	}
	if finalStatus.VerifiedCount < 2 {
		t.Fatalf("expected verified count >= 2, got %d", finalStatus.VerifiedCount)
	}
}
