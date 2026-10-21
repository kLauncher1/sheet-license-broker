package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/airgap"
)

func TestProxyAirgapLifecycle(t *testing.T) {
	p, err := NewProxy(ProxyConfig{
		OfflineMode: true,
	})
	if err != nil {
		t.Fatalf("Failed to initialize proxy: %v", err)
	}
	defer p.Close()

	ctx := context.Background()

	// 1. Issue offline airgap token
	token, compact, qr, err := p.IssueAirgapToken(ctx, airgap.IssueTokenRequest{
		LicenseKey: "LIC-PROXY-AIRGAP-1",
		HWID:       "HWID-PROXY-CLIENT",
		Tier:       "enterprise",
		DaysValid:  45,
		MaxDevices: 1,
		Features:   []string{"radar", "airgap"},
	})
	if err != nil {
		t.Fatalf("IssueAirgapToken error: %v", err)
	}
	if token == nil || compact == "" || qr == "" {
		t.Fatalf("Expected token, compact string, and QR payload")
	}

	// 2. Verify token
	verified, err := p.VerifyAirgapToken(ctx, compact, "HWID-PROXY-CLIENT", time.Now().Unix())
	if err != nil {
		t.Fatalf("VerifyAirgapToken error: %v", err)
	}
	if verified.LicenseKey != "LIC-PROXY-AIRGAP-1" {
		t.Fatalf("Verified license key mismatch: %s", verified.LicenseKey)
	}

	// 3. Request offline activation
	actResp, err := p.RequestAirgapActivation(ctx, airgap.ActivationRequest{
		LicenseKey: "LIC-PROXY-ACT-1",
		HWID:       "HWID-OFFLINE-MACHINE",
	})
	if err != nil {
		t.Fatalf("RequestAirgapActivation error: %v", err)
	}
	if actResp.Status != "ACTIVATED" || actResp.QRPayload == "" {
		t.Fatalf("Invalid activation response: %+v", actResp)
	}

	// 4. Fulfill activation via QR payload
	fulfilled, err := p.FulfillAirgapActivation(ctx, actResp.QRPayload)
	if err != nil {
		t.Fatalf("FulfillAirgapActivation error: %v", err)
	}
	if fulfilled.LicenseKey != "LIC-PROXY-ACT-1" {
		t.Fatalf("Fulfilled token mismatch: %s", fulfilled.LicenseKey)
	}

	// 5. Query status telemetry
	st := p.GetAirgapStatus()
	if st["status"] != "success" || st["enabled"] != true {
		t.Fatalf("Unexpected airgap status: %+v", st)
	}

	// 6. Check rollback state
	rbState := p.GetAirgapRollbackState("HWID-PROXY-CLIENT")
	if rbState == nil || rbState.HWID != "HWID-PROXY-CLIENT" {
		t.Fatalf("Expected valid rollback state: %+v", rbState)
	}

	// 7. Test Admin Unlock through Proxy
	now := time.Now().Unix()
	unlockToken, err := p.AirGapManager().GenerateAdminUnlockToken(rbState.VaultID, "HWID-PROXY-CLIENT", "TEST-NONCE-1", now+60)
	if err != nil {
		t.Fatalf("Failed to generate admin unlock token: %v", err)
	}

	unlockedState, err := p.UnlockAirgapRollback(ctx, airgap.UnlockRequest{
		VaultID:        unlockToken.VaultID,
		HWID:           unlockToken.HWID,
		Nonce:          unlockToken.Nonce,
		Timestamp:      unlockToken.Timestamp,
		AdminSignature: unlockToken.AdminSignature,
	})
	if err != nil {
		t.Fatalf("UnlockAirgapRollback error: %v", err)
	}
	if unlockedState.Tampered {
		t.Fatalf("Expected vault to be untampered post unlock")
	}
}
