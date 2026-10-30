package proxy

import (
	"context"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/hsm"
)

func TestProxyHSMLifecycle(t *testing.T) {
	p, err := NewProxy(ProxyConfig{
		OfflineMode: true,
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// 1. Status Check
	status := p.GetHSMStatus()
	if !status.Initialized || !status.HardwareAvailable {
		t.Fatalf("Expected HSM to be initialized and hardware available")
	}
	if status.FIPSLevel != hsm.FIPSLevel4 {
		t.Errorf("Expected FIPS Level %s, got %s", hsm.FIPSLevel4, status.FIPSLevel)
	}

	// 2. List Slots
	slots := p.ListHSMSlots()
	if len(slots) != 3 {
		t.Fatalf("Expected 3 slots, got %d", len(slots))
	}

	// 3. Derive Key
	ctx := context.Background()
	deriveResp, err := p.DeriveHSMKey(ctx, hsm.KeyDerivationRequest{
		SlotID:  0,
		Purpose: "audit_token_encryption",
		Context: "PROXY-TEST-CTX",
	})
	if err != nil {
		t.Fatalf("DeriveHSMKey failed: %v", err)
	}
	if deriveResp.Fingerprint == "" {
		t.Errorf("Expected valid key fingerprint")
	}

	// 4. Envelope Encrypt & Decrypt
	plaintext := "CONFIDENTIAL-PROXY-PAYLOAD"
	aad := "AAD-CONTEXT"

	encResp, err := p.EncryptHSMEnvelope(hsm.EnvelopeEncryptRequest{
		SlotID:         1,
		Plaintext:      plaintext,
		AssociatedData: aad,
		Purpose:        "audit_token_encryption",
	})
	if err != nil {
		t.Fatalf("EncryptHSMEnvelope failed: %v", err)
	}

	decResp, err := p.DecryptHSMEnvelope(hsm.EnvelopeDecryptRequest{
		SlotID:         1,
		CiphertextHex:  encResp.CiphertextHex,
		NonceHex:       encResp.NonceHex,
		AssociatedData: aad,
		Purpose:        "audit_token_encryption",
	})
	if err != nil {
		t.Fatalf("DecryptHSMEnvelope failed: %v", err)
	}
	if decResp.Plaintext != plaintext {
		t.Errorf("Plaintext mismatch: expected %q, got %q", plaintext, decResp.Plaintext)
	}

	// 5. FIPS 140-3 KAT Self-Tests
	kats := p.RunHSMSelfTest()
	if len(kats) != 5 {
		t.Fatalf("Expected 5 KAT self-tests, got %d", len(kats))
	}
	for _, kat := range kats {
		if !kat.Passed {
			t.Errorf("KAT test %s failed: %s", kat.TestName, kat.Details)
		}
	}

	rep := p.GetHSMFIPSReport()
	if !rep.KATPassed {
		t.Errorf("Expected KATPassed true in FIPS report")
	}

	// 6. Tamper Simulation
	err = p.SimulateHSMTamper("SENSOR_LIGHT_EXPOSURE")
	if err != nil {
		t.Fatalf("SimulateHSMTamper failed: %v", err)
	}

	postTamperStatus := p.GetHSMStatus()
	if !postTamperStatus.TamperDetected {
		t.Errorf("Expected TamperDetected true after simulation")
	}
}
