package license

import (
	"testing"
)

func TestLicenseLifecycle(t *testing.T) {
	mgr := NewManager()

	// 1. Create License
	lic := mgr.CreateLicense(30, 1)
	if lic.LicenseKey == "" {
		t.Fatalf("expected valid license key")
	}
	if lic.Status != "ACTIVE" {
		t.Errorf("expected ACTIVE status, got %s", lic.Status)
	}

	// 2. First Activation (Binds to Machine A)
	hwidA := "hwid_mac_001122334455"
	boundLic, err := mgr.VerifyAndBind(lic.LicenseKey, hwidA)
	if err != nil {
		t.Fatalf("first activation failed: %v", err)
	}
	if boundLic.BoundHWID != hwidA {
		t.Errorf("expected HWID %s, got %s", hwidA, boundLic.BoundHWID)
	}

	// 3. Second Activation from same Machine A (Should succeed)
	_, err = mgr.VerifyAndBind(lic.LicenseKey, hwidA)
	if err != nil {
		t.Errorf("repeat activation on same machine must succeed: %v", err)
	}

	// 4. Pirated Activation from Machine B (Must fail)
	hwidB := "hwid_mac_998877665544"
	_, err = mgr.VerifyAndBind(lic.LicenseKey, hwidB)
	if err == nil {
		t.Errorf("expected hardware mismatch error on Machine B")
	}
}
