package license

import (
	"strings"
	"testing"
)

func TestBlacklistManagerOperations(t *testing.T) {
	bl := NewBlacklistManager()

	// 1. Add device ban
	entry := bl.Add(BlacklistTypeDevice, "HWID-MALICIOUS-99", "Suspicious multi-activation attempt")
	if entry.Target != "HWID-MALICIOUS-99" {
		t.Fatalf("unexpected target: %s", entry.Target)
	}

	// 2. Check device ban (case insensitive)
	banned, reason := bl.IsDeviceBlacklisted("hwid-malicious-99")
	if !banned || !strings.Contains(reason, "Suspicious") {
		t.Fatalf("expected device to be banned, got banned=%v, reason=%s", banned, reason)
	}

	// 3. Add license revocation
	bl.Add(BlacklistTypeLicense, "KEY-REVOKED-1234", "Refund processed")
	revoked, reason := bl.IsLicenseBlacklisted("key-revoked-1234")
	if !revoked || !strings.Contains(reason, "Refund") {
		t.Fatalf("expected license to be revoked, got revoked=%v, reason=%s", revoked, reason)
	}

	// 4. Combined check
	if err := bl.Check("KEY-REVOKED-1234", "HWID-SAFE"); err == nil {
		t.Fatalf("expected error for revoked license")
	}
	if err := bl.Check("KEY-SAFE", "HWID-MALICIOUS-99"); err == nil {
		t.Fatalf("expected error for blacklisted device")
	}
	if err := bl.Check("KEY-SAFE", "HWID-SAFE"); err != nil {
		t.Fatalf("expected safe credentials to pass, got: %v", err)
	}

	// 5. Remove device from blacklist
	removed := bl.Remove(BlacklistTypeDevice, "HWID-MALICIOUS-99")
	if !removed {
		t.Fatalf("expected successful removal")
	}
	if banned, _ := bl.IsDeviceBlacklisted("HWID-MALICIOUS-99"); banned {
		t.Fatalf("expected device to no longer be blacklisted")
	}
}

func TestManagerRevokeAndVerify(t *testing.T) {
	mgr := NewManager()

	lic := mgr.CreateLicense(30, 1)

	// Valid initial bind
	verified, err := mgr.VerifyAndBind(lic.LicenseKey, "HWID-DEV-1")
	if err != nil || verified.BoundHWID != "HWID-DEV-1" {
		t.Fatalf("expected initial bind to succeed, err: %v", err)
	}

	// Revoke license
	if err := mgr.RevokeLicense(lic.LicenseKey, "Chargeback received"); err != nil {
		t.Fatalf("failed to revoke license: %v", err)
	}

	// Verification must now fail
	_, err = mgr.VerifyAndBind(lic.LicenseKey, "HWID-DEV-1")
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revocation error, got: %v", err)
	}

	// Ban device
	mgr.Blacklist().Add(BlacklistTypeDevice, "HWID-DEV-BANNED", "Cheating detected")
	newLic := mgr.CreateLicense(30, 1)
	_, err = mgr.VerifyAndBind(newLic.LicenseKey, "HWID-DEV-BANNED")
	if err == nil || !strings.Contains(err.Error(), "blacklisted") {
		t.Fatalf("expected blacklisted device error, got: %v", err)
	}
}
