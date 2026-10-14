package backup

import (
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/auth"
	"github.com/kLauncher1/sheet-license-broker/internal/db"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
	"github.com/kLauncher1/sheet-license-broker/internal/tenant"
)

func sampleSnapshotData() SnapshotData {
	return SnapshotData{
		Tenants: []tenant.Tenant{
			{
				ID:              "tenant-omega",
				Name:            "Omega Cloud",
				NamespacePrefix: "OMG",
				IsActive:        true,
				CreatedAt:       time.Now().UTC(),
			},
		},
		Users: []auth.User{
			{
				UserID:    "usr-1",
				Username:  "admin",
				Role:      "admin",
				CreatedAt: time.Now().UTC(),
			},
		},
		Licenses: []license.License{
			{
				LicenseKey: "OMG-LIC-1111-2222",
				BoundHWID:  "HWID-TEST-0001",
				MaxDevices: 1,
				Status:     "active",
				ExpiresAt:  time.Now().UTC().Add(30 * 24 * time.Hour),
				CreatedAt:  time.Now().UTC(),
			},
		},
		Blacklist: []license.BlacklistEntry{
			{
				Type:      license.BlacklistTypeDevice,
				Target:    "BANNED-HWID",
				Reason:    "Fraud detection",
				CreatedAt: time.Now().UTC(),
			},
		},
		AuditLogs: []AuditRecord{
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Action:    "backup.create",
				Actor:     "system",
				Details:   "Automated scheduled snapshot",
				Status:    "success",
			},
		},
		Documents: []db.Document{
			{
				Collection: "configs",
				DocID:      "site-settings",
				Payload:    `{"theme":"emerald","maintenance":false}`,
				UpdatedAt:  time.Now().UTC(),
			},
		},
	}
}

func TestCreateSnapshotAndVerifyIntegrity(t *testing.T) {
	data := sampleSnapshotData()
	snapshot, err := CreateSnapshot(data)
	if err != nil {
		t.Fatalf("failed to create snapshot: %v", err)
	}

	if snapshot.Checksum == "" {
		t.Fatalf("expected non-empty checksum")
	}

	valid, err := snapshot.VerifyIntegrity()
	if err != nil || !valid {
		t.Fatalf("expected integrity verification to pass, valid=%v, err=%v", valid, err)
	}
}

func TestTamperedSnapshotChecksumFails(t *testing.T) {
	data := sampleSnapshotData()
	snapshot, err := CreateSnapshot(data)
	if err != nil {
		t.Fatalf("failed to create snapshot: %v", err)
	}

	// Tamper with data
	snapshot.Data.Licenses[0].BoundHWID = "TAMPERED-HWID"

	valid, err := snapshot.VerifyIntegrity()
	if valid || err != ErrChecksumMismatch {
		t.Fatalf("expected checksum mismatch error on tampered data, got valid=%v, err=%v", valid, err)
	}
}

func TestAES256GCMEncryptDecryptRoundtrip(t *testing.T) {
	data := sampleSnapshotData()
	snapshot, err := CreateSnapshot(data)
	if err != nil {
		t.Fatalf("failed to create snapshot: %v", err)
	}

	key := []byte("super-secure-backup-passphrase-32b")
	encrypted, err := EncryptSnapshot(snapshot, key)
	if err != nil {
		t.Fatalf("failed to encrypt snapshot: %v", err)
	}

	if len(encrypted) <= 28 { // 12-byte nonce + 16-byte tag
		t.Fatalf("ciphertext suspiciously short: %d bytes", len(encrypted))
	}

	decrypted, err := DecryptSnapshot(encrypted, key)
	if err != nil {
		t.Fatalf("failed to decrypt snapshot: %v", err)
	}

	if decrypted.Checksum != snapshot.Checksum {
		t.Errorf("checksum mismatch after roundtrip: got %s, expected %s", decrypted.Checksum, snapshot.Checksum)
	}

	if len(decrypted.Data.Tenants) != 1 || decrypted.Data.Tenants[0].ID != "tenant-omega" {
		t.Errorf("decrypted tenants mismatch: %+v", decrypted.Data.Tenants)
	}
	if len(decrypted.Data.Licenses) != 1 || decrypted.Data.Licenses[0].LicenseKey != "OMG-LIC-1111-2222" {
		t.Errorf("decrypted licenses mismatch: %+v", decrypted.Data.Licenses)
	}
}

func TestDecryptionInvalidKeyFails(t *testing.T) {
	data := sampleSnapshotData()
	snapshot, _ := CreateSnapshot(data)
	key1 := []byte("secret-key-1")
	key2 := []byte("secret-key-2")

	encrypted, err := EncryptSnapshot(snapshot, key1)
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	_, err = DecryptSnapshot(encrypted, key2)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed on wrong key, got: %v", err)
	}
}

func TestCorruptedPayloadFails(t *testing.T) {
	data := sampleSnapshotData()
	snapshot, _ := CreateSnapshot(data)
	key := []byte("secret-key")

	encrypted, err := EncryptSnapshot(snapshot, key)
	if err != nil {
		t.Fatalf("encryption error: %v", err)
	}

	// Corrupt a byte
	encrypted[20] ^= 0xFF

	_, err = DecryptSnapshot(encrypted, key)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed on corrupted ciphertext, got: %v", err)
	}
}
