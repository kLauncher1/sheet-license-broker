package audit

import (
	"testing"
	"time"
)

func TestCollectorRecordAndList(t *testing.T) {
	collector := NewCollector(3)

	collector.Record(AuditRecord{
		EventType: "AUTH_SUCCESS",
		Severity:  "INFO",
		ActorIP:   "10.0.0.1",
		Details:   "user admin login",
	})
	collector.Record(AuditRecord{
		EventType: "RATE_LIMIT_EXCEEDED",
		Severity:  "WARNING",
		ActorIP:   "10.0.0.2",
		Details:   "120 req/min",
	})
	collector.Record(AuditRecord{
		EventType: "TAMPER_DETECTED",
		Severity:  "CRITICAL",
		ActorIP:   "10.0.0.3",
		HWID:      "bad-hwid-01",
		Details:   "debugger attached",
	})

	records := collector.List(10, "", "")
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
	// Verify reverse chronological order
	if records[0].EventType != "TAMPER_DETECTED" {
		t.Fatalf("expected newest record first, got: %s", records[0].EventType)
	}
	if records[0].Digest == "" {
		t.Fatalf("expected non-empty digest")
	}

	// Verify filtering by severity
	critRecords := collector.List(10, "CRITICAL", "")
	if len(critRecords) != 1 || critRecords[0].EventType != "TAMPER_DETECTED" {
		t.Fatalf("expected 1 critical record, got %d", len(critRecords))
	}

	// Verify capacity bounded ring behavior
	collector.Record(AuditRecord{
		EventType: "NEW_EVENT",
		Severity:  "INFO",
		Details:   "overflow record",
	})
	allAfter := collector.List(10, "", "")
	if len(allAfter) != 3 {
		t.Fatalf("expected capacity 3 maintained, got %d", len(allAfter))
	}
	if allAfter[0].EventType != "NEW_EVENT" {
		t.Fatalf("expected newest record 'NEW_EVENT', got %s", allAfter[0].EventType)
	}
}

func TestExportAndDecryptSuccess(t *testing.T) {
	secretKey := []byte("super-secure-audit-secret-key-32")
	inputRecords := []AuditRecord{
		{
			ID:        "rec_101",
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			EventType: "IP_TEMPORARY_BAN",
			Severity:  "CRITICAL",
			ActorIP:   "192.168.1.50",
			Details:   "score exceeded 50 threshold",
		},
		{
			ID:        "rec_102",
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			EventType: "LICENSE_REVOKED",
			Severity:  "WARNING",
			Resource:  "LIC-TEST-KEY",
			Details:   "manual revocation by admin",
		},
	}

	bundle, err := ExportEncrypted(inputRecords, secretKey)
	if err != nil {
		t.Fatalf("failed to export encrypted bundle: %v", err)
	}

	if bundle.BundleID == "" || bundle.CiphertextHex == "" || bundle.NonceHex == "" || bundle.HMACSignature == "" {
		t.Fatalf("bundle contains empty cryptographic fields: %+v", bundle)
	}
	if bundle.RecordCount != 2 {
		t.Fatalf("expected record count 2, got %d", bundle.RecordCount)
	}

	decrypted, err := DecryptAndVerify(bundle, secretKey)
	if err != nil {
		t.Fatalf("failed to decrypt bundle: %v", err)
	}

	if len(decrypted) != 2 {
		t.Fatalf("expected 2 decrypted records, got %d", len(decrypted))
	}
	if decrypted[0].ID != "rec_101" || decrypted[1].ID != "rec_102" {
		t.Fatalf("decrypted record mismatch: %+v", decrypted)
	}
}

func TestTamperedBundleRejected(t *testing.T) {
	secretKey := []byte("audit-test-key-0000000000000000")
	inputRecords := []AuditRecord{
		{ID: "r1", EventType: "TEST", Severity: "INFO", Details: "test"},
	}

	bundle, err := ExportEncrypted(inputRecords, secretKey)
	if err != nil {
		t.Fatalf("export error: %v", err)
	}

	// Tamper with ciphertext
	corrupted := *bundle
	corrupted.CiphertextHex = "deadbeef" + bundle.CiphertextHex[8:]

	_, err = DecryptAndVerify(&corrupted, secretKey)
	if err == nil {
		t.Fatalf("expected error on tampered bundle, got nil")
	}
	if err != ErrTamperedAuditBundle {
		t.Fatalf("expected ErrTamperedAuditBundle, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	key1 := []byte("correct-key-32-bytes-long-123456")
	key2 := []byte("wrong-key-32-bytes-long-65432100")
	inputRecords := []AuditRecord{
		{ID: "r1", EventType: "TEST", Severity: "INFO"},
	}

	bundle, err := ExportEncrypted(inputRecords, key1)
	if err != nil {
		t.Fatalf("export error: %v", err)
	}

	_, err = DecryptAndVerify(bundle, key2)
	if err == nil {
		t.Fatalf("expected error on wrong key, got nil")
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	records := []AuditRecord{{ID: "r1"}}
	_, err := ExportEncrypted(records, nil)
	if err != ErrInvalidAuditKey {
		t.Fatalf("expected ErrInvalidAuditKey, got %v", err)
	}

	bundle := &EncryptedAuditBundle{CiphertextHex: "aa", NonceHex: "bb"}
	_, err = DecryptAndVerify(bundle, []byte(""))
	if err != ErrInvalidAuditKey {
		t.Fatalf("expected ErrInvalidAuditKey, got %v", err)
	}
}
