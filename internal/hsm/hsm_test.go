package hsm

import (
	"fmt"
	"sync"
	"testing"
)

func TestHSMSlotsAndTokens(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to initialize HSM manager: %v", err)
	}

	slots := mgr.ListSlots()
	if len(slots) != 3 {
		t.Fatalf("Expected 3 provisioned HSM slots, got %d", len(slots))
	}

	for _, s := range slots {
		if !s.TokenPresent {
			t.Errorf("Slot %d: expected TokenPresent to be true", s.SlotID)
		}
		if !s.HardwareSlot {
			t.Errorf("Slot %d: expected HardwareSlot to be true", s.SlotID)
		}

		tok, err := mgr.GetTokenInfo(s.SlotID)
		if err != nil {
			t.Fatalf("Failed to get token for slot %d: %v", s.SlotID, err)
		}
		if tok.FIPSLevel != FIPSLevel4 {
			t.Errorf("Slot %d: expected FIPS level %s, got %s", s.SlotID, FIPSLevel4, tok.FIPSLevel)
		}
		if tok.TamperDetected {
			t.Errorf("Slot %d: expected clean tamper state", s.SlotID)
		}
	}
}

func TestHSMSessionAndAuthentication(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	handle, err := mgr.OpenSession(0)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}
	defer mgr.CloseSession(handle)

	// Attempt wrong PIN
	err = mgr.Login(handle, CKU_USER, "WRONG-PIN")
	if err != ErrPINIncorrect {
		t.Fatalf("Expected ErrPINIncorrect, got %v", err)
	}

	// Login with correct User PIN
	err = mgr.Login(handle, CKU_USER, "FIPS-ROOT-PIN-9842")
	if err != nil {
		t.Fatalf("Login with correct User PIN failed: %v", err)
	}

	// Logout
	err = mgr.Logout(handle)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Login with correct SO PIN
	err = mgr.Login(handle, CKU_SO, "SO-ROOT-ADMIN-0000")
	if err != nil {
		t.Fatalf("Login with SO PIN failed: %v", err)
	}
	_ = mgr.Logout(handle)
}

func TestHSMPINLockout(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	handle, err := mgr.OpenSession(1)
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}
	defer mgr.CloseSession(handle)

	// Exceed max 5 attempts
	for i := 0; i < 4; i++ {
		err = mgr.Login(handle, CKU_USER, fmt.Sprintf("BAD-PIN-%d", i))
		if err != ErrPINIncorrect {
			t.Fatalf("Attempt %d: expected ErrPINIncorrect, got %v", i, err)
		}
	}

	// 5th attempt triggers lockout
	err = mgr.Login(handle, CKU_USER, "BAD-PIN-FINAL")
	if err != ErrPINLocked {
		t.Fatalf("5th attempt: expected ErrPINLocked, got %v", err)
	}

	// Subsequent attempts must remain locked
	err = mgr.Login(handle, CKU_USER, "FIPS-SNAP-PIN-1102")
	if err != ErrPINLocked {
		t.Fatalf("Expected ErrPINLocked even with correct PIN, got %v", err)
	}
}

func TestHSMKeyDerivation(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	req1 := KeyDerivationRequest{
		SlotID:        0,
		Purpose:       "audit_token_encryption",
		Context:       "TX-9982-TENANT-ALPHA",
		KeyLengthBits: 256,
	}

	resp1, key1, err := mgr.DeriveMasterKey(req1)
	if err != nil {
		t.Fatalf("DeriveMasterKey failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d", len(key1))
	}
	if resp1.Fingerprint == "" {
		t.Errorf("Expected valid fingerprint, got empty")
	}

	// Deriving with identical parameters must yield identical key
	resp2, key2, err := mgr.DeriveMasterKey(req1)
	if err != nil {
		t.Fatalf("Repeat derive failed: %v", err)
	}
	if string(key1) != string(key2) {
		t.Errorf("Deterministic key derivation mismatch")
	}
	if resp1.Fingerprint != resp2.Fingerprint {
		t.Errorf("Fingerprint mismatch on identical context")
	}

	// Deriving with different purpose must yield different key
	reqDiff := req1
	reqDiff.Purpose = "snapshot_backup_encryption"
	_, keyDiff, err := mgr.DeriveMasterKey(reqDiff)
	if err != nil {
		t.Fatalf("Different purpose derive failed: %v", err)
	}
	if string(key1) == string(keyDiff) {
		t.Errorf("Expected different key for different purpose, got identical")
	}
}

func TestHSMEnvelopeEncryptionAndDecryption(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	plaintext := "CONFIDENTIAL-ENTERPRISE-LICENSE-DATA-9842"
	aad := "TENANT:PROD-CLUSTER-01|EPOCH:2026-10"

	encReq := EnvelopeEncryptRequest{
		SlotID:         1,
		Plaintext:      plaintext,
		AssociatedData: aad,
		Purpose:        "audit_token_encryption",
	}

	encResp, err := mgr.EncryptEnvelope(encReq)
	if err != nil {
		t.Fatalf("EncryptEnvelope failed: %v", err)
	}
	if encResp.CiphertextHex == "" || encResp.NonceHex == "" {
		t.Fatalf("Ciphertext or Nonce was empty")
	}

	// Decrypt with matching parameters
	decReq := EnvelopeDecryptRequest{
		SlotID:         1,
		CiphertextHex:  encResp.CiphertextHex,
		NonceHex:       encResp.NonceHex,
		AssociatedData: aad,
		Purpose:        "audit_token_encryption",
	}

	decResp, err := mgr.DecryptEnvelope(decReq)
	if err != nil {
		t.Fatalf("DecryptEnvelope failed: %v", err)
	}
	if !decResp.Authenticated {
		t.Errorf("Expected Authenticated true")
	}
	if decResp.Plaintext != plaintext {
		t.Errorf("Plaintext mismatch: got %q, expected %q", decResp.Plaintext, plaintext)
	}

	// Tampered Associated Data must fail authentication
	tamperedDecReq := decReq
	tamperedDecReq.AssociatedData = "TAMPERED-TENANT-INFO"
	_, err = mgr.DecryptEnvelope(tamperedDecReq)
	if err == nil {
		t.Errorf("Expected decryption error on tampered AAD, got nil")
	}

	// Tampered Ciphertext must fail authentication
	tamperedCipherReq := decReq
	tamperedCipherReq.CiphertextHex = "ff" + encResp.CiphertextHex[2:]
	_, err = mgr.DecryptEnvelope(tamperedCipherReq)
	if err == nil {
		t.Errorf("Expected decryption error on tampered ciphertext, got nil")
	}
}

func TestFIPS140KATSelfTests(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	results := mgr.RunSelfTest()
	if len(results) != 5 {
		t.Fatalf("Expected 5 KAT results, got %d", len(results))
	}

	for _, r := range results {
		if !r.Passed {
			t.Errorf("KAT test %s failed: %s", r.TestName, r.Details)
		}
	}

	rep := mgr.GetFIPSReport()
	if rep.CertificationLevel != FIPSLevel4 {
		t.Errorf("Expected certification level %s, got %s", FIPSLevel4, rep.CertificationLevel)
	}
	if !rep.KATPassed {
		t.Errorf("Expected KATPassed true")
	}
	if rep.TamperState != "SECURE_NORMAL" {
		t.Errorf("Expected SECURE_NORMAL tamper state, got %s", rep.TamperState)
	}
}

func TestHSMTamperAndZeroization(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	// Trigger environmental tamper simulation
	err = mgr.SimulateTamper("SENSOR_PHYSICAL_DRILL_BREACH")
	if err != nil {
		t.Fatalf("SimulateTamper failed: %v", err)
	}

	status := mgr.Status()
	if !status.TamperDetected {
		t.Errorf("Expected TamperDetected true")
	}
	if status.MasterKeyPresent {
		t.Errorf("Expected MasterKeyPresent false after tamper zeroization")
	}

	rep := mgr.GetFIPSReport()
	if rep.TamperState != "TAMPERED_ZEROIZED" {
		t.Errorf("Expected TAMPERED_ZEROIZED, got %s", rep.TamperState)
	}

	// New session should be rejected
	_, err = mgr.OpenSession(0)
	if err != ErrTamperDetected {
		t.Errorf("Expected ErrTamperDetected on OpenSession after tamper, got %v", err)
	}

	// Encryption attempt should be rejected
	_, err = mgr.EncryptEnvelope(EnvelopeEncryptRequest{
		SlotID:    0,
		Plaintext: "TEST",
	})
	if err == nil {
		t.Errorf("Expected encryption failure after tamper, got nil")
	}
}

func TestHSMConcurrentAccess(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	var wg sync.WaitGroup
	workers := 10
	iterations := 20

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			slotID := workerID % 3

			for i := 0; i < iterations; i++ {
				text := fmt.Sprintf("WORKER-%d-ITER-%d", workerID, i)
				aad := fmt.Sprintf("AAD-W%d", workerID)

				enc, err := mgr.EncryptEnvelope(EnvelopeEncryptRequest{
					SlotID:         slotID,
					Plaintext:      text,
					AssociatedData: aad,
				})
				if err != nil {
					t.Errorf("Concurrent encrypt worker %d failed: %v", workerID, err)
					return
				}

				dec, err := mgr.DecryptEnvelope(EnvelopeDecryptRequest{
					SlotID:         slotID,
					CiphertextHex:  enc.CiphertextHex,
					NonceHex:       enc.NonceHex,
					AssociatedData: aad,
				})
				if err != nil {
					t.Errorf("Concurrent decrypt worker %d failed: %v", workerID, err)
					return
				}
				if dec.Plaintext != text {
					t.Errorf("Plaintext mismatch in worker %d", workerID)
					return
				}
			}
		}(w)
	}

	wg.Wait()

	status := mgr.Status()
	if status.OperationsCount < int64(workers*iterations) {
		t.Errorf("Expected at least %d operations, got %d", workers*iterations, status.OperationsCount)
	}
}
