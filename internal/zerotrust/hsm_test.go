package zerotrust

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestHSMLifecycleAndSigning(t *testing.T) {
	hsm, err := NewSoftwareHSM("test-pin-1234")
	if err != nil {
		t.Fatalf("Failed to initialize software HSM: %v", err)
	}

	slots := hsm.ListSlots()
	if len(slots) < 3 {
		t.Fatalf("Expected at least 3 hardware slots, got %d", len(slots))
	}

	for _, slot := range slots {
		if !slot.KeyPresent {
			t.Errorf("Slot %d expected key present", slot.SlotID)
		}
		if slot.PublicKeyPEM == "" {
			t.Errorf("Slot %d expected non-empty public key PEM", slot.SlotID)
		}
	}

	signer, err := hsm.GetSigner(0)
	if err != nil {
		t.Fatalf("Failed to get signer for slot 0: %v", err)
	}

	data := []byte("confidential mesh message")
	hash := sha256.Sum256(data)

	sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign with HSM slot 0: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Signature is empty")
	}

	// Verify operations count incremented
	slot0 := hsm.ListSlots()[0]
	if slot0.OperationsCount != 1 {
		t.Errorf("Expected 1 operation, got %d", slot0.OperationsCount)
	}

	// Test PIN authentication
	hsm.Logout()
	if hsm.IsAuthenticated() {
		t.Error("Expected HSM to be locked after Logout")
	}

	_, err = signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != ErrHSMUnauthorized {
		t.Errorf("Expected ErrHSMUnauthorized, got %v", err)
	}

	// Bad PIN
	if err := hsm.Login("wrong-pin"); err != ErrHSMUnauthorized {
		t.Errorf("Expected ErrHSMUnauthorized on bad PIN, got %v", err)
	}

	// Correct PIN
	if err := hsm.Login("test-pin-1234"); err != nil {
		t.Fatalf("Failed to login with correct PIN: %v", err)
	}

	// Zeroize test
	hsm.Zeroize()
	for _, slot := range hsm.ListSlots() {
		if !slot.Zeroized {
			t.Errorf("Slot %d should be zeroized", slot.SlotID)
		}
	}

	// Signing after zeroize must fail
	_ = hsm.Login("test-pin-1234")
	_, err = signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err == nil {
		t.Fatal("Expected signing error after zeroization")
	}
}
