package enclave

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIsolatedMemorySandboxExecution(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))
	sandbox := NewIsolatedMemorySandbox(tm)

	// Issue valid attestation token
	tok, err := tm.IssueToken(PlatformTDX, "mrtd_verified_digest", "rtmr0_verified_digest", 2, false, "nonce_123", "pub_123", 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	sessionKey := []byte("aes_256_gcm_session_key_32bytes!")
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	nonce := make([]byte, 12)
	rand.Read(nonce)

	rawKey := "SLB-PRO-9876-5432-ABCD"
	payload := EnclaveEvalPayload{
		LicenseKey:       rawKey,
		HWID:             "HWID-TEST-MACHINE-1",
		RequestedFeature: "enterprise_audit",
		Timestamp:        time.Now().Unix(),
	}
	plaintext, _ := json.Marshal(payload)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Mock in-enclave evaluator
	evaluator := func(cleartextKey string) (tier string, features []string, expiresAt string, valid bool, err error) {
		if cleartextKey != rawKey {
			t.Errorf("evaluator received unexpected cleartext key: %s", cleartextKey)
		}
		return "pro", []string{"enterprise_audit", "pqc_signatures"}, "2027-12-31T23:59:59Z", true, nil
	}

	res, err := sandbox.ExecuteIsolatedDecryption(
		context.Background(),
		tok,
		hex.EncodeToString(ciphertext),
		hex.EncodeToString(nonce),
		sessionKey,
		evaluator,
	)
	if err != nil {
		t.Fatalf("ExecuteIsolatedDecryption failed: %v", err)
	}

	if !res.Success {
		t.Errorf("expected res.Success=true, got false")
	}
	if !res.HardwareIsolated {
		t.Errorf("expected HardwareIsolated=true")
	}
	if !res.MemoryZeroized {
		t.Errorf("expected MemoryZeroized=true")
	}
	if res.Tier != "pro" {
		t.Errorf("expected tier pro, got %s", res.Tier)
	}
	if len(res.Features) != 2 {
		t.Errorf("expected 2 features, got %d", len(res.Features))
	}
	if res.LicenseKeyMasked == rawKey {
		t.Errorf("license key must be masked, but got raw key: %s", res.LicenseKeyMasked)
	}
	if !strings.HasPrefix(res.LicenseKeyMasked, "SLB-") || !strings.HasSuffix(res.LicenseKeyMasked, "-ABCD") {
		t.Errorf("expected masked format SLB-****-****-ABCD, got %s", res.LicenseKeyMasked)
	}
	if res.EvaluationDigest == "" {
		t.Errorf("expected non-empty evaluation digest")
	}

	// Verify metrics
	decryptions, zeroizes := sandbox.GetMetrics()
	if decryptions < 1 || zeroizes < 1 {
		t.Errorf("expected recorded metrics > 0, got decryptions=%d zeroizes=%d", decryptions, zeroizes)
	}
}

func TestIsolatedMemorySandboxUnattestedRejection(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))
	sandbox := NewIsolatedMemorySandbox(tm)

	// 1. Nil token
	_, err := sandbox.ExecuteIsolatedDecryption(
		context.Background(),
		nil,
		"deadbeef",
		"0102030405060708090a0b0c",
		make([]byte, 32),
		nil,
	)
	if err == nil || err != ErrSandboxUnattested {
		t.Errorf("expected ErrSandboxUnattested on nil token, got %v", err)
	}

	// 2. Tampered token
	tok, _ := tm.IssueToken(PlatformTDX, "mrtd", "rtmr0", 2, false, "nonce", "pub", 10*time.Minute)
	tok.Signature = "bad_signature"
	_, err = sandbox.ExecuteIsolatedDecryption(
		context.Background(),
		tok,
		"deadbeef",
		"0102030405060708090a0b0c",
		make([]byte, 32),
		nil,
	)
	if err == nil {
		t.Errorf("expected error on tampered token, got nil")
	}
}

func TestIsolatedMemorySandboxDecryptionFailure(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))
	sandbox := NewIsolatedMemorySandbox(tm)

	tok, _ := tm.IssueToken(PlatformTDX, "mrtd", "rtmr0", 2, false, "nonce", "pub", 10*time.Minute)
	sessionKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xff

	nonce := make([]byte, 12)
	block, _ := aes.NewCipher(sessionKey)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, []byte("plaintext"), nil)

	// Decrypt with wrong key
	_, err := sandbox.ExecuteIsolatedDecryption(
		context.Background(),
		tok,
		hex.EncodeToString(ciphertext),
		hex.EncodeToString(nonce),
		wrongKey,
		nil,
	)
	if err == nil {
		t.Errorf("expected decryption failure with wrong key, got nil")
	}
}

func TestMaskLicenseKey(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"SLB-ABCD-1234-EFGH", "SLB-****-****-EFGH"},
		{"SHORT", "SLB-****"},
		{"ABCDEF1234567890", "ABCD-****-7890"},
		{"PRO-TIER-KEY-XYZ9", "PRO-****-****-XYZ9"},
	}

	for _, c := range cases {
		got := MaskLicenseKey(c.input)
		if got != c.expected {
			t.Errorf("MaskLicenseKey(%q) = %q, expected %q", c.input, got, c.expected)
		}
	}
}
