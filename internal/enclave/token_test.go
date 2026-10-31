package enclave

import (
	"testing"
	"time"
)

func TestAttestationTokenLifecycle(t *testing.T) {
	key := []byte("master_attestation_signing_key_32_bytes_test")
	tm := NewTokenManager(key)

	measurement := "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
	rtmr0 := "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	svn := uint32(2)
	nonce := "challenge_nonce_12345"
	pubKey := "04abcdef123456"

	// 1. Issue Token
	tok, err := tm.IssueToken(PlatformTDX, measurement, rtmr0, svn, false, nonce, pubKey, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	if tok.TokenID == "" || tok.Signature == "" {
		t.Fatalf("expected populated tokenID and signature, got id=%s sig=%s", tok.TokenID, tok.Signature)
	}
	if tok.Platform != PlatformTDX {
		t.Errorf("expected PlatformTDX, got %s", tok.Platform)
	}

	// 2. Verify Token
	res, err := tm.VerifyToken(tok, 1, false)
	if err != nil {
		t.Fatalf("VerifyToken failed on valid token: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected res.Valid=true, got false")
	}
	if res.SVN != 2 {
		t.Errorf("expected SVN 2, got %d", res.SVN)
	}
	if res.Measurement != measurement {
		t.Errorf("expected measurement match")
	}

	// 3. Retrieval by ID
	retrieved, exists := tm.GetToken(tok.TokenID)
	if !exists || retrieved == nil {
		t.Fatalf("GetToken failed to find token by ID: %s", tok.TokenID)
	}
	if retrieved.Signature != tok.Signature {
		t.Errorf("retrieved token signature mismatch")
	}
}

func TestAttestationTokenExpiration(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))

	// Issue token with negative TTL (already expired)
	tok, err := tm.IssueToken(PlatformSEVSNP, "meas_sev_snp", "", 1, false, "nonce", "pub", -1*time.Second)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}
	// Manually set past expiration
	tok.ExpiresAt = time.Now().UTC().Add(-5 * time.Second)
	tok.Signature = tm.SignToken(tok)

	res, err := tm.VerifyToken(tok, 1, false)
	if err == nil || err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v (res=%v)", err, res)
	}
}

func TestAttestationTokenTamperSignature(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))

	tok, err := tm.IssueToken(PlatformTDX, "mrtd_val", "rtmr0_val", 2, false, "nonce", "pub", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// Tamper SVN without re-signing
	tok.SVN = 99
	res, err := tm.VerifyToken(tok, 1, false)
	if err == nil || err != ErrTokenInvalidSig {
		t.Errorf("expected ErrTokenInvalidSig on tampered token, got %v (res=%v)", err, res)
	}

	// Tamper Signature string directly
	tok.SVN = 2
	tok.Signature = "bad_hex_signature_12345"
	_, err = tm.VerifyToken(tok, 1, false)
	if err == nil || err != ErrTokenInvalidSig {
		t.Errorf("expected ErrTokenInvalidSig on bad signature hex, got %v", err)
	}
}

func TestAttestationTokenRevocation(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))

	tok, err := tm.IssueToken(PlatformTDX, "mrtd_val", "", 3, false, "nonce", "pub", 10*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// Verify before revocation
	res, err := tm.VerifyToken(tok, 1, false)
	if err != nil || !res.Valid {
		t.Fatalf("token should be valid before revocation: %v", err)
	}

	// Revoke token
	if err := tm.RevokeToken(tok.TokenID, "compromised host detected"); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	if !tm.IsRevoked(tok.TokenID) {
		t.Errorf("expected IsRevoked=true for revoked token")
	}

	// Verify after revocation
	_, err = tm.VerifyToken(tok, 1, false)
	if err == nil || err != ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestAttestationTokenSecurityConstraints(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))

	// 1. Debug forbidden check
	debugTok, _ := tm.IssueToken(PlatformTDX, "mrtd", "", 2, true, "nonce", "pub", 10*time.Minute)
	_, err := tm.VerifyToken(debugTok, 1, false) // allowDebug = false
	if err == nil || err != ErrTokenDebugForbidden {
		t.Errorf("expected ErrTokenDebugForbidden when debug not allowed, got %v", err)
	}

	// Debug allowed check
	res, err := tm.VerifyToken(debugTok, 1, true) // allowDebug = true
	if err != nil || !res.Valid {
		t.Errorf("expected valid verification when allowDebug=true, got err: %v", err)
	}

	// 2. Minimum SVN threshold check
	lowSVNTok, _ := tm.IssueToken(PlatformTDX, "mrtd", "", 1, false, "nonce", "pub", 10*time.Minute)
	_, err = tm.VerifyToken(lowSVNTok, 5, false) // required SVN = 5
	if err == nil || err != ErrTokenSVNTooLow {
		t.Errorf("expected ErrTokenSVNTooLow when SVN < minSVN, got %v", err)
	}
}

func TestAttestationTokenListAndCount(t *testing.T) {
	tm := NewTokenManager([]byte("test_secret_key_32_bytes_long_12345"))

	tm.IssueToken(PlatformTDX, "m1", "", 1, false, "n1", "p1", 10*time.Minute)
	tm.IssueToken(PlatformSEVSNP, "m2", "", 1, false, "n2", "p2", 10*time.Minute)

	if tm.ActiveCount() != 2 {
		t.Errorf("expected ActiveCount=2, got %d", tm.ActiveCount())
	}

	list := tm.ListActiveTokens()
	if len(list) != 2 {
		t.Errorf("expected 2 active tokens, got %d", len(list))
	}
}
