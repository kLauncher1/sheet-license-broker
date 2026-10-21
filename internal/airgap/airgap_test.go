package airgap

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestAirgapKeypairAndTokenSigning(t *testing.T) {
	pub, priv, err := GenerateDongleKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	token := &DongleToken{
		TokenID:    "TEST-DONGLE-001",
		LicenseKey: "LIC-CORP-999",
		HWID:       "HWID-NODE-ALPHA",
		Tier:       "defense-airgap",
		Features:   []string{"scada_control", "offline_mesh"},
		MaxDevices: 1,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Unix() + 86400*30,
		Counter:    101,
	}

	if err := SignDongleToken(token, priv); err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	if token.Signature == "" || token.PublicKey == "" {
		t.Fatalf("Expected signature and public key to be populated")
	}

	// Successful verification
	if err := VerifyDongleToken(token, pub, time.Now().Unix(), "HWID-NODE-ALPHA"); err != nil {
		t.Fatalf("Verification failed on valid token: %v", err)
	}

	// Verify with embedded public key (trustedPubKey empty)
	if err := VerifyDongleToken(token, nil, time.Now().Unix(), "HWID-NODE-ALPHA"); err != nil {
		t.Fatalf("Verification failed using embedded public key: %v", err)
	}
}

func TestAirgapTokenTamperRejection(t *testing.T) {
	pub, priv, err := GenerateDongleKeypair()
	if err != nil {
		t.Fatalf("Keygen error: %v", err)
	}

	token := &DongleToken{
		TokenID:    "TEST-TAMPER-001",
		LicenseKey: "LIC-SECRET-001",
		HWID:       "HWID-SECURE-001",
		Tier:       "pro",
		MaxDevices: 1,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Unix() + 3600,
		Counter:    1,
	}
	_ = SignDongleToken(token, priv)

	// 1. Tamper with tier (privilege escalation attempt)
	token.Tier = "unlimited_admin"
	if err := VerifyDongleToken(token, pub, time.Now().Unix(), "HWID-SECURE-001"); err != ErrTamperedSignature {
		t.Fatalf("Expected ErrTamperedSignature on modified tier, got: %v", err)
	}
	token.Tier = "pro" // restore

	// 2. Tamper with signature bytes
	sigBytes, _ := hex.DecodeString(token.Signature)
	sigBytes[0] ^= 0xFF
	token.Signature = hex.EncodeToString(sigBytes)
	if err := VerifyDongleToken(token, pub, time.Now().Unix(), "HWID-SECURE-001"); err != ErrTamperedSignature {
		t.Fatalf("Expected ErrTamperedSignature on corrupted signature, got: %v", err)
	}
}

func TestAirgapTokenExpirationAndHWIDMismatch(t *testing.T) {
	pub, priv, err := GenerateDongleKeypair()
	if err != nil {
		t.Fatalf("Keygen error: %v", err)
	}

	now := time.Now().Unix()
	expiredToken := &DongleToken{
		TokenID:    "TEST-EXPIRED-001",
		LicenseKey: "LIC-EXPIRED-001",
		HWID:       "HWID-EXPIRED",
		Tier:       "basic",
		MaxDevices: 1,
		IssuedAt:   now - 7200,
		ExpiresAt:  now - 3600, // expired 1 hour ago
		Counter:    1,
	}
	_ = SignDongleToken(expiredToken, priv)

	if err := VerifyDongleToken(expiredToken, pub, now, "HWID-EXPIRED"); err != ErrTokenExpired {
		t.Fatalf("Expected ErrTokenExpired, got: %v", err)
	}

	// Valid token tested with mismatched HWID
	validToken := &DongleToken{
		TokenID:    "TEST-VALID-001",
		LicenseKey: "LIC-VALID-001",
		HWID:       "HWID-SERVER-1",
		Tier:       "basic",
		MaxDevices: 1,
		IssuedAt:   now,
		ExpiresAt:  now + 3600,
		Counter:    1,
	}
	_ = SignDongleToken(validToken, priv)

	if err := VerifyDongleToken(validToken, pub, now, "HWID-SERVER-OTHER"); err != ErrHWIDMismatch {
		t.Fatalf("Expected ErrHWIDMismatch, got: %v", err)
	}
}

func TestAirgapPackingAndQRBase45(t *testing.T) {
	_, priv, _ := GenerateDongleKeypair()
	token := &DongleToken{
		TokenID:    "TEST-PACK-001",
		LicenseKey: "LIC-AIRGAP-PACK",
		HWID:       "HWID-OFFLINE-PC",
		Tier:       "enterprise",
		Features:   []string{"airgap", "dongle", "radar"},
		MaxDevices: 2,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Unix() + 86400*14,
		Counter:    42,
	}
	_ = SignDongleToken(token, priv)

	// Pack & Unpack
	packed, err := PackDongleToken(token)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}

	unpacked, err := UnpackDongleToken(packed)
	if err != nil {
		t.Fatalf("Unpack error: %v", err)
	}

	if unpacked.TokenID != token.TokenID || unpacked.LicenseKey != token.LicenseKey || unpacked.Counter != 42 {
		t.Fatalf("Unpacked token mismatch: %+v", unpacked)
	}

	// QR Code Base45 transfer
	qrPayload := EncodeQRPayload([]byte(packed))
	if !strings.HasPrefix(qrPayload, "AIRGAP:B45:") {
		t.Fatalf("Invalid QR payload prefix: %s", qrPayload)
	}

	decodedBytes, err := DecodeQRPayload(qrPayload)
	if err != nil {
		t.Fatalf("Failed to decode QR payload: %v", err)
	}

	if string(decodedBytes) != packed {
		t.Fatalf("Decoded bytes do not match original packed string")
	}

	// Test CRC corruption detection
	qrParts := strings.Split(qrPayload, ":")
	qrParts[2] = "DEADBEEF"
	corrupted := strings.Join(qrParts, ":")
	if _, err := DecodeQRPayload(corrupted); err != ErrCorruptedQRPayload {
		t.Fatalf("Expected ErrCorruptedQRPayload on bad CRC, got: %v", err)
	}
}

func TestMonotonicTrackerRollbackAndTamperLock(t *testing.T) {
	now := time.Now().Unix()
	tracker := NewMonotonicTracker("VAULT-001", "HWID-INDUSTRIAL-01", now)

	// Normal forward progression
	c1, err := tracker.RecordTime(now + 10)
	if err != nil || c1 <= 1 {
		t.Fatalf("RecordTime forward error: %v (counter=%d)", err, c1)
	}

	c2, err := tracker.RecordTime(now + 600)
	if err != nil || c2 <= c1 {
		t.Fatalf("RecordTime jump error: %v (counter=%d)", err, c2)
	}

	// Attempt clock rollback (e.g., turning system clock back 2 days)
	_, err = tracker.RecordTime(now - 172800)
	if err != ErrClockRollback {
		t.Fatalf("Expected ErrClockRollback on retroactive timestamp, got: %v", err)
	}

	// Once tampered, subsequent operations fail with ErrVaultTampered even if timestamp is restored
	st := tracker.State()
	if !st.Tampered {
		t.Fatalf("Expected tracker state to be tampered")
	}

	_, err = tracker.RecordTime(now + 1000)
	if err != ErrVaultTampered {
		t.Fatalf("Expected ErrVaultTampered on locked vault, got: %v", err)
	}
}

func TestMonotonicTrackerAdminUnlockRecovery(t *testing.T) {
	adminPub, adminPriv, _ := GenerateDongleKeypair()
	now := time.Now().Unix()
	hwid := "HWID-SCADA-SYSTEM"
	tracker := NewMonotonicTracker("VAULT-SCADA", hwid, now)

	// Deliberately trip the tracker
	tracker.ForceTrip("simulated tamper trip")
	if !tracker.State().Tampered {
		t.Fatalf("Expected tracker to be tampered")
	}

	// Generate valid admin unlock token
	nonce := "RECOVERY-NONCE-12345"
	unlockTimestamp := now + 1200
	msg := "UNLOCK:VAULT-SCADA:" + hwid + ":" + nonce + ":" + hex.EncodeToString([]byte{}) // canonical format
	_ = msg

	// Canonical message: UNLOCK:<VaultID>:<HWID>:<Nonce>:<Timestamp>
	canonicalMsg := "UNLOCK:VAULT-SCADA:" + hwid + ":" + nonce + ":" + time.Unix(unlockTimestamp, 0).Format("2006-01-02")
	_ = canonicalMsg

	// Sign proper unlock token
	mgr, _ := NewManager(nil, adminPub)
	mgr.adminPrivKey = adminPriv
	unlockToken, err := mgr.GenerateAdminUnlockToken("VAULT-SCADA", hwid, nonce, unlockTimestamp)
	if err != nil {
		t.Fatalf("Failed to generate unlock token: %v", err)
	}

	// Attempt unlock with invalid key
	fakePub, _, _ := GenerateDongleKeypair()
	if err := tracker.Unlock(unlockToken, fakePub); err != ErrInvalidUnlockToken {
		t.Fatalf("Expected ErrInvalidUnlockToken on wrong key, got: %v", err)
	}

	// Unlock with legitimate admin key
	if err := tracker.Unlock(unlockToken, adminPub); err != nil {
		t.Fatalf("Failed to unlock tracker with valid admin token: %v", err)
	}

	st := tracker.State()
	if st.Tampered {
		t.Fatalf("Expected tamper flag to be cleared after admin unlock")
	}

	// Verify normal operations resume
	newCounter, err := tracker.RecordTime(unlockTimestamp + 10)
	if err != nil {
		t.Fatalf("Failed to record time post-unlock: %v", err)
	}
	if newCounter <= st.MonotonicCounter {
		t.Fatalf("Expected monotonic counter to increase post-unlock")
	}
}

func TestAirgapManagerFullActivationWorkflow(t *testing.T) {
	mgr, err := NewManager(nil, nil)
	if err != nil {
		t.Fatalf("Failed to init manager: %v", err)
	}

	// 1. Issue dongle token
	token, compact, qr, err := mgr.IssueDongleToken(IssueTokenRequest{
		LicenseKey: "LIC-AIRGAP-FULL",
		HWID:       "HWID-AIRGAP-CLIENT-1",
		Tier:       "enterprise",
		DaysValid:  60,
		MaxDevices: 1,
		Features:   []string{"radar", "missile_guidance", "scada"},
	})
	if err != nil {
		t.Fatalf("IssueDongleToken error: %v", err)
	}
	if token == nil || compact == "" || qr == "" {
		t.Fatalf("Expected populated token, compact string, and QR payload")
	}

	// 2. Verify token
	verified, err := mgr.VerifyDongleToken(compact, "HWID-AIRGAP-CLIENT-1", time.Now().Unix())
	if err != nil {
		t.Fatalf("VerifyDongleToken error: %v", err)
	}
	if verified.LicenseKey != "LIC-AIRGAP-FULL" {
		t.Fatalf("Verified license key mismatch: %s", verified.LicenseKey)
	}

	// 3. Activation Request and Fulfillment via QR payload
	actResp, err := mgr.RequestActivation(ActivationRequest{
		LicenseKey: "LIC-AIRGAP-ACT",
		HWID:       "HWID-OFFLINE-02",
	})
	if err != nil {
		t.Fatalf("RequestActivation error: %v", err)
	}
	if actResp.Status != "ACTIVATED" || actResp.QRPayload == "" {
		t.Fatalf("Invalid activation response: %+v", actResp)
	}

	fulfilledToken, err := mgr.FulfillActivation(actResp.QRPayload)
	if err != nil {
		t.Fatalf("FulfillActivation error: %v", err)
	}
	if fulfilledToken.LicenseKey != "LIC-AIRGAP-ACT" {
		t.Fatalf("Fulfilled token mismatch: %s", fulfilledToken.LicenseKey)
	}

	// 4. Check status telemetry
	status := mgr.GetStatus()
	if !status.VaultActive || status.TotalIssuedTokens < 2 || status.TotalActivations < 1 {
		t.Fatalf("Telemetry status mismatch: %+v", status)
	}
}
