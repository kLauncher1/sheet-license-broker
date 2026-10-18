package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

func TestZeroizeAndSecureBuffer(t *testing.T) {
	raw := []byte("confidential-license-secret-material")
	secBuf := NewSecureBuffer(raw, true)

	// Verify raw was zeroized
	for i, b := range raw {
		if b != 0 {
			t.Fatalf("raw slice byte at index %d was not zeroized: %d", i, b)
		}
	}

	data, err := secBuf.Bytes()
	if err != nil {
		t.Fatalf("unexpected error reading secure buffer: %v", err)
	}
	if string(data) != "confidential-license-secret-material" {
		t.Fatalf("unexpected buffer content: %s", string(data))
	}

	secBuf.Destroy()
	if _, err := secBuf.Bytes(); err != ErrBufferDestroyed {
		t.Fatalf("expected ErrBufferDestroyed after destroy, got: %v", err)
	}

	// Constant-time comparisons
	if !ConstantTimeCompare([]byte("alpha"), []byte("alpha")) {
		t.Fatal("ConstantTimeCompare returned false for identical slices")
	}
	if ConstantTimeCompare([]byte("alpha"), []byte("bravo")) {
		t.Fatal("ConstantTimeCompare returned true for distinct slices")
	}

	hexA := hex.EncodeToString([]byte("secret"))
	hexB := hex.EncodeToString([]byte("secret"))
	hexC := hex.EncodeToString([]byte("public"))
	if !ConstantTimeCompareHex(hexA, hexB) {
		t.Fatal("ConstantTimeCompareHex returned false for matching hex")
	}
	if ConstantTimeCompareHex(hexA, hexC) {
		t.Fatal("ConstantTimeCompareHex returned true for mismatched hex")
	}
}

func TestSGXQuoteVerification(t *testing.T) {
	attestPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attest key: %v", err)
	}

	mrEnclave := sha256.Sum256([]byte("enclave-binary-v1"))
	mrSigner := sha256.Sum256([]byte("corporate-signer-root"))
	nonce := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	nonceHash := sha256.Sum256([]byte(nonce))
	var reportData [64]byte
	copy(reportData[:32], nonceHash[:])

	// 1. Build valid production non-debug quote
	rawQuote, err := BuildMockSGXQuote(attestPriv, mrEnclave, mrSigner, 2, false, reportData)
	if err != nil {
		t.Fatalf("failed to build mock quote: %v", err)
	}

	parsed, err := ParseSGXQuote(rawQuote)
	if err != nil {
		t.Fatalf("failed to parse quote: %v", err)
	}
	if parsed.Version != 3 {
		t.Fatalf("expected version 3, got: %d", parsed.Version)
	}

	policy := &EnclavePolicy{
		ID:                "sgx-test-policy",
		Platform:          PlatformSGX,
		AllowedMREnclaves: []string{hex.EncodeToString(mrEnclave[:])},
		AllowedMRSigners:  []string{hex.EncodeToString(mrSigner[:])},
		MinISVSVN:         1,
		AllowDebug:        false,
	}

	// Verify valid quote
	result, err := VerifySGXQuote(parsed, rawQuote, nonceHash[:], policy)
	if err != nil {
		t.Fatalf("expected valid quote verification, got: %v", err)
	}
	if !result.Valid || result.Platform != PlatformSGX || result.Debug {
		t.Fatalf("unexpected attestation result: %+v", result)
	}

	// 2. Reject tampered signature
	tamperedQuote := make([]byte, len(rawQuote))
	copy(tamperedQuote, rawQuote)
	tamperedQuote[437] ^= 0xFF
	tamperedParsed, _ := ParseSGXQuote(tamperedQuote)
	if _, err := VerifySGXQuote(tamperedParsed, tamperedQuote, nonceHash[:], policy); err != ErrSGXInvalidSignature {
		t.Fatalf("expected ErrSGXInvalidSignature for tampered quote, got: %v", err)
	}

	// 3. Reject mismatched report data
	wrongNonceHash := sha256.Sum256([]byte("wrong-nonce"))
	if _, err := VerifySGXQuote(parsed, rawQuote, wrongNonceHash[:], policy); err != ErrSGXReportDataMismatch {
		t.Fatalf("expected ErrSGXReportDataMismatch, got: %v", err)
	}

	// 4. Reject debug enclave when policy prohibits debug
	debugQuote, err := BuildMockSGXQuote(attestPriv, mrEnclave, mrSigner, 2, true, reportData)
	if err != nil {
		t.Fatalf("failed to build debug quote: %v", err)
	}
	debugParsed, _ := ParseSGXQuote(debugQuote)
	if _, err := VerifySGXQuote(debugParsed, debugQuote, nonceHash[:], policy); err != ErrSGXDebugNotAllowed {
		t.Fatalf("expected ErrSGXDebugNotAllowed, got: %v", err)
	}

	// 5. Reject SVN lower than policy
	strictSVNPolicy := &EnclavePolicy{
		Platform:   PlatformSGX,
		MinISVSVN:  5,
		AllowDebug: false,
	}
	if _, err := VerifySGXQuote(parsed, rawQuote, nonceHash[:], strictSVNPolicy); err == nil {
		t.Fatal("expected error for ISVSVN lower than policy requirement")
	}
}

func TestSEVSNPReportVerification(t *testing.T) {
	vcekPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate vcek key: %v", err)
	}

	var measurement [48]byte
	h := sha256.Sum256([]byte("guest-sev-vm-image"))
	copy(measurement[:32], h[:])

	nonce := "sev-nonce-challenge-hex"
	nonceHash := sha256.Sum256([]byte(nonce))
	var reportData [64]byte
	copy(reportData[:32], nonceHash[:])

	rawReport, err := BuildMockSEVSNPReport(vcekPriv, measurement, 3, false, reportData)
	if err != nil {
		t.Fatalf("failed to build mock sev-snp report: %v", err)
	}

	parsed, err := ParseSEVSNPReport(rawReport)
	if err != nil {
		t.Fatalf("failed to parse sev-snp report: %v", err)
	}

	policy := &EnclavePolicy{
		ID:                  "sev-policy-1",
		Platform:            PlatformSEVSNP,
		AllowedMeasurements: []string{hex.EncodeToString(measurement[:])},
		MinGuestSVN:         2,
		AllowDebug:          false,
	}

	// Valid verification
	result, err := VerifySEVSNPReport(parsed, rawReport, nonceHash[:], &vcekPriv.PublicKey, policy)
	if err != nil {
		t.Fatalf("expected valid sev-snp report, got: %v", err)
	}
	if !result.Valid || result.Platform != PlatformSEVSNP || result.Debug {
		t.Fatalf("unexpected attestation result: %+v", result)
	}

	// Reject mismatched measurement
	strictMeasurementPolicy := &EnclavePolicy{
		Platform:            PlatformSEVSNP,
		AllowedMeasurements: []string{"deadbeef"},
		AllowDebug:          false,
	}
	if _, err := VerifySEVSNPReport(parsed, rawReport, nonceHash[:], &vcekPriv.PublicKey, strictMeasurementPolicy); err == nil {
		t.Fatal("expected error on mismatched measurement")
	}
}

func TestEnclaveTunnelECDHAndEncryption(t *testing.T) {
	tm := NewTunnelManager()

	// 1. Client creates ephemeral keypair
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientPubBytes := make([]byte, 64)
	copy(clientPubBytes[0:32], clientPriv.PublicKey.X.Bytes())
	copy(clientPubBytes[32:64], clientPriv.PublicKey.Y.Bytes())

	// 2. Broker establishes handshake
	session, brokerPubBytes, err := tm.EstablishHandshake(PlatformSGX, clientPubBytes, 10*time.Minute)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	// 3. Client derives matching shared secret
	brokerX := new(big.Int).SetBytes(brokerPubBytes[0:32])
	brokerY := new(big.Int).SetBytes(brokerPubBytes[32:64])
	curve := elliptic.P256()
	sharedX, _ := curve.ScalarMult(brokerX, brokerY, clientPriv.D.Bytes())
	clientSharedSecret := sharedX.Bytes()

	salt := make([]byte, 32)
	copy(salt, brokerX.Bytes()[:16])
	copy(salt[16:], clientPriv.PublicKey.X.Bytes()[:16])

	clientDerivedKeys, err := hkdfExtractAndExpand(clientSharedSecret, salt, []byte(TunnelHKDFInfo), 64)
	if err != nil {
		t.Fatalf("client hkdf failed: %v", err)
	}
	clientWriteKey := clientDerivedKeys[0:32]
	clientReadKey := clientDerivedKeys[32:64]

	// 4. Client encrypts message to broker
	clientPayload := []byte(`{"license_key":"LIC-TEST-1234","hwid":"HWID-ENCLAVE-99"}`)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	block, _ := aes.NewCipher(clientWriteKey)
	gcm, _ := cipher.NewGCM(block)
	aad := fmt.Sprintf("%s:1", session.SessionID)
	ciphertext := gcm.Seal(nil, nonce, clientPayload, []byte(aad))

	msg := &EncryptedTunnelMessage{
		SessionID:  session.SessionID,
		Sequence:   1,
		NonceHex:   hex.EncodeToString(nonce),
		PayloadHex: hex.EncodeToString(ciphertext),
	}

	// 5. Broker decrypts message
	decrypted, err := session.DecryptClientMessage(msg)
	if err != nil {
		t.Fatalf("broker failed to decrypt client message: %v", err)
	}
	if string(decrypted) != string(clientPayload) {
		t.Fatalf("payload mismatch: got %s, want %s", string(decrypted), string(clientPayload))
	}

	// 6. Enforce replay attack rejection on non-monotonic sequence
	if _, err := session.DecryptClientMessage(msg); !errors.Is(err, ErrTunnelReplayAttack) {
		t.Fatalf("expected ErrTunnelReplayAttack on repeated sequence 1, got: %v", err)
	}

	// 7. Broker replies with encrypted response
	brokerReplyPayload := []byte(`{"valid":true,"tier":"enterprise"}`)
	replyMsg, err := session.EncryptBrokerMessage(brokerReplyPayload)
	if err != nil {
		t.Fatalf("failed to encrypt broker reply: %v", err)
	}

	// 8. Client decrypts reply
	replyNonce, _ := hex.DecodeString(replyMsg.NonceHex)
	replyCiphertext, _ := hex.DecodeString(replyMsg.PayloadHex)
	readBlock, _ := aes.NewCipher(clientReadKey)
	readGCM, _ := cipher.NewGCM(readBlock)
	replyAAD := fmt.Sprintf("%s:%d", session.SessionID, replyMsg.Sequence)
	clientDecrypted, err := readGCM.Open(nil, replyNonce, replyCiphertext, []byte(replyAAD))
	if err != nil {
		t.Fatalf("client failed to decrypt broker reply: %v", err)
	}
	if string(clientDecrypted) != string(brokerReplyPayload) {
		t.Fatalf("reply mismatch: got %s, want %s", string(clientDecrypted), string(brokerReplyPayload))
	}

	session.Close()
	if _, err := session.DecryptClientMessage(msg); err != ErrTunnelNotFound {
		t.Fatalf("expected ErrTunnelNotFound on closed session, got: %v", err)
	}
}

func TestEnclaveManagerFullWorkflow(t *testing.T) {
	mgr := NewManager()

	// 1. Challenge issuance & consumption
	nonce, err := mgr.GenerateChallenge()
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}
	if len(nonce) != 64 {
		t.Fatalf("expected 32-byte (64 hex char) nonce, got %d", len(nonce))
	}

	// 2. Client enclave key & quote construction
	clientPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientPubBytes := make([]byte, 64)
	copy(clientPubBytes[0:32], clientPriv.PublicKey.X.Bytes())
	copy(clientPubBytes[32:64], clientPriv.PublicKey.Y.Bytes())

	h := sha256.New()
	h.Write([]byte(nonce))
	h.Write(clientPubBytes)
	boundDigest := h.Sum(nil)
	var reportData [64]byte
	copy(reportData[:32], boundDigest)

	attestPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrEnclave := sha256.Sum256([]byte("trusted-workload"))
	mrSigner := sha256.Sum256([]byte("trusted-signer"))
	rawQuote, err := BuildMockSGXQuote(attestPriv, mrEnclave, mrSigner, 1, false, reportData)
	if err != nil {
		t.Fatalf("failed to build quote: %v", err)
	}

	policy := &EnclavePolicy{
		ID:                "custom-sgx",
		Platform:          PlatformSGX,
		AllowedMREnclaves: []string{hex.EncodeToString(mrEnclave[:])},
		AllowedMRSigners:  []string{hex.EncodeToString(mrSigner[:])},
		MinISVSVN:         1,
		AllowDebug:        false,
	}
	mgr.RegisterPolicy(policy)

	// 3. Establish tunnel with attestation quote
	session, brokerPubHex, err := mgr.EstablishTunnel(PlatformSGX, rawQuote, nonce, "custom-sgx", hex.EncodeToString(clientPubBytes))
	if err != nil {
		t.Fatalf("failed to establish enclave tunnel: %v", err)
	}
	if session == nil || brokerPubHex == "" {
		t.Fatal("empty session or broker public key returned")
	}

	// 4. Derive keys on client side
	brokerPubBytes, _ := hex.DecodeString(brokerPubHex)
	brokerX := new(big.Int).SetBytes(brokerPubBytes[0:32])
	brokerY := new(big.Int).SetBytes(brokerPubBytes[32:64])
	sharedX, _ := elliptic.P256().ScalarMult(brokerX, brokerY, clientPriv.D.Bytes())

	salt := make([]byte, 32)
	copy(salt, brokerX.Bytes()[:16])
	copy(salt[16:], clientPriv.PublicKey.X.Bytes()[:16])

	keys, err := hkdfExtractAndExpand(sharedX.Bytes(), salt, []byte(TunnelHKDFInfo), 64)
	if err != nil {
		t.Fatalf("client hkdf failed: %v", err)
	}
	clientWriteKey := keys[0:32]
	clientReadKey := keys[32:64]

	// 5. Send encrypted evaluation query
	evalPayload := EnclaveEvalPayload{
		LicenseKey: "LIC-PRO-8899",
		HWID:       "HWID-SECURE-ENCLAVE-01",
		Timestamp:  time.Now().Unix(),
	}
	payloadBytes, _ := json.Marshal(evalPayload)

	msgNonce := make([]byte, 12)
	rand.Read(msgNonce)
	block, _ := aes.NewCipher(clientWriteKey)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, msgNonce, payloadBytes, []byte(fmt.Sprintf("%s:1", session.SessionID)))

	encMsg := &EncryptedTunnelMessage{
		SessionID:  session.SessionID,
		Sequence:   1,
		NonceHex:   hex.EncodeToString(msgNonce),
		PayloadHex: hex.EncodeToString(ciphertext),
	}

	// 6. Broker evaluates inside zero-plaintext execution environment
	encResp, err := mgr.EvaluateZeroPlaintext(session.SessionID, encMsg, func(payload *EnclaveEvalPayload) (*EnclaveEvalResponse, error) {
		if payload.LicenseKey != "LIC-PRO-8899" {
			return &EnclaveEvalResponse{Valid: false, Message: "Unknown key"}, nil
		}
		return &EnclaveEvalResponse{
			Valid:      true,
			LicenseKey: payload.LicenseKey,
			Tier:       "pro",
			Features:   []string{"confidential_computing", "sgx_attestation"},
			ExpiresAt:  "2030-01-01T00:00:00Z",
		}, nil
	})
	if err != nil {
		t.Fatalf("failed to evaluate zero plaintext: %v", err)
	}

	// 7. Client decrypts response
	respNonce, _ := hex.DecodeString(encResp.NonceHex)
	respCipher, _ := hex.DecodeString(encResp.PayloadHex)
	readBlock, _ := aes.NewCipher(clientReadKey)
	readGCM, _ := cipher.NewGCM(readBlock)
	respAAD := fmt.Sprintf("%s:%d", session.SessionID, encResp.Sequence)
	decryptedRespBytes, err := readGCM.Open(nil, respNonce, respCipher, []byte(respAAD))
	if err != nil {
		t.Fatalf("client failed to decrypt response: %v", err)
	}

	var evalResult EnclaveEvalResponse
	if err := json.Unmarshal(decryptedRespBytes, &evalResult); err != nil {
		t.Fatalf("failed to parse evaluation result: %v", err)
	}
	if !evalResult.Valid || !evalResult.ZeroPlaintextGuarantee || evalResult.Tier != "pro" {
		t.Fatalf("unexpected eval result: %+v", evalResult)
	}

	telemetry := mgr.GetTelemetry()
	if telemetry.VerifiedQuotes < 1 || telemetry.TotalEvaluations < 1 {
		t.Fatalf("telemetry not properly recorded: %+v", telemetry)
	}
}

func TestEnclaveConcurrentStress(t *testing.T) {
	mgr := NewManager()
	var wg sync.WaitGroup
	workers := 20

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			nonce, err := mgr.GenerateChallenge()
			if err != nil {
				t.Errorf("worker %d challenge error: %v", workerID, err)
				return
			}
			if !mgr.ConsumeNonce(nonce) {
				t.Errorf("worker %d failed to consume nonce", workerID)
			}
		}(i)
	}
	wg.Wait()

	telemetry := mgr.GetTelemetry()
	if telemetry.ActivePoliciesCount < 2 {
		t.Fatalf("expected at least 2 default policies, got: %d", telemetry.ActivePoliciesCount)
	}
}
