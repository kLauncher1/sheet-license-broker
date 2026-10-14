package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"
)

func generateTestECDSAKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal pkix: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return priv, string(pemBytes)
}

func TestChallengeLifecycleAndReplay(t *testing.T) {
	mgr := NewManager()

	c, err := mgr.CreateChallenge("LIC-TEST-1234", "HWID-MACH-AAAA")
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}

	if len(c.Nonce) != 64 { // 32 bytes hex = 64 characters
		t.Errorf("expected 64 hex chars for nonce, got %d", len(c.Nonce))
	}

	// 1. First consume succeeds
	nonce, err := mgr.consumeChallenge(c.ChallengeID, "LIC-TEST-1234", "HWID-MACH-AAAA")
	if err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if nonce != c.Nonce {
		t.Errorf("nonce mismatch: expected %s, got %s", c.Nonce, nonce)
	}

	// 2. Second consume must fail (replay defense)
	_, err = mgr.consumeChallenge(c.ChallengeID, "LIC-TEST-1234", "HWID-MACH-AAAA")
	if err == nil {
		t.Fatalf("expected error on replaying consumed challenge, got nil")
	}

	// 3. Mismatched binding must fail
	c2, _ := mgr.CreateChallenge("LIC-TEST-1234", "HWID-MACH-AAAA")
	_, err = mgr.consumeChallenge(c2.ChallengeID, "LIC-OTHER", "HWID-MACH-AAAA")
	if err == nil {
		t.Fatalf("expected error on mismatched license key, got nil")
	}
}

func TestTPMQuoteVerification(t *testing.T) {
	mgr := NewManager()
	priv, pubPEM := generateTestECDSAKeyPair(t)

	pcr0 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	pcr7 := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	pcrValues := map[int]string{
		0: pcr0,
		7: pcr7,
	}
	pcrSelection := []int{0, 7}

	// Set baseline golden PCR for index 0
	mgr.SetGoldenPCR(0, pcr0)

	// Create challenge
	challenge, err := mgr.CreateChallenge("LIC-TPM-9999", "HWID-TPM-DEV1")
	if err != nil {
		t.Fatalf("create challenge failed: %v", err)
	}

	// Compute composite
	compositeDigest, err := ComputePCRComposite(pcrValues, pcrSelection, challenge.Nonce)
	if err != nil {
		t.Fatalf("composite calculation failed: %v", err)
	}
	compositeHex := hex.EncodeToString(compositeDigest)

	// Sign composite with private key
	r, s, err := ecdsa.Sign(rand.Reader, priv, compositeDigest)
	if err != nil {
		t.Fatalf("failed to sign composite: %v", err)
	}
	sigBytes, _ := asn1.Marshal(ecdsaSignature{R: r, S: s})
	sigHex := hex.EncodeToString(sigBytes)

	quote := &PCRQuote{
		PCRValues:       pcrValues,
		PCRSelection:    pcrSelection,
		CompositeDigest: compositeHex,
		Signature:       sigHex,
		AKPublicKeyPEM:  pubPEM,
	}

	// Verify quote
	rec, err := mgr.VerifyTPMQuote("LIC-TPM-9999", "HWID-TPM-DEV1", challenge.ChallengeID, quote)
	if err != nil {
		t.Fatalf("TPM quote verification failed: %v", err)
	}

	if rec.TrustLevel != TrustAttestedHardware {
		t.Errorf("expected TrustAttestedHardware, got %s", rec.TrustLevel)
	}
	if rec.PCRDigest != compositeHex {
		t.Errorf("digest mismatch in record: %s vs %s", rec.PCRDigest, compositeHex)
	}

	// Verify tampered quote is rejected
	challenge2, _ := mgr.CreateChallenge("LIC-TPM-9999", "HWID-TPM-DEV1")
	tamperedQuote := &PCRQuote{
		PCRValues:       pcrValues,
		PCRSelection:    pcrSelection,
		CompositeDigest: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		Signature:       sigHex,
		AKPublicKeyPEM:  pubPEM,
	}
	_, err = mgr.VerifyTPMQuote("LIC-TPM-9999", "HWID-TPM-DEV1", challenge2.ChallengeID, tamperedQuote)
	if err == nil {
		t.Fatalf("expected error on tampered composite digest, got nil")
	}
}

func TestSecureEnclaveVerification(t *testing.T) {
	mgr := NewManager()
	priv, pubPEM := generateTestECDSAKeyPair(t)

	challenge, err := mgr.CreateChallenge("LIC-APPLE-1234", "HWID-MAC-M3MAX")
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}

	counter := uint64(42)
	h := sha256.New()
	h.Write([]byte(challenge.Nonce))
	var cBuf [8]byte
	binary.BigEndian.PutUint64(cBuf[:], counter)
	h.Write(cBuf[:])
	data := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, priv, data)
	if err != nil {
		t.Fatalf("failed to sign enclave statement: %v", err)
	}
	sigBytes, _ := asn1.Marshal(ecdsaSignature{R: r, S: s})
	sigHex := hex.EncodeToString(sigBytes)

	enclave := &EnclaveAttestation{
		EnclaveType:   TypeSecureEnclave,
		PublicKeyPEM:  pubPEM,
		AttestReceipt: "base64-apple-receipt-data",
		Signature:     sigHex,
		Counter:       counter,
	}

	rec, err := mgr.VerifyEnclave("LIC-APPLE-1234", "HWID-MAC-M3MAX", challenge.ChallengeID, enclave)
	if err != nil {
		t.Fatalf("enclave verification failed: %v", err)
	}

	if rec.TrustLevel != TrustAttestedEnclave {
		t.Errorf("expected TrustAttestedEnclave, got %s", rec.TrustLevel)
	}
}

func TestTelemetryAntiDebuggingAndTamperScoring(t *testing.T) {
	mgr := NewManager()

	// 1. Clean report
	clean := &TelemetryReport{
		DebuggerPresent: false,
		MemoryIntegrity: true,
		SandboxDetected: false,
		HooksDetected:   false,
		ProcessChecksum: "aabbcc",
		Timestamp:       time.Now(),
	}
	score, tampered, rec, err := mgr.EvaluateTelemetry("LIC-AUDIT-1", "HWID-CLEAN-1", clean)
	if err != nil {
		t.Fatalf("clean telemetry evaluation failed: %v", err)
	}
	if score != 0 || tampered {
		t.Errorf("expected pristine score 0 and tampered=false, got score=%d, tampered=%v", score, tampered)
	}
	if rec.TrustLevel != TrustSoftwareGrace {
		t.Errorf("expected TrustSoftwareGrace for clean unverified device, got %s", rec.TrustLevel)
	}

	// 2. Memory patch detected (critical tamper)
	tamperedReport := &TelemetryReport{
		DebuggerPresent: true,
		MemoryIntegrity: false, // +50
		HooksDetected:   true,  // +35 -> total 45 + 50 + 35 = 130 -> capped to 100
		Timestamp:       time.Now(),
	}
	score, tampered, rec, err = mgr.EvaluateTelemetry("LIC-AUDIT-1", "HWID-CLEAN-1", tamperedReport)
	if err != nil {
		t.Fatalf("tampered telemetry evaluation failed: %v", err)
	}
	if !tampered || score < TamperScoreThreshold {
		t.Errorf("expected tampered=true and score >= 50, got score=%d, tampered=%v", score, tampered)
	}
	if rec.TrustLevel != TrustTampered {
		t.Errorf("expected TrustTampered, got %s", rec.TrustLevel)
	}
}

func TestConcurrentAttestations(t *testing.T) {
	mgr := NewManager()
	var wg sync.WaitGroup
	errCh := make(chan error, 50)

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			lic := fmt.Sprintf("LIC-CONC-%d", idx)
			hwid := fmt.Sprintf("HWID-CONC-%d", idx)
			c, err := mgr.CreateChallenge(lic, hwid)
			if err != nil {
				errCh <- err
				return
			}
			_, err = mgr.consumeChallenge(c.ChallengeID, lic, hwid)
			if err != nil {
				errCh <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent challenge execution error: %v", err)
	}
}
