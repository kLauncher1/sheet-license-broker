package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/attestation"
)

type testSig struct {
	R, S *big.Int
}

func generateProxyTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return priv, string(pemBytes)
}

func TestProxyAttestationChallengeAndTPMVerify(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	licKey := "LIC-PROXY-TPM"
	hwid := "HWID-DEV-1234"

	// 1. Create challenge
	c, err := p.CreateAttestationChallenge(licKey, hwid)
	if err != nil {
		t.Fatalf("failed to create challenge: %v", err)
	}
	if c.Nonce == "" {
		t.Fatalf("expected non-empty nonce")
	}

	// 2. Prepare TPM quote
	priv, pubPEM := generateProxyTestKey(t)
	pcrVals := map[int]string{
		0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	selection := []int{0}

	compDigest, err := attestation.ComputePCRComposite(pcrVals, selection, c.Nonce)
	if err != nil {
		t.Fatalf("failed to compute composite: %v", err)
	}
	r, s, _ := ecdsa.Sign(rand.Reader, priv, compDigest)
	sigBytes, _ := asn1.Marshal(testSig{R: r, S: s})

	quote := &attestation.PCRQuote{
		PCRValues:       pcrVals,
		PCRSelection:    selection,
		CompositeDigest: hex.EncodeToString(compDigest),
		Signature:       hex.EncodeToString(sigBytes),
		AKPublicKeyPEM:  pubPEM,
	}

	rec, err := p.VerifyTPMAttestation(context.Background(), licKey, hwid, c.ChallengeID, quote)
	if err != nil {
		t.Fatalf("VerifyTPMAttestation failed: %v", err)
	}
	if rec.TrustLevel != attestation.TrustAttestedHardware {
		t.Errorf("expected TrustAttestedHardware, got %s", rec.TrustLevel)
	}

	// 3. Query status
	saved, found := p.GetAttestationStatus(licKey, hwid)
	if !found {
		t.Fatalf("expected record to be found")
	}
	if saved.TrustLevel != attestation.TrustAttestedHardware {
		t.Errorf("expected saved TrustAttestedHardware, got %s", saved.TrustLevel)
	}
}

func TestProxyEnclaveAttestation(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	licKey := "LIC-ENCLAVE-1"
	hwid := "HWID-ENCLAVE-1"

	c, err := p.CreateAttestationChallenge(licKey, hwid)
	if err != nil {
		t.Fatalf("create challenge failed: %v", err)
	}

	priv, pubPEM := generateProxyTestKey(t)
	counter := uint64(10)
	h := sha256.New()
	h.Write([]byte(c.Nonce))
	var cBuf [8]byte
	binary.BigEndian.PutUint64(cBuf[:], counter)
	h.Write(cBuf[:])
	data := h.Sum(nil)

	r, s, _ := ecdsa.Sign(rand.Reader, priv, data)
	sigBytes, _ := asn1.Marshal(testSig{R: r, S: s})

	enclave := &attestation.EnclaveAttestation{
		EnclaveType:  attestation.TypeWindowsHello,
		PublicKeyPEM: pubPEM,
		Signature:    hex.EncodeToString(sigBytes),
		Counter:      counter,
	}

	rec, err := p.VerifyEnclaveAttestation(context.Background(), licKey, hwid, c.ChallengeID, enclave)
	if err != nil {
		t.Fatalf("VerifyEnclaveAttestation failed: %v", err)
	}
	if rec.TrustLevel != attestation.TrustAttestedEnclave {
		t.Errorf("expected TrustAttestedEnclave, got %s", rec.TrustLevel)
	}
}

func TestProxyTelemetryTamperAutoMitigation(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	licKey := "LIC-TAMPER-TARGET"
	hwid := "HWID-ROGUE-DEV"

	// 1. Submit critical tamper report
	tamperReport := &attestation.TelemetryReport{
		DebuggerPresent:  true,
		MemoryIntegrity:  false, // Corrupted / patched code section
		HooksDetected:    true,
		ExecutionUptimeS: 120,
		Timestamp:        time.Now(),
	}

	score, tampered, rec, err := p.SubmitAttestationTelemetry(context.Background(), licKey, hwid, tamperReport)
	if err != nil {
		t.Fatalf("SubmitAttestationTelemetry failed: %v", err)
	}
	if !tampered || score < 50 {
		t.Fatalf("expected tampered=true and score >= 50, got score=%d, tampered=%v", score, tampered)
	}
	if rec.TrustLevel != attestation.TrustTampered {
		t.Errorf("expected TrustTampered, got %s", rec.TrustLevel)
	}

	// 2. Verify automatic blacklist and revocation
	if banned, _ := p.localLicense.Blacklist().IsDeviceBlacklisted(hwid); !banned {
		t.Errorf("expected device %s to be banned automatically in blacklist", hwid)
	}
	if revoked, _ := p.localLicense.Blacklist().IsLicenseBlacklisted(licKey); !revoked {
		t.Errorf("expected license %s to be revoked automatically in blacklist", licKey)
	}
}
