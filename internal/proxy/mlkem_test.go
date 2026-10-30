package proxy

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/mlkem"
)

func TestProxyMLKEMLifecycle(t *testing.T) {
	p, err := NewProxy(ProxyConfig{
		OfflineMode:          true,
		CacheTTL:             5 * time.Minute,
		MLKEMQuantumEnforced: false,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	// 1. Verify status
	status := p.GetMLKEMStatus()
	if !status.Initialized || status.ActiveKeysCount < 1 {
		t.Fatalf("unexpected ML-KEM status: %+v", status)
	}

	// 2. Generate ML-KEM-1024 key
	pk1024, err := p.GenerateMLKEMKey(mlkem.AlgoMLKEM1024)
	if err != nil {
		t.Fatalf("GenerateMLKEMKey failed: %v", err)
	}
	if pk1024.Algorithm != mlkem.AlgoMLKEM1024 {
		t.Fatalf("expected ML-KEM-1024, got %s", pk1024.Algorithm)
	}

	// 3. Encapsulate & Decapsulate
	encap, err := p.EncapsulateMLKEM(pk1024.KeyID)
	if err != nil {
		t.Fatalf("EncapsulateMLKEM failed: %v", err)
	}
	cBytes, _ := hex.DecodeString(encap.CiphertextHex)
	ss, err := p.DecapsulateMLKEM(pk1024.KeyID, cBytes)
	if err != nil {
		t.Fatalf("DecapsulateMLKEM failed: %v", err)
	}
	expectedSS, _ := hex.DecodeString(encap.SharedSecretHex)
	if hex.EncodeToString(ss) != hex.EncodeToString(expectedSS) {
		t.Fatalf("shared secret mismatch")
	}

	// 4. Hybrid Handshake
	_, clientPubBytes, err := mlkem.GenerateEphemeralECDH()
	if err != nil {
		t.Fatalf("client ECDH generation failed: %v", err)
	}
	clientPubHex := hex.EncodeToString(clientPubBytes)

	req := mlkem.HybridHandshakeRequest{
		ClientECDHPublicKey: clientPubHex,
		ClientMLKEMKeyID:    pk1024.KeyID,
		RequestedMode:       mlkem.ModeHybrid,
		Algorithm:           mlkem.AlgoMLKEM1024,
		ClientNonce:         "proxy-nonce-987",
	}

	resp, err := p.HandleHybridKEMHandshake(req)
	if err != nil {
		t.Fatalf("HandleHybridKEMHandshake failed: %v", err)
	}
	if resp.SessionID == "" || !resp.QuantumResistant {
		t.Fatalf("unexpected handshake response: %+v", resp)
	}

	// 5. Verify Session
	sess, err := p.VerifyHybridKEMSession(resp.SessionID)
	if err != nil {
		t.Fatalf("VerifyHybridKEMSession failed: %v", err)
	}
	if sess.SessionID != resp.SessionID || sess.AgreedMode != mlkem.ModeHybrid {
		t.Fatalf("session mismatch")
	}
}
