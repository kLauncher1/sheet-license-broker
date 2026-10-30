package mlkem

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"
	"time"
)

func TestMLKEMParams(t *testing.T) {
	p768 := GetParams(AlgoMLKEM768)
	if p768.K != 3 || p768.Du != 10 || p768.Dv != 4 {
		t.Fatalf("unexpected ML-KEM-768 params: %+v", p768)
	}

	p1024 := GetParams(AlgoMLKEM1024)
	if p1024.K != 4 || p1024.Du != 11 || p1024.Dv != 5 {
		t.Fatalf("unexpected ML-KEM-1024 params: %+v", p1024)
	}
}

func TestPolyArithmetic(t *testing.T) {
	var a, b Poly
	a[0] = 100
	a[1] = 200
	b[0] = 50
	b[1] = 300

	sum := PolyAdd(a, b)
	if sum[0] != 150 || sum[1] != 500 {
		t.Fatalf("PolyAdd mismatch: got [0]=%d, [1]=%d", sum[0], sum[1])
	}

	diff := PolySub(a, b)
	if diff[0] != 50 || diff[1] != (200-300+ModulusQ)%ModulusQ {
		t.Fatalf("PolySub mismatch: got [0]=%d, [1]=%d", diff[0], diff[1])
	}

	// Test negacyclic multiplication: X^128 * X^128 = X^256 = -1 mod (X^256 + 1)
	var x128, y128 Poly
	x128[128] = 1
	y128[128] = 1
	prod := PolyMul(x128, y128)
	expected := int16(ModulusQ - 1) // -1 mod q = 3328
	if prod[0] != expected {
		t.Fatalf("Negacyclic PolyMul failed: expected prod[0]=%d (-1), got %d", expected, prod[0])
	}
}

func TestCBDAndMatrixSampling(t *testing.T) {
	seed := make([]byte, 32)
	p := SampleCBD(seed, 1, 2)
	for i := 0; i < DegreeN; i++ {
		val := p[i]
		if val > 2 && val < ModulusQ-2 {
			t.Fatalf("CBD sample coefficient out of bounds at %d: %d", i, val)
		}
	}

	var rho [32]byte
	_, _ = rand.Read(rho[:])
	A := SampleMatrixA(rho, 3)
	if len(A) != 3 || len(A[0]) != 3 {
		t.Fatalf("SampleMatrixA dimension mismatch")
	}
}

func TestCompressionRoundtrip(t *testing.T) {
	var p Poly
	for i := 0; i < DegreeN; i++ {
		p[i] = int16(i * 13 % ModulusQ)
	}

	compressed := CompressPoly(p, 10)
	decompressed := DecompressPoly(compressed, 10)

	// Check error bounds for d=10 (q / 2^10 = 3329 / 1024 ~= 3.25)
	for i := 0; i < DegreeN; i++ {
		diff := int32(p[i]) - int32(decompressed[i])
		if diff < 0 {
			diff = -diff
		}
		if diff > ModulusQ/2 {
			diff = ModulusQ - diff
		}
		if diff > 4 {
			t.Fatalf("compression error too large at coeff %d: diff=%d", i, diff)
		}
	}
}

func TestKeyGenAndEncapsDecapsRoundtrip(t *testing.T) {
	algos := []string{AlgoMLKEM768, AlgoMLKEM1024}

	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			pk, sk, err := GenerateKeyPair(algo)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}
			if pk.Algorithm != algo || sk.Algorithm != algo {
				t.Fatalf("algorithm mismatch")
			}

			encap, err := Encapsulate(pk)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			cBytes, err := hex.DecodeString(encap.CiphertextHex)
			if err != nil {
				t.Fatalf("invalid ciphertext hex: %v", err)
			}

			decappedSS, err := Decapsulate(sk, cBytes)
			if err != nil {
				t.Fatalf("Decapsulate failed: %v", err)
			}

			expectedSS, _ := hex.DecodeString(encap.SharedSecretHex)
			if !bytes.Equal(decappedSS, expectedSS) {
				t.Fatalf("shared secret mismatch!\ngot:  %x\nwant: %x", decappedSS, expectedSS)
			}
		})
	}
}

func TestFujisakiOkamotoImplicitRejection(t *testing.T) {
	pk, sk, err := GenerateKeyPair(AlgoMLKEM768)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	encap, err := Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	cBytes, _ := hex.DecodeString(encap.CiphertextHex)
	expectedSS, _ := hex.DecodeString(encap.SharedSecretHex)

	// Tamper with the ciphertext (flip bits in last byte)
	tampered := make([]byte, len(cBytes))
	copy(tampered, cBytes)
	tampered[len(tampered)-1] ^= 0xFF

	rejectedSS, err := Decapsulate(sk, tampered)
	if err != nil {
		t.Fatalf("Decapsulate should not fail on tampered ciphertext (implicit rejection expected): %v", err)
	}

	if bytes.Equal(rejectedSS, expectedSS) {
		t.Fatalf("Fujisaki-Okamoto implicit rejection failed: tampered ciphertext produced genuine shared secret!")
	}

	if len(rejectedSS) != 32 {
		t.Fatalf("rejected secret length mismatch: got %d", len(rejectedSS))
	}
}

func TestHybridKeyExchange(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{
		DefaultAlgorithm: AlgoMLKEM768,
		SessionTTL:       10 * time.Minute,
		QuantumEnforced:  false,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	// Client generates ephemeral P-256 ECDH
	clientPriv, clientPubBytes, err := GenerateEphemeralECDH()
	if err != nil {
		t.Fatalf("client ECDH generation failed: %v", err)
	}
	clientPubHex := hex.EncodeToString(clientPubBytes)

	// Client initiates handshake
	req := HybridHandshakeRequest{
		ClientECDHPublicKey: clientPubHex,
		RequestedMode:       ModeHybrid,
		Algorithm:           AlgoMLKEM768,
		ClientNonce:         "nonce-client-12345",
	}

	resp, err := mgr.HandleHybridHandshake(req)
	if err != nil {
		t.Fatalf("HandleHybridHandshake failed: %v", err)
	}

	if resp.SessionID == "" || resp.ServerECDHPublicKey == "" || resp.CiphertextHex == "" {
		t.Fatalf("incomplete handshake response: %+v", resp)
	}
	if !resp.QuantumResistant || resp.AgreedMode != ModeHybrid {
		t.Fatalf("unexpected agreement mode: %s, qr=%v", resp.AgreedMode, resp.QuantumResistant)
	}

	// Verify session in manager
	session, err := mgr.VerifySession(resp.SessionID)
	if err != nil {
		t.Fatalf("VerifySession failed: %v", err)
	}
	if session.AgreedMode != ModeHybrid {
		t.Fatalf("session mode mismatch")
	}

	// Client completes derivation and verifies auth tag
	serverPubBytes, _ := hex.DecodeString(resp.ServerECDHPublicKey)
	curve := elliptic.P256()
	px, py := elliptic.Unmarshal(curve, serverPubBytes)
	if px == nil || py == nil {
		t.Fatalf("failed to unmarshal server ECDH public key")
	}
	sx, sy := curve.ScalarMult(px, py, clientPriv.D.Bytes())
	if sx == nil || sy == nil {
		t.Fatalf("client scalar mult failed")
	}

	authData, err := VerifySessionAuth(session.SessionKeyBytes, resp.AuthTagHex)
	if err != nil {
		t.Fatalf("VerifySessionAuth failed: %v", err)
	}
	if !bytes.Contains(authData, []byte(resp.SessionID)) {
		t.Fatalf("auth data does not contain session ID: %s", string(authData))
	}
}

func TestClassicalFallbackAndDowngradeEnforcement(t *testing.T) {
	// 1. Quantum enforcement OFF: fallback should succeed
	mgrSoft, err := NewManager(ManagerConfig{QuantumEnforced: false})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgrSoft.Close()

	_, clientPubBytes, _ := GenerateEphemeralECDH()
	clientPubHex := hex.EncodeToString(clientPubBytes)

	req := HybridHandshakeRequest{
		ClientECDHPublicKey: clientPubHex,
		RequestedMode:       ModeFallback,
	}

	resp, err := mgrSoft.HandleHybridHandshake(req)
	if err != nil {
		t.Fatalf("fallback handshake should succeed when quantum enforcement is false: %v", err)
	}
	if resp.AgreedMode != ModeFallback || resp.QuantumResistant {
		t.Fatalf("expected classical fallback mode: %+v", resp)
	}

	// 2. Quantum enforcement ON: fallback MUST be rejected
	mgrStrict, err := NewManager(ManagerConfig{QuantumEnforced: true})
	if err != nil {
		t.Fatalf("NewManager strict failed: %v", err)
	}
	defer mgrStrict.Close()

	_, err = mgrStrict.HandleHybridHandshake(req)
	if err == nil {
		t.Fatalf("strict quantum enforcement should have rejected classical fallback!")
	}
	if err != ErrDowngradeRejected {
		t.Fatalf("expected ErrDowngradeRejected, got %v", err)
	}
}

func TestManagerStatusAndConcurrency(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{DefaultAlgorithm: AlgoMLKEM768})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	pk1024, err := mgr.GenerateKey(AlgoMLKEM1024)
	if err != nil {
		t.Fatalf("GenerateKey 1024 failed: %v", err)
	}

	keys := mgr.ListKeys()
	if len(keys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(keys))
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			encap, err := mgr.Encapsulate(pk1024.KeyID)
			if err != nil {
				t.Errorf("concurrent encaps failed: %v", err)
				return
			}
			cBytes, _ := hex.DecodeString(encap.CiphertextHex)
			ss, err := mgr.Decapsulate(pk1024.KeyID, cBytes)
			if err != nil {
				t.Errorf("concurrent decaps failed: %v", err)
				return
			}
			expected, _ := hex.DecodeString(encap.SharedSecretHex)
			if !bytes.Equal(ss, expected) {
				t.Errorf("concurrent ss mismatch")
			}
		}()
	}
	wg.Wait()

	status := mgr.Status()
	if !status.Initialized || status.TotalEncapsulations < 10 || status.TotalDecapsulations < 10 {
		t.Fatalf("unexpected telemetry status: %+v", status)
	}
}
