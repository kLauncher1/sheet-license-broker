package pqc

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPolynomialRingArithmetic(t *testing.T) {
	// 1. Ring addition and subtraction
	var a, b Poly
	a[0] = 100
	a[1] = ModulusQ - 50
	b[0] = 50
	b[1] = 60

	c := PolyAdd(a, b)
	if c[0] != 150 {
		t.Fatalf("expected c[0] = 150, got %d", c[0])
	}
	if c[1] != 10 {
		t.Fatalf("expected c[1] = 10 (mod q), got %d", c[1])
	}

	d := PolySub(c, b)
	if d[0] != a[0] || d[1] != a[1] {
		t.Fatalf("expected PolySub to invert PolyAdd: got %d, %d; expected %d, %d", d[0], d[1], a[0], a[1])
	}

	// 2. Ring multiplication mod (X^256 + 1)
	// Let p = X^200, q = X^100 -> p*q = X^300 = -X^44
	var p1, p2 Poly
	p1[200] = 1
	p2[100] = 1
	prod := PolyMul(p1, p2)
	expected44 := modQ(-1)
	if prod[44] != expected44 {
		t.Fatalf("expected X^300 = -X^44 = %d, got %d", expected44, prod[44])
	}

	// Power2Round correctness: r = r1 * 2^d + r0 with -2^(d-1) < r0 <= 2^(d-1)
	r := int32(50000)
	r1, r0 := Power2Round(r, PowerD)
	reconstructed := r1*(1<<PowerD) + r0
	if reconstructed != r {
		t.Fatalf("Power2Round mismatch: r=%d, reconstructed=%d (r1=%d, r0=%d)", r, reconstructed, r1, r0)
	}
	if r0 <= -(1<<(PowerD-1)) || r0 > (1<<(PowerD-1)) {
		t.Fatalf("r0 out of bounds: %d", r0)
	}
}

func TestMLDSAKeyGenSignVerify(t *testing.T) {
	for _, algo := range []string{AlgoMLDSA44, AlgoMLDSA65} {
		t.Run(algo, func(t *testing.T) {
			priv, pub, err := GenerateMLDSAKeyPair(algo)
			if err != nil {
				t.Fatalf("failed to generate key pair: %v", err)
			}
			if priv == nil || pub == nil {
				t.Fatalf("keys must not be nil")
			}
			if len(pub.KeyID) == 0 {
				t.Fatalf("key ID is empty")
			}

			msg := []byte("License-Token-Enterprise-Entitlement-v1.4.0")
			sig, err := SignMLDSA(priv, msg)
			if err != nil {
				t.Fatalf("failed to sign message: %v", err)
			}
			if sig == nil {
				t.Fatalf("signature is nil")
			}

			// Verify valid signature
			if !VerifyMLDSA(pub, msg, sig) {
				t.Fatalf("signature verification failed for valid signature")
			}

			// Verify serialization round-trip
			encodedSig := EncodeSignature(sig)
			decodedSig, err := DecodeSignature(encodedSig)
			if err != nil {
				t.Fatalf("failed to decode signature: %v", err)
			}
			if !VerifyMLDSA(pub, msg, decodedSig) {
				t.Fatalf("decoded signature failed verification")
			}

			encodedPub := EncodePublicKey(pub)
			decodedPub, err := DecodePublicKey(encodedPub)
			if err != nil {
				t.Fatalf("failed to decode public key: %v", err)
			}
			if !VerifyMLDSA(decodedPub, msg, sig) {
				t.Fatalf("decoded public key failed verification")
			}

			// Rejection on tampered message
			tamperedMsg := []byte("License-Token-Enterprise-Entitlement-v1.4.0-Tampered")
			if VerifyMLDSA(pub, tamperedMsg, sig) {
				t.Fatalf("expected verification to fail on tampered message")
			}

			// Rejection on tampered signature challenge
			tamperedSig := *sig
			tamperedSig.Challenge[0] ^= 0xFF
			if VerifyMLDSA(pub, msg, &tamperedSig) {
				t.Fatalf("expected verification to fail on tampered challenge")
			}
		})
	}
}

func TestHybridSignAndVerify(t *testing.T) {
	secret := []byte("quantum-hmac-shared-secret-key-32b")
	km, err := NewKeyManager(AlgoHybridP256, secret)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	payload := []byte(`{"license_id":"LIC-ENTERPRISE-9988","hwid":"HWID-ABCD-1234-EF56"}`)

	// 1. Test Hybrid-P256-MLDSA65
	sigP256, err := km.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign hybrid P-256: %v", err)
	}

	resP256 := km.Verify(payload, sigP256)
	if !resP256.Valid {
		t.Fatalf("hybrid P-256 verification failed: %s", resP256.ErrorMessage)
	}
	if !resP256.ClassicalValid || !resP256.QuantumValid {
		t.Fatalf("both classical and quantum flags must be true: %+v", resP256)
	}

	// 2. Test Hybrid-HMAC-MLDSA44
	rec, err := km.RotateKey(AlgoHybridHMAC, 1*time.Hour, "testing hmac hybrid mode")
	if err != nil {
		t.Fatalf("failed to rotate to HMAC hybrid: %v", err)
	}
	if rec.NewKeyID == "" {
		t.Fatalf("new key ID is empty")
	}

	sigHMAC, err := km.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign hybrid HMAC: %v", err)
	}
	resHMAC := km.Verify(payload, sigHMAC)
	if !resHMAC.Valid {
		t.Fatalf("hybrid HMAC verification failed: %s", resHMAC.ErrorMessage)
	}

	// 3. Rejection of tampered payload
	tamperedPayload := []byte(`{"license_id":"LIC-ENTERPRISE-9988","hwid":"HWID-HACKED-0000"}`)
	resTampered := km.Verify(tamperedPayload, sigHMAC)
	if resTampered.Valid {
		t.Fatalf("expected verification to fail for tampered payload")
	}

	// 4. Verification with rotated old key within grace period
	resGrace := km.Verify(payload, sigP256)
	if !resGrace.Valid {
		t.Fatalf("expected old key in grace period to verify successfully: %s", resGrace.ErrorMessage)
	}
	if !resGrace.GraceActive {
		t.Fatalf("expected GraceActive to be true for rotated key")
	}
}

func TestKeyRotationAndRevocation(t *testing.T) {
	secret := []byte("rotation-revocation-test-secret")
	km, err := NewKeyManager(AlgoHybridP256, secret)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	initialKey := km.ActiveKey()
	payload := []byte("PQC-Revocation-Test-Payload")

	sig, err := km.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Immediate revocation
	if err := km.RevokeKey(initialKey.KeyID, "key compromised in red-team audit"); err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	// Verifying with revoked key must fail
	res := km.Verify(payload, sig)
	if res.Valid {
		t.Fatalf("expected verification to fail on revoked key")
	}
	if res.ErrorMessage == "" {
		t.Fatalf("expected descriptive error message on revocation")
	}

	// Active key should have automatically rolled forward
	newActive := km.ActiveKey()
	if newActive.KeyID == initialKey.KeyID {
		t.Fatalf("expected active key to auto-rotate after revocation")
	}

	// New key can sign and verify
	newSig, err := km.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign with new key: %v", err)
	}
	newRes := km.Verify(payload, newSig)
	if !newRes.Valid {
		t.Fatalf("failed to verify with new active key: %s", newRes.ErrorMessage)
	}
}

func TestPQCConcurrentStress(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	km, err := NewKeyManager(AlgoHybridP256, secret)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	workers := 25
	iterations := 2
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				data := []byte(fmt.Sprintf("worker-%d-iteration-%d", workerID, i))
				sig, err := km.Sign(data)
				if err != nil {
					t.Errorf("worker %d failed to sign: %v", workerID, err)
					return
				}
				res := km.Verify(data, sig)
				if !res.Valid {
					t.Errorf("worker %d verification failed: %s", workerID, res.ErrorMessage)
					return
				}
			}
		}(w)
	}

	wg.Wait()

	status := km.GetStatus()
	if status.VerifiedCount < uint64(workers*iterations) {
		t.Fatalf("expected at least %d verified signatures, got %d", workers*iterations, status.VerifiedCount)
	}
}
