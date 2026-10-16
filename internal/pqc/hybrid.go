package pqc

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ecdsaSig holds the r and s big integers for ASN.1 DER encoding.
type ecdsaSig struct {
	R, S *big.Int
}

// CanonicalPayload forms the strict domain-separated binding string for hybrid verification.
func CanonicalPayload(algo, keyID, timestamp string, payloadHash string) []byte {
	return []byte(fmt.Sprintf("PQC-HYBRID-V1:%s:%s:%s:%s", algo, keyID, timestamp, payloadHash))
}

// SignHybrid signs arbitrary payload bytes using both classical and lattice algorithms.
func SignHybrid(key *HybridKeyPair, payload []byte) (*HybridSignature, error) {
	if key == nil {
		return nil, fmt.Errorf("hybrid key pair is nil")
	}
	if key.Status == "revoked" {
		return nil, fmt.Errorf("cannot sign with revoked key %s", key.KeyID)
	}

	payloadSum := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadSum[:])
	timestamp := time.Now().UTC().Format(time.RFC3339)

	canonical := CanonicalPayload(key.Algorithm, key.KeyID, timestamp, payloadHash)

	var classicalSigHex string
	switch key.Algorithm {
	case AlgoHybridP256:
		if key.ECDSAKey == nil {
			return nil, fmt.Errorf("missing ECDSA P-256 private key for hybrid mode")
		}
		digest := sha256.Sum256(canonical)
		r, s, err := ecdsa.Sign(rand.Reader, key.ECDSAKey, digest[:])
		if err != nil {
			return nil, fmt.Errorf("ecdsa sign failure: %w", err)
		}
		der, err := asn1.Marshal(ecdsaSig{R: r, S: s})
		if err != nil {
			return nil, fmt.Errorf("asn1 marshal failure: %w", err)
		}
		classicalSigHex = hex.EncodeToString(der)

	case AlgoHybridHMAC:
		if len(key.HMACSecret) == 0 {
			return nil, fmt.Errorf("missing HMAC secret for hybrid mode")
		}
		mac := hmac.New(sha256.New, key.HMACSecret)
		mac.Write(canonical)
		classicalSigHex = hex.EncodeToString(mac.Sum(nil))

	case AlgoMLDSA44, AlgoMLDSA65, AlgoMLDSA87:
		classicalSigHex = "NONE"

	default:
		return nil, fmt.Errorf("unsupported hybrid algorithm: %s", key.Algorithm)
	}

	// Post-quantum ML-DSA signature
	if key.MLDSAKey == nil {
		return nil, fmt.Errorf("missing ML-DSA private key")
	}
	mldsaSig, err := SignMLDSA(key.MLDSAKey, canonical)
	if err != nil {
		return nil, fmt.Errorf("mldsa lattice sign failure: %w", err)
	}

	return &HybridSignature{
		Algorithm:    key.Algorithm,
		KeyID:        key.KeyID,
		ClassicalSig: classicalSigHex,
		QuantumSig:   mldsaSig.RawHex,
		Timestamp:    timestamp,
		PayloadHash:  payloadHash,
	}, nil
}

// VerifyHybrid validates both the classical and post-quantum digital signatures.
func VerifyHybrid(key *HybridKeyPair, payload []byte, sig *HybridSignature) *PQCVerificationResult {
	start := time.Now()
	res := &PQCVerificationResult{
		Algorithm: sig.Algorithm,
		KeyID:     sig.KeyID,
	}

	if key == nil {
		res.ErrorMessage = "key not found"
		res.LatencyNs = time.Since(start).Nanoseconds()
		return res
	}

	if key.Status == "revoked" {
		res.ErrorMessage = fmt.Sprintf("key %s has been revoked (reason: %s)", key.KeyID, key.RevokeReason)
		res.LatencyNs = time.Since(start).Nanoseconds()
		return res
	}

	if key.Status == "rotated" {
		if key.GraceUntil != nil && time.Now().After(*key.GraceUntil) {
			res.ErrorMessage = fmt.Sprintf("key %s grace period expired", key.KeyID)
			res.LatencyNs = time.Since(start).Nanoseconds()
			return res
		}
		res.GraceActive = true
	}

	payloadSum := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadSum[:])
	if subtleEqualString(payloadHash, sig.PayloadHash) == false {
		res.ErrorMessage = "payload hash mismatch"
		res.LatencyNs = time.Since(start).Nanoseconds()
		return res
	}

	canonical := CanonicalPayload(sig.Algorithm, sig.KeyID, sig.Timestamp, sig.PayloadHash)

	// 1. Classical verification
	switch sig.Algorithm {
	case AlgoHybridP256:
		if key.ECDSAKey == nil && (key.ECDSAPublicX == "" || key.ECDSAPublicY == "") {
			res.ErrorMessage = "missing public ecdsa parameters"
			res.LatencyNs = time.Since(start).Nanoseconds()
			return res
		}
		derBytes, err := hex.DecodeString(sig.ClassicalSig)
		if err != nil {
			res.ErrorMessage = "invalid hex in classical signature"
			res.LatencyNs = time.Since(start).Nanoseconds()
			return res
		}
		var parsedSig ecdsaSig
		if _, err := asn1.Unmarshal(derBytes, &parsedSig); err != nil {
			res.ErrorMessage = "malformed ecdsa der signature"
			res.LatencyNs = time.Since(start).Nanoseconds()
			return res
		}

		var pubKey ecdsa.PublicKey
		if key.ECDSAKey != nil {
			pubKey = key.ECDSAKey.PublicKey
		} else {
			pubKey.Curve = key.ECDSAKey.Curve
			pubKey.X, _ = new(big.Int).SetString(key.ECDSAPublicX, 16)
			pubKey.Y, _ = new(big.Int).SetString(key.ECDSAPublicY, 16)
		}

		digest := sha256.Sum256(canonical)
		if ecdsa.Verify(&pubKey, digest[:], parsedSig.R, parsedSig.S) {
			res.ClassicalValid = true
		} else {
			res.ErrorMessage = "classical ecdsa verification failed"
		}

	case AlgoHybridHMAC:
		if len(key.HMACSecret) == 0 {
			res.ErrorMessage = "missing hmac secret"
			res.LatencyNs = time.Since(start).Nanoseconds()
			return res
		}
		macBytes, err := hex.DecodeString(sig.ClassicalSig)
		if err != nil {
			res.ErrorMessage = "invalid hex in classical hmac"
			res.LatencyNs = time.Since(start).Nanoseconds()
			return res
		}
		mac := hmac.New(sha256.New, key.HMACSecret)
		mac.Write(canonical)
		expectedMAC := mac.Sum(nil)
		if hmac.Equal(macBytes, expectedMAC) {
			res.ClassicalValid = true
		} else {
			res.ErrorMessage = "classical hmac verification failed"
		}

	case AlgoMLDSA44, AlgoMLDSA65, AlgoMLDSA87:
		res.ClassicalValid = true // Standalone quantum mode

	default:
		res.ErrorMessage = fmt.Sprintf("unsupported algorithm: %s", sig.Algorithm)
		res.LatencyNs = time.Since(start).Nanoseconds()
		return res
	}

	// 2. Quantum ML-DSA lattice verification
	if key.MLDSAPublic == nil {
		res.ErrorMessage = "missing mldsa public key"
		res.LatencyNs = time.Since(start).Nanoseconds()
		return res
	}

	mldsaSig, err := DecodeSignature(sig.QuantumSig)
	if err != nil {
		res.ErrorMessage = fmt.Sprintf("failed to decode quantum signature: %v", err)
		res.LatencyNs = time.Since(start).Nanoseconds()
		return res
	}

	if VerifyMLDSA(key.MLDSAPublic, canonical, mldsaSig) {
		res.QuantumValid = true
	} else {
		if res.ErrorMessage == "" {
			res.ErrorMessage = "quantum mldsa lattice verification failed"
		}
	}

	res.Valid = res.ClassicalValid && res.QuantumValid
	res.LatencyNs = time.Since(start).Nanoseconds()
	return res
}

func subtleEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return strings.EqualFold(a, b)
}
