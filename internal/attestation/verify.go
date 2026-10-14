package attestation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// ComputePCRComposite calculates a deterministic SHA-256 digest over selected PCRs and challenge nonce.
func ComputePCRComposite(pcrValues map[int]string, selection []int, nonce string) ([]byte, error) {
	if len(pcrValues) == 0 {
		return nil, errors.New("empty PCR values")
	}

	indices := make([]int, 0, len(selection))
	indices = append(indices, selection...)
	sort.Ints(indices)

	h := sha256.New()
	for _, idx := range indices {
		valHex, ok := pcrValues[idx]
		if !ok {
			return nil, fmt.Errorf("selected PCR %d missing from quote values", idx)
		}
		cleanHex := strings.TrimSpace(valHex)
		valBytes, err := hex.DecodeString(cleanHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hex encoding for PCR %d: %w", idx, err)
		}

		var idxBuf [4]byte
		binary.BigEndian.PutUint32(idxBuf[:], uint32(idx))
		h.Write(idxBuf[:])
		h.Write(valBytes)
	}

	cleanNonce := strings.TrimSpace(nonce)
	h.Write([]byte(cleanNonce))
	return h.Sum(nil), nil
}

// VerifyPCRQuote validates the composite digest and cryptographic signature of a TPM 2.0 quote.
func VerifyPCRQuote(quote *PCRQuote, nonce string, expectedPCRs map[int]string) (bool, string, error) {
	if quote == nil {
		return false, "", errors.New("nil quote")
	}

	// 1. Verify expected PCR values if baseline is provided
	if len(expectedPCRs) > 0 {
		for idx, expHex := range expectedPCRs {
			actualHex, exists := quote.PCRValues[idx]
			if !exists {
				return false, "", fmt.Errorf("baseline PCR %d missing in quote", idx)
			}
			if subtle.ConstantTimeCompare([]byte(strings.ToLower(actualHex)), []byte(strings.ToLower(expHex))) != 1 {
				return false, "", fmt.Errorf("PCR %d mismatch against golden baseline", idx)
			}
		}
	}

	// 2. Compute expected composite digest
	computedDigest, err := ComputePCRComposite(quote.PCRValues, quote.PCRSelection, nonce)
	if err != nil {
		return false, "", fmt.Errorf("failed to compute composite digest: %w", err)
	}
	computedHex := hex.EncodeToString(computedDigest)

	// 3. Compare with quote's composite digest
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(quote.CompositeDigest)), []byte(computedHex)) != 1 {
		return false, "", errors.New("quote composite digest does not match computed PCR+nonce hash")
	}

	// 4. Verify signature using AK public key if provided
	if strings.TrimSpace(quote.AKPublicKeyPEM) != "" && strings.TrimSpace(quote.Signature) != "" {
		valid, err := VerifyECDSASignature(quote.AKPublicKeyPEM, computedDigest, quote.Signature)
		if err != nil {
			return false, "", fmt.Errorf("AK signature verification error: %w", err)
		}
		if !valid {
			return false, "", errors.New("invalid cryptographic signature over TPM quote")
		}
	}

	return true, computedHex, nil
}

// VerifyECDSASignature verifies an ECDSA ASN.1 or raw R||S signature against data bytes.
func VerifyECDSASignature(pubKeyPEM string, data []byte, sigHex string) (bool, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return false, errors.New("failed to parse PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("public key is not an ECDSA key")
	}

	sigBytes, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return false, fmt.Errorf("invalid hex encoded signature: %w", err)
	}

	// Try ASN.1 decoding first
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(sigBytes, &sig); err == nil && sig.R != nil && sig.S != nil {
		return ecdsa.Verify(ecdsaPub, data, sig.R, sig.S), nil
	}

	// Fallback to raw (R || S) format (32 bytes R + 32 bytes S for P-256)
	if len(sigBytes) == 64 {
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		return ecdsa.Verify(ecdsaPub, data, r, s), nil
	}

	return false, errors.New("unrecognized signature format (must be ASN.1 DER or IEEE P1363 raw 64-byte)")
}

// VerifyEnclaveStatement validates an Apple Secure Enclave or Windows Hello cryptographic statement.
func VerifyEnclaveStatement(enclave *EnclaveAttestation, nonce string) (bool, string, error) {
	if enclave == nil {
		return false, "", errors.New("nil enclave attestation")
	}
	if strings.TrimSpace(enclave.PublicKeyPEM) == "" {
		return false, "", errors.New("missing enclave public key")
	}

	// Challenge payload: sha256(nonce || counter)
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(nonce)))
	var cBuf [8]byte
	binary.BigEndian.PutUint64(cBuf[:], enclave.Counter)
	h.Write(cBuf[:])
	expectedData := h.Sum(nil)

	if strings.TrimSpace(enclave.Signature) != "" {
		valid, err := VerifyECDSASignature(enclave.PublicKeyPEM, expectedData, enclave.Signature)
		if err != nil {
			return false, "", fmt.Errorf("enclave signature error: %w", err)
		}
		if !valid {
			return false, "", errors.New("invalid hardware signature from enclave")
		}
	}

	// Generate fingerprint of public key
	pubHash := sha256.Sum256([]byte(enclave.PublicKeyPEM))
	return true, hex.EncodeToString(pubHash[:16]), nil
}
