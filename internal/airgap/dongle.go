package airgap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GenerateDongleKeypair creates a cryptographically secure Ed25519 keypair.
func GenerateDongleKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// CanonicalTokenPayload builds the deterministic signing payload for a DongleToken.
func CanonicalTokenPayload(t *DongleToken) []byte {
	featStr := strings.Join(t.Features, ",")
	msg := fmt.Sprintf("DONGLE-v1:%s:%s:%s:%s:%s:%d:%d:%d:%d",
		t.TokenID,
		t.LicenseKey,
		t.HWID,
		t.Tier,
		featStr,
		t.MaxDevices,
		t.IssuedAt,
		t.ExpiresAt,
		t.Counter,
	)
	return []byte(msg)
}

// SignDongleToken signs the canonical token payload using the given Ed25519 private key.
func SignDongleToken(t *DongleToken, privKey ed25519.PrivateKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	payload := CanonicalTokenPayload(t)
	sig := ed25519.Sign(privKey, payload)
	t.Signature = hex.EncodeToString(sig)

	// Populate public key if available
	pubKey := privKey.Public().(ed25519.PublicKey)
	t.PublicKey = hex.EncodeToString(pubKey)
	return nil
}

// VerifyDongleToken verifies the Ed25519 signature, expiration, and optional HWID match.
func VerifyDongleToken(t *DongleToken, trustedPubKey ed25519.PublicKey, currentTimestamp int64, expectedHWID string) error {
	if t == nil {
		return ErrInvalidToken
	}

	// 1. Signature format validation
	sigBytes, err := hex.DecodeString(t.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrTamperedSignature
	}

	// 2. Resolve verification public key
	var verifyKey ed25519.PublicKey
	if len(trustedPubKey) == ed25519.PublicKeySize {
		verifyKey = trustedPubKey
	} else if t.PublicKey != "" {
		pkBytes, pkErr := hex.DecodeString(t.PublicKey)
		if pkErr != nil || len(pkBytes) != ed25519.PublicKeySize {
			return ErrTamperedSignature
		}
		verifyKey = ed25519.PublicKey(pkBytes)
	} else {
		return ErrTamperedSignature
	}

	// 3. Cryptographic signature check
	payload := CanonicalTokenPayload(t)
	if !ed25519.Verify(verifyKey, payload, sigBytes) {
		return ErrTamperedSignature
	}

	// 4. Temporal validity check
	if currentTimestamp <= 0 {
		currentTimestamp = time.Now().Unix()
	}
	if t.ExpiresAt > 0 && currentTimestamp > t.ExpiresAt {
		return ErrTokenExpired
	}

	// 5. Hardware binding check (constant-time comparison)
	if expectedHWID != "" && t.HWID != "" {
		if subtle.ConstantTimeCompare([]byte(strings.ToUpper(t.HWID)), []byte(strings.ToUpper(expectedHWID))) != 1 {
			return ErrHWIDMismatch
		}
	}

	return nil
}

// PackDongleToken serializes a DongleToken into a compact URL-safe base64 string.
func PackDongleToken(t *DongleToken) (string, error) {
	if t == nil {
		return "", ErrInvalidToken
	}
	data, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to marshal dongle token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// UnpackDongleToken parses a compact URL-safe base64 string back into a DongleToken.
func UnpackDongleToken(raw string) (*DongleToken, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, ErrInvalidToken
	}

	data, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		// Fallback: standard base64 if padding was included
		var stdErr error
		data, stdErr = base64.StdEncoding.DecodeString(trimmed)
		if stdErr != nil {
			return nil, ErrInvalidToken
		}
	}

	var token DongleToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, ErrInvalidToken
	}

	if token.TokenID == "" || token.Signature == "" {
		return nil, ErrInvalidToken
	}

	return &token, nil
}
