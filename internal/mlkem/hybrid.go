package mlkem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

const hybridHKDFInfo = "sheet-broker-hybrid-kem-v2.3.0"

// GenerateEphemeralECDH generates an ephemeral NIST P-256 ECDH keypair.
func GenerateEphemeralECDH() (*ecdsa.PrivateKey, []byte, error) {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral ECDH key: %w", err)
	}

	pubBytes := elliptic.Marshal(curve, priv.PublicKey.X, priv.PublicKey.Y)
	return priv, pubBytes, nil
}

// DeriveHybridSessionKey combines classical ECDH and post-quantum ML-KEM shared secrets using HKDF-SHA256.
func DeriveHybridSessionKey(ecdhPriv *ecdsa.PrivateKey, peerPubHex string, mlkemSS []byte, salt []byte) ([]byte, error) {
	if ecdhPriv == nil {
		return nil, fmt.Errorf("ephemeral ECDH private key cannot be nil")
	}

	peerPubBytes, err := hex.DecodeString(peerPubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid peer ECDH public key hex: %w", err)
	}

	curve := elliptic.P256()
	px, py := elliptic.Unmarshal(curve, peerPubBytes)
	if px == nil || py == nil {
		return nil, fmt.Errorf("failed to unmarshal peer ECDH public key (invalid curve point)")
	}

	// Verify point is on curve
	if !curve.IsOnCurve(px, py) {
		return nil, fmt.Errorf("peer ECDH public key is not on curve P-256")
	}

	// Compute shared secret: S = priv.D * (Px, Py)
	sx, _ := curve.ScalarMult(px, py, ecdhPriv.D.Bytes())
	if sx == nil || sx.Sign() == 0 {
		return nil, fmt.Errorf("invalid scalar multiplication result (identity point)")
	}

	ecdhSecret := make([]byte, 32)
	sxBytes := sx.Bytes()
	copy(ecdhSecret[32-len(sxBytes):], sxBytes)

	// Combine secrets: IKM = ecdhSecret || mlkemSS
	ikm := append(ecdhSecret, mlkemSS...)

	sessionKey, err := hkdfExtractAndExpand(ikm, salt, []byte(hybridHKDFInfo), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive hybrid session key via HKDF: %w", err)
	}

	// Secure memory wiping for intermediate secret buffers
	zeroizeBytes(ecdhSecret)
	zeroizeBytes(ikm)

	return sessionKey, nil
}

// DeriveClassicalSessionKey derives a session key solely from classical ECDH with forward secrecy.
func DeriveClassicalSessionKey(ecdhPriv *ecdsa.PrivateKey, peerPubHex string, salt []byte) ([]byte, error) {
	if ecdhPriv == nil {
		return nil, fmt.Errorf("ephemeral ECDH private key cannot be nil")
	}

	peerPubBytes, err := hex.DecodeString(peerPubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid peer ECDH public key hex: %w", err)
	}

	curve := elliptic.P256()
	px, py := elliptic.Unmarshal(curve, peerPubBytes)
	if px == nil || py == nil || !curve.IsOnCurve(px, py) {
		return nil, fmt.Errorf("invalid peer ECDH public key on curve P-256")
	}

	sx, _ := curve.ScalarMult(px, py, ecdhPriv.D.Bytes())
	ecdhSecret := make([]byte, 32)
	sxBytes := sx.Bytes()
	copy(ecdhSecret[32-len(sxBytes):], sxBytes)

	sessionKey, err := hkdfExtractAndExpand(ecdhSecret, salt, []byte(hybridHKDFInfo+"-classical"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive classical session key: %w", err)
	}

	zeroizeBytes(ecdhSecret)
	return sessionKey, nil
}

// hkdfExtractAndExpand implements RFC 5869 Extract-and-Expand key derivation.
func hkdfExtractAndExpand(secret, salt, info []byte, outLen int) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)
	defer zeroizeBytes(prk)

	out := make([]byte, 0, outLen)
	var prev []byte
	counter := byte(1)
	for len(out) < outLen {
		expander := hmac.New(sha256.New, prk)
		if len(prev) > 0 {
			expander.Write(prev)
		}
		expander.Write(info)
		expander.Write([]byte{counter})
		prev = expander.Sum(nil)
		needed := outLen - len(out)
		if needed > len(prev) {
			needed = len(prev)
		}
		out = append(out, prev[:needed]...)
		counter++
	}
	return out, nil
}

// EncryptSessionAuth encrypts and authenticates a handshake confirmation tag using AES-256-GCM.
func EncryptSessionAuth(sessionKey []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(hybridHKDFInfo))
	return hex.EncodeToString(sealed), nil
}

// VerifySessionAuth decrypts and authenticates the confirmation tag using AES-256-GCM.
func VerifySessionAuth(sessionKey []byte, ciphertextHex string) ([]byte, error) {
	data, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, fmt.Errorf("invalid auth ciphertext hex: %w", err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("auth ciphertext is too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(hybridHKDFInfo))
	if err != nil {
		return nil, fmt.Errorf("session authentication tag verification failed: %w", err)
	}

	return plaintext, nil
}

// ParseECDHPublicKey converts uncompressed (04 || X || Y) bytes to an ecdsa.PublicKey.
func ParseECDHPublicKey(pubHex string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal curve point")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// FormatECDHPublicKey converts an ECDSA public key to uncompressed hex string.
func FormatECDHPublicKey(pub *ecdsa.PublicKey) string {
	if pub == nil {
		return ""
	}
	b := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	return hex.EncodeToString(b)
}

// zeroizeBytes securely wipes a byte slice in place.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroizeBigInt securely wipes a big.Int in place.
func zeroizeBigInt(n *big.Int) {
	if n != nil {
		words := n.Bits()
		for i := range words {
			words[i] = 0
		}
	}
}
