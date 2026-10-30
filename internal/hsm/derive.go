package hsm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrDecryptionFailed = errors.New("hsm: envelope decryption or authentication tag verification failed")
	ErrInvalidCiphertext= errors.New("hsm: invalid ciphertext or nonce formatting")
)

// KeyDeriver coordinates HSM-backed master key derivation and envelope cryptographic operations.
type KeyDeriver struct {
	engine *CryptokiEngine
}

// NewKeyDeriver initializes an HSM key deriver backed by the Cryptoki engine.
func NewKeyDeriver(engine *CryptokiEngine) *KeyDeriver {
	return &KeyDeriver{engine: engine}
}

// HKDFExtractAndExpand implements RFC 5869 Extract-and-Expand key derivation using pure crypto/hmac and crypto/sha256.
func HKDFExtractAndExpand(secret, salt, info []byte, outLen int) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	// Extract: PRK = HMAC-Hash(salt, IKM)
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)
	defer func() {
		for i := range prk {
			prk[i] = 0
		}
	}()

	// Expand: T(1) = HMAC(PRK, info || 0x01), T(2) = HMAC(PRK, T(1) || info || 0x02)...
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

// DeriveMasterKey derives an ephemeral or envelope encryption key using HKDF-SHA256.
func (kd *KeyDeriver) DeriveMasterKey(req KeyDerivationRequest) (*KeyDerivationResponse, []byte, error) {
	masterSeed, err := kd.engine.GetMasterSeed(req.SlotID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve master seed from slot %d: %w", req.SlotID, err)
	}
	defer func() {
		// Zeroize temporary master seed copy
		for i := range masterSeed {
			masterSeed[i] = 0
		}
	}()

	var salt []byte
	if req.SaltHex != "" {
		s, err := hex.DecodeString(req.SaltHex)
		if err == nil && len(s) > 0 {
			salt = s
		}
	}
	if len(salt) == 0 {
		salt = []byte(fmt.Sprintf("HSM-VAULT-SALT-SLOT-%d", req.SlotID))
	}

	keyLen := req.KeyLengthBits / 8
	if keyLen <= 0 {
		keyLen = 32 // Default to 256 bits for AES-256
	}

	info := fmt.Sprintf("PURPOSE:%s|CONTEXT:%s", req.Purpose, req.Context)
	derivedKey, err := HKDFExtractAndExpand(masterSeed, salt, []byte(info), keyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("hkdf key derivation failed: %w", err)
	}

	// Compute public key fingerprint
	h := sha256.Sum256(derivedKey)
	fingerprint := fmt.Sprintf("HSM-KEY-%s-%x", req.Purpose, h[:8])

	kd.engine.RecordOp()

	resp := &KeyDerivationResponse{
		SlotID:           req.SlotID,
		Purpose:          req.Purpose,
		DerivedKeyHandle: uint64(time.Now().UnixNano()),
		Fingerprint:      fingerprint,
		KeyLengthBits:    keyLen * 8,
		Algorithm:        "AES_256_GCM_HKDF_SHA256",
		DerivedAt:        time.Now(),
	}

	return resp, derivedKey, nil
}

// EncryptEnvelope performs authenticated AES-256-GCM envelope encryption under an HSM-derived key.
func (kd *KeyDeriver) EncryptEnvelope(req EnvelopeEncryptRequest) (*EnvelopeEncryptResponse, error) {
	purpose := req.Purpose
	if purpose == "" {
		purpose = "audit_token_encryption"
	}

	deriveReq := KeyDerivationRequest{
		SlotID:        req.SlotID,
		Purpose:       purpose,
		Context:       "ENVELOPE_ENCRYPT_PAYLOAD",
		KeyLengthBits: 256,
	}

	derivResp, keyBytes, err := kd.DeriveMasterKey(deriveReq)
	if err != nil {
		return nil, fmt.Errorf("envelope key derivation failed: %w", err)
	}
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("aes cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm mode initialization failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	plaintextBytes := []byte(req.Plaintext)
	aadBytes := []byte(req.AssociatedData)

	ciphertext := gcm.Seal(nil, nonce, plaintextBytes, aadBytes)
	kd.engine.RecordOp()

	return &EnvelopeEncryptResponse{
		SlotID:         req.SlotID,
		CiphertextHex:  hex.EncodeToString(ciphertext),
		NonceHex:       hex.EncodeToString(nonce),
		KeyFingerprint: derivResp.Fingerprint,
		Algorithm:      "AES_256_GCM_FIPS_140_3",
		EncryptedAt:    time.Now(),
	}, nil
}

// DecryptEnvelope performs authenticated AES-256-GCM envelope decryption under the HSM-derived key.
func (kd *KeyDeriver) DecryptEnvelope(req EnvelopeDecryptRequest) (*EnvelopeDecryptResponse, error) {
	purpose := req.Purpose
	if purpose == "" {
		purpose = "audit_token_encryption"
	}

	deriveReq := KeyDerivationRequest{
		SlotID:        req.SlotID,
		Purpose:       purpose,
		Context:       "ENVELOPE_ENCRYPT_PAYLOAD",
		KeyLengthBits: 256,
	}

	_, keyBytes, err := kd.DeriveMasterKey(deriveReq)
	if err != nil {
		return nil, fmt.Errorf("envelope key derivation failed: %w", err)
	}
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	ciphertext, err := hex.DecodeString(req.CiphertextHex)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	nonce, err := hex.DecodeString(req.NonceHex)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("aes cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm mode initialization failed: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalidCiphertext
	}

	aadBytes := []byte(req.AssociatedData)
	plaintextBytes, err := gcm.Open(nil, nonce, ciphertext, aadBytes)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	kd.engine.RecordOp()

	return &EnvelopeDecryptResponse{
		SlotID:        req.SlotID,
		Plaintext:     string(plaintextBytes),
		Authenticated: true,
		DecryptedAt:   time.Now(),
	}, nil
}
