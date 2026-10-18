package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

var (
	ErrTunnelNotFound      = errors.New("enclave tunnel session not found or expired")
	ErrTunnelExpired       = errors.New("enclave tunnel session has expired")
	ErrTunnelReplayAttack  = errors.New("enclave tunnel replay attack detected; sequence number must be strictly monotonic")
	ErrTunnelInvalidKey    = errors.New("invalid client public key format for ecdh handshake")
	ErrTunnelDecryption    = errors.New("enclave tunnel gcm authentication or decryption failed")
)

const (
	TunnelHKDFInfo     = "sheet-license-enclave-tunnel-v1"
	TunnelDefaultTTL   = 30 * time.Minute
	TunnelKeySize      = 32 // AES-256
	TunnelNonceSize    = 12 // Standard GCM nonce
)

// EnclaveTunnelSession represents an authenticated, end-to-end encrypted channel to a remote enclave.
type EnclaveTunnelSession struct {
	mu             sync.Mutex
	SessionID      string
	Platform       PlatformType
	ClientPubKey   []byte
	BrokerPubKey   []byte
	ClientWriteKey []byte // 32 bytes AES-256 key
	BrokerWriteKey []byte // 32 bytes AES-256 key
	ClientSeq      uint64
	BrokerSeq      uint64
	CreatedAt      time.Time
	ExpiresAt      time.Time
	closed         bool
}

// DecryptClientMessage decrypts and verifies an incoming message sent from the client enclave.
func (s *EnclaveTunnelSession) DecryptClientMessage(msg *EncryptedTunnelMessage) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrTunnelNotFound
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, ErrTunnelExpired
	}

	// Strictly monotonic sequence verification prevents replay attacks
	if msg.Sequence <= s.ClientSeq {
		return nil, fmt.Errorf("%w: received %d, expected > %d", ErrTunnelReplayAttack, msg.Sequence, s.ClientSeq)
	}

	nonce, err := hex.DecodeString(msg.NonceHex)
	if err != nil || len(nonce) != TunnelNonceSize {
		return nil, errors.New("invalid tunnel message nonce format")
	}

	ciphertext, err := hex.DecodeString(msg.PayloadHex)
	if err != nil || len(ciphertext) < 16 {
		return nil, errors.New("invalid tunnel message payload format")
	}

	block, err := aes.NewCipher(s.ClientWriteKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Additional authenticated data: SessionID + Sequence
	aad := fmt.Sprintf("%s:%d", s.SessionID, msg.Sequence)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, ErrTunnelDecryption
	}

	s.ClientSeq = msg.Sequence
	return plaintext, nil
}

// EncryptBrokerMessage seals an outgoing payload with AES-256-GCM for transmission to the enclave.
func (s *EnclaveTunnelSession) EncryptBrokerMessage(plaintext []byte) (*EncryptedTunnelMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrTunnelNotFound
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, ErrTunnelExpired
	}

	s.BrokerSeq++
	nonce := make([]byte, TunnelNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(s.BrokerWriteKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	aad := fmt.Sprintf("%s:%d", s.SessionID, s.BrokerSeq)
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))

	return &EncryptedTunnelMessage{
		SessionID:  s.SessionID,
		Sequence:   s.BrokerSeq,
		NonceHex:   hex.EncodeToString(nonce),
		PayloadHex: hex.EncodeToString(ciphertext),
	}, nil
}

// Close destroys session keys and prevents further communication on the tunnel.
func (s *EnclaveTunnelSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		Zeroize(s.ClientWriteKey)
		Zeroize(s.BrokerWriteKey)
		s.closed = true
	}
}

// TunnelManager coordinates active encrypted tunnels to confidential enclaves.
type TunnelManager struct {
	mu       sync.RWMutex
	sessions map[string]*EnclaveTunnelSession
}

// NewTunnelManager creates a new thread-safe enclave tunnel registry.
func NewTunnelManager() *TunnelManager {
	tm := &TunnelManager{
		sessions: make(map[string]*EnclaveTunnelSession),
	}
	go tm.cleanupLoop()
	return tm
}

// EstablishHandshake executes ECDH key agreement with client enclave ephemeral public key and establishes tunnel.
func (tm *TunnelManager) EstablishHandshake(platform PlatformType, clientPubBytes []byte, ttl time.Duration) (*EnclaveTunnelSession, []byte, error) {
	if len(clientPubBytes) != 64 && len(clientPubBytes) != 65 {
		return nil, nil, ErrTunnelInvalidKey
	}

	curve := elliptic.P256()
	var clientX, clientY *big.Int
	if len(clientPubBytes) == 65 {
		// Uncompressed prefix 0x04
		clientX = new(big.Int).SetBytes(clientPubBytes[1:33])
		clientY = new(big.Int).SetBytes(clientPubBytes[33:65])
	} else {
		clientX = new(big.Int).SetBytes(clientPubBytes[0:32])
		clientY = new(big.Int).SetBytes(clientPubBytes[32:64])
	}

	if !curve.IsOnCurve(clientX, clientY) {
		return nil, nil, errors.New("client ecdh public key is not on curve P-256")
	}

	// Generate broker ephemeral keypair
	brokerPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Derive shared secret via scalar multiplication: (clientX, clientY) * brokerPriv.D
	sharedX, _ := curve.ScalarMult(clientX, clientY, brokerPriv.D.Bytes())
	sharedSecret := sharedX.Bytes()
	defer Zeroize(sharedSecret)

	// HKDF expansion to derive distinct bidirectional keys (32 bytes each)
	salt := make([]byte, 32)
	copy(salt, brokerPriv.PublicKey.X.Bytes()[:16])
	copy(salt[16:], clientX.Bytes()[:16])

	derivedKeys, err := hkdfExtractAndExpand(sharedSecret, salt, []byte(TunnelHKDFInfo), TunnelKeySize*2)
	if err != nil {
		return nil, nil, fmt.Errorf("hkdf key expansion failed: %w", err)
	}

	clientWriteKey := make([]byte, TunnelKeySize)
	brokerWriteKey := make([]byte, TunnelKeySize)
	copy(clientWriteKey, derivedKeys[0:TunnelKeySize])
	copy(brokerWriteKey, derivedKeys[TunnelKeySize:TunnelKeySize*2])
	Zeroize(derivedKeys)

	// Generate unique session ID
	sessionBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, sessionBytes); err != nil {
		return nil, nil, err
	}
	sessionID := hex.EncodeToString(sessionBytes)

	if ttl <= 0 {
		ttl = TunnelDefaultTTL
	}

	// Serialize broker public key (64 bytes X || Y with zero padding)
	brokerPubBytes := make([]byte, 64)
	bX := brokerPriv.PublicKey.X.Bytes()
	bY := brokerPriv.PublicKey.Y.Bytes()
	copy(brokerPubBytes[32-len(bX):32], bX)
	copy(brokerPubBytes[64-len(bY):64], bY)

	session := &EnclaveTunnelSession{
		SessionID:      sessionID,
		Platform:       platform,
		ClientPubKey:   clientPubBytes,
		BrokerPubKey:   brokerPubBytes,
		ClientWriteKey: clientWriteKey,
		BrokerWriteKey: brokerWriteKey,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(ttl),
	}

	tm.mu.Lock()
	tm.sessions[sessionID] = session
	tm.mu.Unlock()

	return session, brokerPubBytes, nil
}

// GetSession retrieves an active tunnel session by ID.
func (tm *TunnelManager) GetSession(sessionID string) (*EnclaveTunnelSession, error) {
	tm.mu.RLock()
	session, exists := tm.sessions[sessionID]
	tm.mu.RUnlock()

	if !exists || session.closed {
		return nil, ErrTunnelNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		session.Close()
		return nil, ErrTunnelExpired
	}
	return session, nil
}

// ActiveCount returns current count of non-expired tunnel sessions.
func (tm *TunnelManager) ActiveCount() int64 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	var count int64
	now := time.Now()
	for _, s := range tm.sessions {
		if !s.closed && now.Before(s.ExpiresAt) {
			count++
		}
	}
	return count
}

// DeriveClientTunnelKeys performs ECDH and HKDF on the client side to obtain symmetric tunnel keys.
func DeriveClientTunnelKeys(clientPriv *ecdsa.PrivateKey, brokerPubBytes []byte) (clientWriteKey, clientReadKey []byte, err error) {
	if len(brokerPubBytes) != 64 {
		return nil, nil, errors.New("invalid broker public key length")
	}
	brokerX := new(big.Int).SetBytes(brokerPubBytes[0:32])
	brokerY := new(big.Int).SetBytes(brokerPubBytes[32:64])
	curve := elliptic.P256()
	if !curve.IsOnCurve(brokerX, brokerY) {
		return nil, nil, errors.New("broker public key is not on curve P-256")
	}

	sharedX, _ := curve.ScalarMult(brokerX, brokerY, clientPriv.D.Bytes())
	sharedSecret := sharedX.Bytes()
	defer Zeroize(sharedSecret)

	salt := make([]byte, 32)
	copy(salt, brokerX.Bytes()[:16])
	copy(salt[16:], clientPriv.PublicKey.X.Bytes()[:16])

	derived, err := hkdfExtractAndExpand(sharedSecret, salt, []byte(TunnelHKDFInfo), TunnelKeySize*2)
	if err != nil {
		return nil, nil, err
	}

	writeKey := make([]byte, TunnelKeySize)
	readKey := make([]byte, TunnelKeySize)
	copy(writeKey, derived[0:TunnelKeySize])
	copy(readKey, derived[TunnelKeySize:TunnelKeySize*2])
	Zeroize(derived)

	return writeKey, readKey, nil
}

// EncryptClientTunnelMessage creates an authenticated AES-256-GCM packet from the client side.
func EncryptClientTunnelMessage(sessionID string, seq uint64, clientWriteKey []byte, plaintext []byte) (*EncryptedTunnelMessage, error) {
	nonce := make([]byte, TunnelNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(clientWriteKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := fmt.Sprintf("%s:%d", sessionID, seq)
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))

	return &EncryptedTunnelMessage{
		SessionID:  sessionID,
		Sequence:   seq,
		NonceHex:   hex.EncodeToString(nonce),
		PayloadHex: hex.EncodeToString(ciphertext),
	}, nil
}

func (tm *TunnelManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		tm.mu.Lock()
		now := time.Now()
		for id, s := range tm.sessions {
			if s.closed || now.After(s.ExpiresAt) {
				s.Close()
				delete(tm.sessions, id)
			}
		}
		tm.mu.Unlock()
	}
}

// hkdfExtractAndExpand implements RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function using SHA-256.
func hkdfExtractAndExpand(secret, salt, info []byte, outLen int) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	// Extract: PRK = HMAC-Hash(salt, IKM)
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)
	defer Zeroize(prk)

	// Expand: T(1) = HMAC(PRK, info || 0x01), T(2) = HMAC(PRK, T(1) || info || 0x02), etc.
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

