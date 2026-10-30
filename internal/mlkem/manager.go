package mlkem

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Common error definitions for ML-KEM and hybrid exchange.
var (
	ErrKeyNotFound       = errors.New("ml-kem key not found")
	ErrSessionNotFound   = errors.New("hybrid session not found or expired")
	ErrDowngradeRejected = errors.New("classical fallback rejected: post-quantum enforcement policy active")
	ErrInvalidAlgorithm  = errors.New("unsupported post-quantum algorithm")
	ErrInvalidClientPub  = errors.New("invalid client public key parameters")
)

// ManagerConfig holds configuration parameters for the ML-KEM orchestrator.
type ManagerConfig struct {
	DefaultAlgorithm string
	SessionTTL       time.Duration
	QuantumEnforced  bool
}

// Manager orchestrates lattice keys, hybrid key exchanges, and ephemeral forward-secrecy sessions.
type Manager struct {
	mu                  sync.RWMutex
	keys                map[string]*PrivateKey
	publicKeys          map[string]*PublicKey
	sessions            map[string]*HybridSession
	defaultAlgo         string
	defaultKeyID        string
	sessionTTL          time.Duration
	quantumEnforced     bool
	startTime           time.Time
	stopChan            chan struct{}

	// Operational atomic counters
	totalEncapsulations atomic.Int64
	totalDecapsulations atomic.Int64
	totalHandshakes     atomic.Int64
	fallbackAttempts    atomic.Int64
	fallbackRejected    atomic.Int64
	lastHandshakeAt     atomic.Pointer[time.Time]
}

// NewManager initializes the ML-KEM manager with default keys and session sweepers.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	algo := cfg.DefaultAlgorithm
	if algo == "" {
		algo = AlgoMLKEM768
	}

	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	mgr := &Manager{
		keys:            make(map[string]*PrivateKey),
		publicKeys:      make(map[string]*PublicKey),
		sessions:        make(map[string]*HybridSession),
		defaultAlgo:     algo,
		sessionTTL:      ttl,
		quantumEnforced: cfg.QuantumEnforced,
		startTime:       time.Now().UTC(),
		stopChan:        make(chan struct{}),
	}

	// Pre-seed default keypair
	pk, err := mgr.GenerateKey(algo)
	if err != nil {
		return nil, fmt.Errorf("failed to pre-seed default ML-KEM key: %w", err)
	}
	mgr.defaultKeyID = pk.KeyID

	// Background ticker to purge expired ephemeral sessions
	go mgr.sessionSweeper()

	return mgr, nil
}

// GenerateKey generates and registers a new ML-KEM keypair.
func (m *Manager) GenerateKey(algo string) (*PublicKey, error) {
	if algo == "" {
		algo = m.defaultAlgo
	}
	if algo != AlgoMLKEM768 && algo != AlgoMLKEM1024 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, algo)
	}

	pk, sk, err := GenerateKeyPair(algo)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[pk.KeyID] = sk
	m.publicKeys[pk.KeyID] = pk
	if m.defaultKeyID == "" {
		m.defaultKeyID = pk.KeyID
	}

	return pk, nil
}

// ListKeys returns all public ML-KEM encapsulation keys.
func (m *Manager) ListKeys() []*PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*PublicKey, 0, len(m.publicKeys))
	for _, pk := range m.publicKeys {
		res = append(res, pk)
	}
	return res
}

// GetKey returns the requested public encapsulation key.
func (m *Manager) GetKey(keyID string) (*PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if keyID == "" {
		keyID = m.defaultKeyID
	}
	pk, ok := m.publicKeys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return pk, nil
}

// Encapsulate executes encapsulation against the specified (or default) public key.
func (m *Manager) Encapsulate(keyID string) (*EncapsulationResult, error) {
	pk, err := m.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	res, err := Encapsulate(pk)
	if err != nil {
		return nil, err
	}

	m.totalEncapsulations.Add(1)
	return res, nil
}

// Decapsulate decapsulates a ciphertext using the specified private key.
func (m *Manager) Decapsulate(keyID string, ciphertext []byte) ([]byte, error) {
	m.mu.RLock()
	if keyID == "" {
		keyID = m.defaultKeyID
	}
	sk, ok := m.keys[keyID]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrKeyNotFound
	}

	ss, err := Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, err
	}

	m.totalDecapsulations.Add(1)
	return ss, nil
}

// HandleHybridHandshake performs post-quantum hybrid key exchange with client.
func (m *Manager) HandleHybridHandshake(req HybridHandshakeRequest) (*HybridHandshakeResponse, error) {
	m.totalHandshakes.Add(1)
	now := time.Now().UTC()
	m.lastHandshakeAt.Store(&now)

	reqMode := strings.ToLower(strings.TrimSpace(req.RequestedMode))
	if reqMode == "" {
		reqMode = ModeHybrid
	}

	// Downgrade protection check
	if reqMode == ModeFallback {
		m.fallbackAttempts.Add(1)
		if m.quantumEnforced {
			m.fallbackRejected.Add(1)
			return nil, ErrDowngradeRejected
		}
	}

	clientECDHPub := strings.TrimSpace(req.ClientECDHPublicKey)
	if clientECDHPub == "" {
		return nil, fmt.Errorf("%w: missing client ECDH public key", ErrInvalidClientPub)
	}

	// 1. Generate server ephemeral ECDH keypair
	serverECDHPriv, serverECDHPubBytes, err := GenerateEphemeralECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to generate server ephemeral ECDH key: %w", err)
	}
	serverECDHPubHex := hex.EncodeToString(serverECDHPubBytes)

	// 2. Determine salt from client nonce
	salt := []byte(req.ClientNonce)
	if len(salt) == 0 {
		salt = make([]byte, 32)
		_, _ = rand.Read(salt)
	}

	var sessionKey []byte
	var ciphertextHex string
	agreedMode := reqMode
	quantumResistant := false
	algo := req.Algorithm
	if algo == "" {
		algo = m.defaultAlgo
	}

	if reqMode == ModeFallback {
		// Classical fallback mode (P-256 only)
		classicalKey, err := DeriveClassicalSessionKey(serverECDHPriv, clientECDHPub, salt)
		if err != nil {
			return nil, fmt.Errorf("classical session derivation failed: %w", err)
		}
		sessionKey = classicalKey
		agreedMode = ModeFallback
		algo = "Classical-ECDH-P256"
	} else {
		// Post-quantum hybrid mode (ECDH P-256 + ML-KEM)
		pk, err := m.GetKey(req.ClientMLKEMKeyID)
		if err != nil {
			// Fall back to default key
			pk, err = m.GetKey(m.defaultKeyID)
			if err != nil {
				return nil, fmt.Errorf("failed to locate encapsulation key: %w", err)
			}
		}

		encapRes, err := Encapsulate(pk)
		if err != nil {
			return nil, fmt.Errorf("ml-kem encapsulation failed: %w", err)
		}
		ciphertextHex = encapRes.CiphertextHex
		mlkemSS, _ := hex.DecodeString(encapRes.SharedSecretHex)

		derivedKey, err := DeriveHybridSessionKey(serverECDHPriv, clientECDHPub, mlkemSS, salt)
		if err != nil {
			return nil, fmt.Errorf("hybrid key derivation failed: %w", err)
		}
		sessionKey = derivedKey
		agreedMode = ModeHybrid
		quantumResistant = true
		algo = pk.Algorithm
	}

	// 3. Generate random session ID and confirmation auth tag
	sessionIDBytes := make([]byte, 16)
	_, _ = rand.Read(sessionIDBytes)
	sessionID := fmt.Sprintf("sess-pqc-%s", hex.EncodeToString(sessionIDBytes))

	authPayload := []byte(fmt.Sprintf("%s:%s:%d", sessionID, agreedMode, now.Unix()))
	authTagHex, err := EncryptSessionAuth(sessionKey, authPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session auth confirmation: %w", err)
	}

	session := &HybridSession{
		SessionID:        sessionID,
		AgreedMode:       agreedMode,
		Algorithm:        algo,
		QuantumResistant: quantumResistant,
		SessionKeyHex:    hex.EncodeToString(sessionKey),
		SessionKeyBytes:  sessionKey,
		CreatedAt:        now,
		ExpiresAt:        now.Add(m.sessionTTL),
	}

	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	return &HybridHandshakeResponse{
		SessionID:           sessionID,
		ServerECDHPublicKey: serverECDHPubHex,
		CiphertextHex:       ciphertextHex,
		AuthTagHex:          authTagHex,
		AgreedMode:          agreedMode,
		Algorithm:           algo,
		QuantumResistant:    quantumResistant,
		ExpiresAt:           session.ExpiresAt,
	}, nil
}

// VerifySession validates and retrieves an active ephemeral session.
func (m *Manager) VerifySession(sessionID string) (*HybridSession, error) {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok || session == nil {
		return nil, ErrSessionNotFound
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		m.mu.Lock()
		delete(m.sessions, sessionID)
		m.mu.Unlock()
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// Status returns the operational telemetry snapshot of the ML-KEM manager.
func (m *Manager) Status() MLKEMStatus {
	m.mu.RLock()
	activeKeys := len(m.publicKeys)
	activeSessions := len(m.sessions)
	m.mu.RUnlock()

	var lastHandshake time.Time
	if ptr := m.lastHandshakeAt.Load(); ptr != nil {
		lastHandshake = *ptr
	}

	return MLKEMStatus{
		Initialized:         true,
		ActiveKeysCount:     activeKeys,
		DefaultAlgorithm:    m.defaultAlgo,
		ActiveSessionsCount: activeSessions,
		QuantumEnforced:     m.quantumEnforced,
		TotalEncapsulations: m.totalEncapsulations.Load(),
		TotalDecapsulations: m.totalDecapsulations.Load(),
		TotalHandshakes:     m.totalHandshakes.Load(),
		FallbackAttempts:    m.fallbackAttempts.Load(),
		FallbackRejected:    m.fallbackRejected.Load(),
		LastHandshakeAt:     lastHandshake,
		UptimeSeconds:       int64(time.Since(m.startTime).Seconds()),
	}
}

// sessionSweeper runs a periodic background task to purge expired sessions.
func (m *Manager) sessionSweeper() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.purgeExpiredSessions()
		}
	}
}

// purgeExpiredSessions removes all sessions whose expiry timestamp has passed.
func (m *Manager) purgeExpiredSessions() {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, sess := range m.sessions {
		if now.After(sess.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
}

// Close gracefully terminates background sweepers and zeroizes active session keys.
func (m *Manager) Close() {
	select {
	case <-m.stopChan:
		return
	default:
		close(m.stopChan)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sess := range m.sessions {
		zeroizeBytes(sess.SessionKeyBytes)
	}
}
