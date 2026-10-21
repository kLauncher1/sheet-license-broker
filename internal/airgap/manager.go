package airgap

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Manager orchestrates air-gapped license token generation, verification,
// monotonic rollback tracking, and offline QR-based activations.
type Manager struct {
	mu                   sync.RWMutex
	masterPrivKey        ed25519.PrivateKey
	masterPubKey         ed25519.PublicKey
	adminPubKey          ed25519.PublicKey
	adminPrivKey         ed25519.PrivateKey // Available for self-hosted or test environments
	trackers             map[string]*MonotonicTracker
	issuedTokens         map[string]*DongleToken
	totalIssuedTokens    atomic.Int64
	totalVerifiedTokens  atomic.Int64
	totalActivations     atomic.Int64
	rollbackTrippedCount atomic.Int64
}

// NewManager initializes the airgap vault manager with cryptographic keys.
// If keys are omitted, self-contained Ed25519 keypairs are generated automatically.
func NewManager(masterPriv ed25519.PrivateKey, adminPub ed25519.PublicKey) (*Manager, error) {
	m := &Manager{
		trackers:     make(map[string]*MonotonicTracker),
		issuedTokens: make(map[string]*DongleToken),
	}

	if len(masterPriv) == ed25519.PrivateKeySize {
		m.masterPrivKey = masterPriv
		m.masterPubKey = masterPriv.Public().(ed25519.PublicKey)
	} else {
		pub, priv, err := GenerateDongleKeypair()
		if err != nil {
			return nil, err
		}
		m.masterPubKey = pub
		m.masterPrivKey = priv
	}

	if len(adminPub) == ed25519.PublicKeySize {
		m.adminPubKey = adminPub
	} else {
		pub, priv, err := GenerateDongleKeypair()
		if err != nil {
			return nil, err
		}
		m.adminPubKey = pub
		m.adminPrivKey = priv
	}

	return m, nil
}

// MasterPublicKey returns the hex-encoded Ed25519 master public key.
func (m *Manager) MasterPublicKey() string {
	return hex.EncodeToString(m.masterPubKey)
}

// AdminPublicKey returns the hex-encoded Ed25519 admin public key.
func (m *Manager) AdminPublicKey() string {
	return hex.EncodeToString(m.adminPubKey)
}

// getOrCreateTracker retrieves or initializes a thread-safe monotonic tracker for a target HWID.
func (m *Manager) getOrCreateTracker(hwid string, timestamp int64) *MonotonicTracker {
	normHWID := strings.ToUpper(strings.TrimSpace(hwid))
	if normHWID == "" {
		normHWID = "DEFAULT-VAULT"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tracker, exists := m.trackers[normHWID]
	if !exists {
		tracker = NewMonotonicTracker("VAULT-"+normHWID, normHWID, timestamp)
		m.trackers[normHWID] = tracker
	}
	return tracker
}

// IssueDongleToken constructs and cryptographically signs a new offline DongleToken,
// returning the token object, its compact URL-safe base64 string, and QR-ready text.
func (m *Manager) IssueDongleToken(req IssueTokenRequest) (*DongleToken, string, string, error) {
	if strings.TrimSpace(req.LicenseKey) == "" {
		return nil, "", "", fmt.Errorf("%w: license_key required", ErrInvalidToken)
	}

	hwid := strings.ToUpper(strings.TrimSpace(req.HWID))
	now := time.Now().Unix()
	days := req.DaysValid
	if days <= 0 {
		days = 30
	}
	expiresAt := now + int64(days*86400)

	tracker := m.getOrCreateTracker(hwid, now)
	counter, err := tracker.RecordTime(now)
	if err != nil {
		if err == ErrClockRollback {
			m.rollbackTrippedCount.Add(1)
		}
		return nil, "", "", err
	}

	tier := strings.ToLower(strings.TrimSpace(req.Tier))
	if tier == "" {
		tier = "enterprise"
	}
	maxDevices := req.MaxDevices
	if maxDevices <= 0 {
		maxDevices = 1
	}

	// Generate unique Token ID
	randBuf := make([]byte, 8)
	_, _ = rand.Read(randBuf)
	tokenID := fmt.Sprintf("DONGLE-%s-%s", hex.EncodeToString(randBuf), hwid)

	token := &DongleToken{
		TokenID:    tokenID,
		LicenseKey: req.LicenseKey,
		HWID:       hwid,
		Tier:       tier,
		Features:   req.Features,
		MaxDevices: maxDevices,
		IssuedAt:   now,
		ExpiresAt:  expiresAt,
		Counter:    counter,
	}

	if err := SignDongleToken(token, m.masterPrivKey); err != nil {
		return nil, "", "", err
	}

	compact, err := PackDongleToken(token)
	if err != nil {
		return nil, "", "", err
	}

	qrPayload := EncodeQRPayload([]byte(compact))

	m.mu.Lock()
	m.issuedTokens[tokenID] = token
	m.mu.Unlock()

	m.totalIssuedTokens.Add(1)
	return token, compact, qrPayload, nil
}

// VerifyDongleToken unpacks and validates a dongle token against the master key and monotonic clock.
func (m *Manager) VerifyDongleToken(tokenStr, hwid string, currentTimestamp int64) (*DongleToken, error) {
	token, err := UnpackDongleToken(tokenStr)
	if err != nil {
		return nil, err
	}

	targetHWID := hwid
	if targetHWID == "" {
		targetHWID = token.HWID
	}

	tracker := m.getOrCreateTracker(targetHWID, currentTimestamp)
	_, err = tracker.RecordTime(currentTimestamp)
	if err != nil {
		if err == ErrClockRollback {
			m.rollbackTrippedCount.Add(1)
		}
		return nil, err
	}

	if err := VerifyDongleToken(token, m.masterPubKey, currentTimestamp, hwid); err != nil {
		return nil, err
	}

	m.totalVerifiedTokens.Add(1)
	return token, nil
}

// RequestActivation generates a full activation payload responding to an offline machine's challenge.
func (m *Manager) RequestActivation(req ActivationRequest) (*ActivationResponse, error) {
	if strings.TrimSpace(req.LicenseKey) == "" || strings.TrimSpace(req.HWID) == "" {
		return nil, fmt.Errorf("%w: license_key and hwid required", ErrInvalidActivationPayload)
	}

	token, compact, qrPayload, err := m.IssueDongleToken(IssueTokenRequest{
		LicenseKey: req.LicenseKey,
		HWID:       req.HWID,
		Tier:       "enterprise-airgap",
		DaysValid:  90,
		MaxDevices: 1,
	})
	if err != nil {
		return nil, err
	}

	m.totalActivations.Add(1)

	reqID := req.RequestID
	if reqID == "" {
		reqID = fmt.Sprintf("ACT-%d", time.Now().UnixNano())
	}

	return &ActivationResponse{
		RequestID:   reqID,
		LicenseKey:  req.LicenseKey,
		HWID:        req.HWID,
		DongleToken: compact,
		QRPayload:   qrPayload,
		ValidUntil:  token.ExpiresAt,
		Counter:     token.Counter,
		Status:      "ACTIVATED",
		Signature:   token.Signature,
	}, nil
}

// FulfillActivation processes an air-gap QR payload and returns the verified DongleToken.
func (m *Manager) FulfillActivation(qrPayload string) (*DongleToken, error) {
	payloadBytes, err := DecodeQRPayload(qrPayload)
	if err != nil {
		return nil, err
	}

	tokenStr := string(payloadBytes)
	return m.VerifyDongleToken(tokenStr, "", time.Now().Unix())
}

// UnlockRollback restores a tripped monotonic vault state using a valid admin unlock token.
func (m *Manager) UnlockRollback(req UnlockRequest) (*RollbackState, error) {
	tracker := m.getOrCreateTracker(req.HWID, req.Timestamp)
	token := &UnlockToken{
		VaultID:        req.VaultID,
		HWID:           req.HWID,
		Nonce:          req.Nonce,
		Timestamp:      req.Timestamp,
		AdminSignature: req.AdminSignature,
	}

	if err := tracker.Unlock(token, m.adminPubKey); err != nil {
		return nil, err
	}

	st := tracker.State()
	return &st, nil
}

// GenerateAdminUnlockToken creates a signed unlock token for administrative restoration.
func (m *Manager) GenerateAdminUnlockToken(vaultID, hwid, nonce string, timestamp int64) (*UnlockToken, error) {
	if len(m.adminPrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("admin private key not loaded in current environment")
	}

	if timestamp <= 0 {
		timestamp = time.Now().Unix()
	}

	msg := fmt.Sprintf("UNLOCK:%s:%s:%s:%d", vaultID, hwid, nonce, timestamp)
	sig := ed25519.Sign(m.adminPrivKey, []byte(msg))

	return &UnlockToken{
		VaultID:        vaultID,
		HWID:           hwid,
		Nonce:          nonce,
		Timestamp:      timestamp,
		AdminSignature: hex.EncodeToString(sig),
	}, nil
}

// GetRollbackState returns the current state of a tracker for a specific HWID.
func (m *Manager) GetRollbackState(hwid string) *RollbackState {
	normHWID := strings.ToUpper(strings.TrimSpace(hwid))
	m.mu.RLock()
	tracker, exists := m.trackers[normHWID]
	m.mu.RUnlock()

	if !exists {
		return &RollbackState{
			VaultID:          "VAULT-" + normHWID,
			HWID:             normHWID,
			HighWaterMark:    time.Now().Unix(),
			MonotonicCounter: 1,
			Tampered:         false,
		}
	}

	st := tracker.State()
	return &st
}

// GetStatus returns the operational status and telemetry of the air-gap vault.
func (m *Manager) GetStatus() AirgapStatus {
	m.mu.RLock()
	tracked := len(m.trackers)
	var lastHWM int64
	for _, t := range m.trackers {
		st := t.State()
		if st.HighWaterMark > lastHWM {
			lastHWM = st.HighWaterMark
		}
	}
	m.mu.RUnlock()

	return AirgapStatus{
		VaultActive:          true,
		MasterPublicKey:      m.MasterPublicKey(),
		AdminPublicKey:       m.AdminPublicKey(),
		TotalIssuedTokens:    m.totalIssuedTokens.Load(),
		TotalVerifiedTokens:  m.totalVerifiedTokens.Load(),
		TotalActivations:     m.totalActivations.Load(),
		RollbackTrippedCount: m.rollbackTrippedCount.Load(),
		LastHighWaterMark:    lastHWM,
		TrackedVaults:        tracked,
		Timestamp:            time.Now().UTC(),
	}
}
