package airgap

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// MonotonicTracker maintains the monotonic high-water mark and detects clock rollback tampering.
type MonotonicTracker struct {
	mu               sync.RWMutex
	vaultID          string
	hwid             string
	highWaterMark    int64
	monotonicCounter int64
	tampered         bool
	tamperedReason   string
	trippedAt        int64
	unlockedAt       int64
	toleranceSeconds int64
}

// NewMonotonicTracker initializes a new tracker with a specified initial timestamp and tolerance.
func NewMonotonicTracker(vaultID, hwid string, initialTimestamp int64) *MonotonicTracker {
	if initialTimestamp <= 0 {
		initialTimestamp = time.Now().Unix()
	}
	return &MonotonicTracker{
		vaultID:          vaultID,
		hwid:             hwid,
		highWaterMark:    initialTimestamp,
		monotonicCounter: 1,
		toleranceSeconds: 60, // 60-second jitter tolerance
	}
}

// RecordTime checks the given timestamp against the high-water mark.
// Returns the updated monotonic counter or an error if tampered/rolled back.
func (m *MonotonicTracker) RecordTime(timestamp int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.tampered {
		return m.monotonicCounter, ErrVaultTampered
	}

	if timestamp <= 0 {
		timestamp = time.Now().Unix()
	}

	// Detect rollback beyond tolerance
	if timestamp < (m.highWaterMark - m.toleranceSeconds) {
		m.tampered = true
		m.trippedAt = timestamp
		m.tamperedReason = fmt.Sprintf("clock rollback detected: time %d is prior to high-water mark %d", timestamp, m.highWaterMark)
		return m.monotonicCounter, ErrClockRollback
	}

	if timestamp > m.highWaterMark {
		m.highWaterMark = timestamp
	}

	m.monotonicCounter++
	return m.monotonicCounter, nil
}

// Unlock resets the tampered status if supplied with a cryptographically valid admin unlock token.
func (m *MonotonicTracker) Unlock(token *UnlockToken, adminPubKey ed25519.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if token == nil {
		return ErrInvalidUnlockToken
	}

	if len(adminPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid admin public key size: %d", len(adminPubKey))
	}

	sigBytes, err := hex.DecodeString(token.AdminSignature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrInvalidUnlockToken
	}

	// Verify target match
	if token.HWID != "" && m.hwid != "" {
		if strings.ToUpper(token.HWID) != strings.ToUpper(m.hwid) {
			return ErrHWIDMismatch
		}
	}

	// Canonical unlock signing message
	msg := fmt.Sprintf("UNLOCK:%s:%s:%s:%d", token.VaultID, token.HWID, token.Nonce, token.Timestamp)
	if !ed25519.Verify(adminPubKey, []byte(msg), sigBytes) {
		return ErrInvalidUnlockToken
	}

	// Clear tamper state
	m.tampered = false
	m.tamperedReason = ""
	m.unlockedAt = time.Now().Unix()
	if token.Timestamp > m.highWaterMark {
		m.highWaterMark = token.Timestamp
	}
	m.monotonicCounter++

	return nil
}

// State returns a snapshot of current monotonic rollback and tamper metrics.
func (m *MonotonicTracker) State() RollbackState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return RollbackState{
		VaultID:          m.vaultID,
		HWID:             m.hwid,
		HighWaterMark:    m.highWaterMark,
		MonotonicCounter: m.monotonicCounter,
		Tampered:         m.tampered,
		TamperedReason:   m.tamperedReason,
		TrippedAt:        m.trippedAt,
		UnlockedAt:       m.unlockedAt,
	}
}

// ForceTrip deliberately trips the rollback guard for testing or security defense enforcement.
func (m *MonotonicTracker) ForceTrip(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tampered = true
	m.trippedAt = time.Now().Unix()
	m.tamperedReason = reason
}
