package hsm

import (
	"fmt"
	"sync"
	"time"
)

// HSMManager provides a unified facade coordinating PKCS#11 cryptoki, key derivation, and FIPS compliance.
type HSMManager struct {
	mu        sync.RWMutex
	cryptoki  *CryptokiEngine
	deriver   *KeyDeriver
	fips      *FIPSEngine
	startTime time.Time
}

// NewManager initializes the high-assurance Hardware Security Module vault manager.
func NewManager() (*HSMManager, error) {
	engine, err := NewCryptokiEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cryptoki engine: %w", err)
	}

	deriver := NewKeyDeriver(engine)
	fips := NewFIPSEngine(engine)

	return &HSMManager{
		cryptoki:  engine,
		deriver:   deriver,
		fips:      fips,
		startTime: time.Now(),
	}, nil
}

// Status returns a point-in-time telemetry snapshot of the HSM vault.
func (m *HSMManager) Status() HSMVaultStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	slots := m.cryptoki.ListSlots()
	activeSessions := m.cryptoki.ActiveSessionCount()
	ops := m.cryptoki.OperationsCount()

	tamper := false
	locked := false
	masterPresent := true

	for _, s := range slots {
		t, err := m.cryptoki.GetTokenInfo(s.SlotID)
		if err == nil {
			if t.TamperDetected {
				tamper = true
				masterPresent = false
			}
			if t.UserPinLocked {
				locked = true
			}
		}
	}

	return HSMVaultStatus{
		Initialized:       true,
		HardwareAvailable: true,
		FIPSLevel:         FIPSLevel4,
		SlotsTotal:        len(slots),
		ActiveSessions:    activeSessions,
		TamperDetected:    tamper,
		LockedOut:         locked,
		MasterKeyPresent:  masterPresent,
		OperationsCount:   ops,
		LastSelfTest:      m.fips.lastKATRun,
		UptimeSeconds:     int64(time.Since(m.startTime).Seconds()),
	}
}

// ListSlots returns metadata for all provisioned hardware slots.
func (m *HSMManager) ListSlots() []SlotInfo {
	return m.cryptoki.ListSlots()
}

// GetTokenInfo returns details for a specific slot token.
func (m *HSMManager) GetTokenInfo(slotID int) (*TokenInfo, error) {
	return m.cryptoki.GetTokenInfo(slotID)
}

// OpenSession creates a session bound to a slot token.
func (m *HSMManager) OpenSession(slotID int) (uint64, error) {
	return m.cryptoki.OpenSession(slotID)
}

// CloseSession terminates an open session.
func (m *HSMManager) CloseSession(handle uint64) error {
	return m.cryptoki.CloseSession(handle)
}

// Login authenticates an active session with User or SO credentials.
func (m *HSMManager) Login(handle uint64, userType uint32, pin string) error {
	return m.cryptoki.Login(handle, userType, pin)
}

// Logout revokes session authentication.
func (m *HSMManager) Logout(handle uint64) error {
	return m.cryptoki.Logout(handle)
}

// DeriveMasterKey executes HKDF-SHA256 key derivation within the hardware boundary.
func (m *HSMManager) DeriveMasterKey(req KeyDerivationRequest) (*KeyDerivationResponse, []byte, error) {
	return m.deriver.DeriveMasterKey(req)
}

// EncryptEnvelope performs authenticated AES-256-GCM envelope encryption under an HSM key.
func (m *HSMManager) EncryptEnvelope(req EnvelopeEncryptRequest) (*EnvelopeEncryptResponse, error) {
	return m.deriver.EncryptEnvelope(req)
}

// DecryptEnvelope performs authenticated AES-256-GCM envelope decryption under an HSM key.
func (m *HSMManager) DecryptEnvelope(req EnvelopeDecryptRequest) (*EnvelopeDecryptResponse, error) {
	return m.deriver.DecryptEnvelope(req)
}

// RunSelfTest triggers on-demand Known Answer Tests (KAT) for all cryptographic primitives.
func (m *HSMManager) RunSelfTest() []SelfTestResult {
	return m.fips.RunKATSelfTests()
}

// GetFIPSReport generates the formal FIPS 140-3 Level 4 compliance audit record.
func (m *HSMManager) GetFIPSReport() *FIPS140AuditReport {
	return m.fips.GenerateAuditReport()
}

// SimulateTamper triggers a physical or environmental tamper event on the hardware vault.
func (m *HSMManager) SimulateTamper(sensorID string) error {
	m.fips.TriggerTamperResponse(sensorID)
	return nil
}

// Zeroize performs immediate administrative zeroization across all hardware slots.
func (m *HSMManager) Zeroize() {
	m.cryptoki.Zeroize()
}
