package attestation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	ChallengeTTL         = 5 * time.Minute
	MaxActiveChallenges  = 5000
	TamperScoreThreshold = 50
)

// Manager coordinates hardware attestation challenges, quote verifications, and integrity telemetry.
type Manager struct {
	mu          sync.RWMutex
	challenges  map[string]*AttestationChallenge
	records     map[string]*AttestationRecord
	goldenPCRs  map[int]string
}

// NewManager constructs a new attestation manager with standard defaults.
func NewManager() *Manager {
	return &Manager{
		challenges: make(map[string]*AttestationChallenge),
		records:    make(map[string]*AttestationRecord),
		goldenPCRs: make(map[int]string),
	}
}

func recordKey(licenseKey, hwid string) string {
	return strings.ToUpper(strings.TrimSpace(licenseKey)) + ":" + strings.ToUpper(strings.TrimSpace(hwid))
}

// SetGoldenPCR sets or updates an expected PCR baseline value for firmware verification.
func (m *Manager) SetGoldenPCR(index int, digestHex string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.goldenPCRs[index] = strings.ToLower(strings.TrimSpace(digestHex))
}

// CreateChallenge generates a single-use cryptographically random challenge for an endpoint.
func (m *Manager) CreateChallenge(licenseKey, hwid string) (*AttestationChallenge, error) {
	normKey := strings.TrimSpace(licenseKey)
	normHWID := strings.TrimSpace(hwid)
	if normKey == "" || normHWID == "" {
		return nil, errors.New("license_key and hwid are required")
	}

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secure random nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonceBytes)

	challengeIDBytes := make([]byte, 16)
	if _, err := rand.Read(challengeIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate challenge ID: %w", err)
	}
	challengeID := hex.EncodeToString(challengeIDBytes)

	challenge := &AttestationChallenge{
		ChallengeID: challengeID,
		LicenseKey:  normKey,
		HWID:        normHWID,
		Nonce:       nonceHex,
		ExpiresAt:   time.Now().Add(ChallengeTTL),
		Consumed:    false,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Clean expired challenges if capacity exceeded
	if len(m.challenges) >= MaxActiveChallenges {
		now := time.Now()
		for k, c := range m.challenges {
			if c.Consumed || now.After(c.ExpiresAt) {
				delete(m.challenges, k)
			}
		}
	}

	m.challenges[challengeID] = challenge
	return challenge, nil
}

// consumeChallenge validates and atomically marks a challenge as consumed.
func (m *Manager) consumeChallenge(challengeID, licenseKey, hwid string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	challenge, exists := m.challenges[challengeID]
	if !exists {
		return "", errors.New("challenge not found or expired")
	}

	if challenge.Consumed {
		return "", errors.New("attestation challenge has already been used (replay detected)")
	}

	if time.Now().After(challenge.ExpiresAt) {
		delete(m.challenges, challengeID)
		return "", errors.New("attestation challenge has expired")
	}

	if !strings.EqualFold(challenge.LicenseKey, licenseKey) || !strings.EqualFold(challenge.HWID, hwid) {
		return "", errors.New("challenge binding does not match provided license_key and hwid")
	}

	challenge.Consumed = true
	return challenge.Nonce, nil
}

// VerifyTPMQuote processes and validates a TPM 2.0 quote against an issued challenge.
func (m *Manager) VerifyTPMQuote(licenseKey, hwid, challengeID string, quote *PCRQuote) (*AttestationRecord, error) {
	nonce, err := m.consumeChallenge(challengeID, licenseKey, hwid)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	expectedPCRs := make(map[int]string, len(m.goldenPCRs))
	for k, v := range m.goldenPCRs {
		expectedPCRs[k] = v
	}
	m.mu.RUnlock()

	valid, compositeHex, err := VerifyPCRQuote(quote, nonce, expectedPCRs)
	if err != nil {
		return nil, fmt.Errorf("quote verification failed: %w", err)
	}
	if !valid {
		return nil, errors.New("invalid TPM 2.0 quote")
	}

	akHash := ""
	if quote.AKPublicKeyPEM != "" {
		h := sha256.Sum256([]byte(quote.AKPublicKeyPEM))
		akHash = hex.EncodeToString(h[:16])
	}

	rec := &AttestationRecord{
		LicenseKey:      strings.ToUpper(licenseKey),
		HWID:            strings.ToUpper(hwid),
		AttestationType: TypeTPM2,
		TrustLevel:      TrustAttestedHardware,
		PCRDigest:       compositeHex,
		AKPublicHash:    akHash,
		LastNonce:       nonce,
		VerifiedAt:      time.Now(),
		TamperScore:     0,
		Details:         fmt.Sprintf("TPM 2.0 PCRs verified against nonce (selected PCRs: %v)", quote.PCRSelection),
	}

	m.mu.Lock()
	m.records[recordKey(licenseKey, hwid)] = rec
	m.mu.Unlock()

	return rec, nil
}

// VerifyEnclave processes and validates an Apple Secure Enclave or Windows Hello assertion.
func (m *Manager) VerifyEnclave(licenseKey, hwid, challengeID string, enclave *EnclaveAttestation) (*AttestationRecord, error) {
	nonce, err := m.consumeChallenge(challengeID, licenseKey, hwid)
	if err != nil {
		return nil, err
	}

	valid, pubFingerprint, err := VerifyEnclaveStatement(enclave, nonce)
	if err != nil {
		return nil, fmt.Errorf("enclave verification failed: %w", err)
	}
	if !valid {
		return nil, errors.New("invalid enclave statement")
	}

	attType := enclave.EnclaveType
	if attType == "" {
		attType = TypeSecureEnclave
	}

	rec := &AttestationRecord{
		LicenseKey:      strings.ToUpper(licenseKey),
		HWID:            strings.ToUpper(hwid),
		AttestationType: attType,
		TrustLevel:      TrustAttestedEnclave,
		AKPublicHash:    pubFingerprint,
		LastNonce:       nonce,
		VerifiedAt:      time.Now(),
		TamperScore:     0,
		Details:         fmt.Sprintf("Hardware enclave key attested (counter: %d)", enclave.Counter),
	}

	m.mu.Lock()
	m.records[recordKey(licenseKey, hwid)] = rec
	m.mu.Unlock()

	return rec, nil
}

// EvaluateTelemetry assesses client integrity signals, calculates a tamper score, and updates trust.
func (m *Manager) EvaluateTelemetry(licenseKey, hwid string, report *TelemetryReport) (int, bool, *AttestationRecord, error) {
	if report == nil {
		return 0, false, nil, errors.New("nil telemetry report")
	}

	score := 0
	details := make([]string, 0)

	if report.DebuggerPresent {
		score += 45
		details = append(details, "Active debugger attached to client process")
	}
	if !report.MemoryIntegrity {
		score += 50
		details = append(details, "Executable memory section checksum violated / patched")
	}
	if report.HooksDetected {
		score += 35
		details = append(details, "Syscall detours or inline hooks detected")
	}
	if report.SandboxDetected {
		score += 15
		details = append(details, "Automated analysis sandbox artifacts detected")
	}

	if score > 100 {
		score = 100
	}

	isTampered := score >= TamperScoreThreshold

	m.mu.Lock()
	defer m.mu.Unlock()

	k := recordKey(licenseKey, hwid)
	rec, exists := m.records[k]
	if !exists {
		rec = &AttestationRecord{
			LicenseKey:      strings.ToUpper(licenseKey),
			HWID:            strings.ToUpper(hwid),
			AttestationType: TypeSoftwareEmulate,
			TrustLevel:      TrustUnverified,
			VerifiedAt:      time.Now(),
		}
		m.records[k] = rec
	}

	rec.TamperScore = score
	if isTampered {
		rec.TrustLevel = TrustTampered
		rec.Details = "SECURITY ALERT: " + strings.Join(details, "; ")
	} else if rec.TrustLevel == TrustUnverified {
		rec.TrustLevel = TrustSoftwareGrace
		rec.Details = "Software integrity verified without hardware enclave"
	}
	rec.VerifiedAt = time.Now()

	return score, isTampered, rec, nil
}

// GetRecord returns the verified attestation record for a license and device.
func (m *Manager) GetRecord(licenseKey, hwid string) (*AttestationRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, exists := m.records[recordKey(licenseKey, hwid)]
	if !exists {
		return nil, false
	}
	copyRec := *rec
	return &copyRec, true
}

// ListRecords returns all tracked attestation records.
func (m *Manager) ListRecords() []*AttestationRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*AttestationRecord, 0, len(m.records))
	for _, r := range m.records {
		c := *r
		list = append(list, &c)
	}
	return list
}
