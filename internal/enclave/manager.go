package enclave

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidNonce      = errors.New("challenge nonce is invalid, expired, or already consumed")
	ErrPolicyNotFound    = errors.New("specified enclave policy not found")
	ErrUnsupportedPlatform = errors.New("unsupported confidential computing enclave platform")
)

// Manager coordinates confidential computing attestation quotes, policies, and zero-plaintext tunnels.
type Manager struct {
	mu           sync.RWMutex
	policies     map[string]*EnclavePolicy
	nonces       map[string]time.Time
	tunnelMgr    *TunnelManager
	telemetry    EnclaveTelemetry
	vcekKey      interface{} // Optional custom VCEK key for SEV-SNP
}

// NewManager creates and initializes the confidential computing enclave coordinator.
func NewManager() *Manager {
	m := &Manager{
		policies:  make(map[string]*EnclavePolicy),
		nonces:    make(map[string]time.Time),
		tunnelMgr: NewTunnelManager(),
		telemetry: EnclaveTelemetry{
			QuotesByPlatform: make(map[string]int64),
		},
	}

	// Register default baseline policies for SGX and SEV-SNP
	m.RegisterPolicy(&EnclavePolicy{
		ID:          "default-sgx",
		Name:        "Production Intel SGX Strict Policy",
		Platform:    PlatformSGX,
		MinISVSVN:   1,
		AllowDebug:  false,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	})

	m.RegisterPolicy(&EnclavePolicy{
		ID:          "default-sev",
		Name:        "Production AMD SEV-SNP Strict Policy",
		Platform:    PlatformSEVSNP,
		MinGuestSVN: 1,
		AllowDebug:  false,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	})

	go m.nonceCleanupLoop()
	return m
}

// GenerateChallenge produces a fresh, single-use 32-byte cryptographic nonce for attestation binding.
func (m *Manager) GenerateChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)

	m.mu.Lock()
	m.nonces[nonce] = time.Now().Add(5 * time.Minute)
	m.mu.Unlock()

	return nonce, nil
}

// ConsumeNonce checks validity of a nonce and consumes it in a single atomic operation.
func (m *Manager) ConsumeNonce(nonce string) bool {
	clean := strings.TrimSpace(nonce)
	if clean == "" {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	expiry, exists := m.nonces[clean]
	if !exists {
		return false
	}
	delete(m.nonces, clean)

	return time.Now().Before(expiry)
}

// RegisterPolicy adds or updates an authorized enclave policy.
func (m *Manager) RegisterPolicy(policy *EnclavePolicy) error {
	if policy == nil || strings.TrimSpace(policy.ID) == "" {
		return errors.New("policy ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	policy.UpdatedAt = time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = policy.UpdatedAt
	}
	m.policies[policy.ID] = policy
	m.telemetry.ActivePoliciesCount = len(m.policies)
	return nil
}

// GetPolicy retrieves a registered policy by ID.
func (m *Manager) GetPolicy(id string) (*EnclavePolicy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, exists := m.policies[id]
	return p, exists
}

// ListPolicies returns all active enclave policies.
func (m *Manager) ListPolicies() []*EnclavePolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*EnclavePolicy, 0, len(m.policies))
	for _, p := range m.policies {
		res = append(res, p)
	}
	return res
}

// AttestQuote validates an Intel SGX or AMD SEV-SNP quote against active security policies.
func (m *Manager) AttestQuote(platform PlatformType, rawQuote []byte, nonce string, policyID string) (*AttestationResult, error) {
	if !m.ConsumeNonce(nonce) {
		m.recordFailure()
		return nil, ErrInvalidNonce
	}

	var policy *EnclavePolicy
	if policyID != "" {
		var exists bool
		policy, exists = m.GetPolicy(policyID)
		if !exists {
			m.recordFailure()
			return nil, ErrPolicyNotFound
		}
	}

	expectedDigest := sha256.Sum256([]byte(nonce))

	var result *AttestationResult
	var err error

	switch platform {
	case PlatformSGX:
		var quote *SGXQuoteV3
		quote, err = ParseSGXQuote(rawQuote)
		if err != nil {
			m.recordFailure()
			return nil, err
		}
		result, err = VerifySGXQuote(quote, rawQuote, expectedDigest[:], policy)

	case PlatformSEVSNP:
		var report *SEVSNPReport
		report, err = ParseSEVSNPReport(rawQuote)
		if err != nil {
			m.recordFailure()
			return nil, err
		}
		result, err = VerifySEVSNPReport(report, rawQuote, expectedDigest[:], nil, policy)

	default:
		m.recordFailure()
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, platform)
	}

	if err != nil {
		m.recordFailure()
		return nil, err
	}

	m.mu.Lock()
	m.telemetry.VerifiedQuotes++
	m.telemetry.QuotesByPlatform[string(platform)]++
	m.mu.Unlock()

	return result, nil
}

// EstablishTunnel attests the client enclave and constructs a bidirectional AES-256-GCM encrypted tunnel.
func (m *Manager) EstablishTunnel(platform PlatformType, rawQuote []byte, nonce string, policyID string, clientPubHex string) (*EnclaveTunnelSession, string, error) {
	if !m.ConsumeNonce(nonce) {
		m.recordFailure()
		return nil, "", ErrInvalidNonce
	}

	clientPubBytes, err := hex.DecodeString(strings.TrimSpace(clientPubHex))
	if err != nil || (len(clientPubBytes) != 64 && len(clientPubBytes) != 65) {
		m.recordFailure()
		return nil, "", ErrTunnelInvalidKey
	}

	var policy *EnclavePolicy
	if policyID != "" {
		var exists bool
		policy, exists = m.GetPolicy(policyID)
		if !exists {
			m.recordFailure()
			return nil, "", ErrPolicyNotFound
		}
	}

	// Cryptographic binding: ReportData must contain SHA-256(nonce || clientPub)
	h := sha256.New()
	h.Write([]byte(nonce))
	h.Write(clientPubBytes)
	boundDigest := h.Sum(nil)

	switch platform {
	case PlatformSGX:
		quote, err := ParseSGXQuote(rawQuote)
		if err != nil {
			m.recordFailure()
			return nil, "", err
		}
		if _, err := VerifySGXQuote(quote, rawQuote, boundDigest, policy); err != nil {
			m.recordFailure()
			return nil, "", err
		}
	case PlatformSEVSNP:
		report, err := ParseSEVSNPReport(rawQuote)
		if err != nil {
			m.recordFailure()
			return nil, "", err
		}
		if _, err := VerifySEVSNPReport(report, rawQuote, boundDigest, nil, policy); err != nil {
			m.recordFailure()
			return nil, "", err
		}
	default:
		m.recordFailure()
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupportedPlatform, platform)
	}

	session, brokerPubBytes, err := m.tunnelMgr.EstablishHandshake(platform, clientPubBytes, TunnelDefaultTTL)
	if err != nil {
		m.recordFailure()
		return nil, "", err
	}

	m.mu.Lock()
	m.telemetry.VerifiedQuotes++
	m.telemetry.QuotesByPlatform[string(platform)]++
	m.mu.Unlock()

	return session, hex.EncodeToString(brokerPubBytes), nil
}

// EvaluateZeroPlaintext executes a license check inside an encrypted tunnel with zero-plaintext memory wiping.
func (m *Manager) EvaluateZeroPlaintext(sessionID string, encryptedMsg *EncryptedTunnelMessage, evalFn func(*EnclaveEvalPayload) (*EnclaveEvalResponse, error)) (*EncryptedTunnelMessage, error) {
	session, err := m.tunnelMgr.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	decryptedBytes, err := session.DecryptClientMessage(encryptedMsg)
	if err != nil {
		return nil, err
	}

	// Encapsulate plaintext in zero-wipe memory buffer
	secBuf := NewSecureBuffer(decryptedBytes, true)
	defer secBuf.Destroy()

	rawBytes, err := secBuf.Bytes()
	if err != nil {
		return nil, err
	}

	var payload EnclaveEvalPayload
	if err := json.Unmarshal(rawBytes, &payload); err != nil {
		return nil, fmt.Errorf("malformed enclave evaluation payload: %w", err)
	}

	// Immediately wipe plaintext json bytes before executing business evaluation
	secBuf.Destroy()

	resp, err := evalFn(&payload)
	if err != nil {
		return nil, err
	}
	resp.EnclavePlatform = string(session.Platform)
	resp.ZeroPlaintextGuarantee = true
	resp.EvaluatedAt = time.Now().UTC().Format(time.RFC3339)

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	respBuf := NewSecureBuffer(respBytes, true)
	defer respBuf.Destroy()

	finalPlaintext, err := respBuf.Bytes()
	if err != nil {
		return nil, err
	}

	encryptedResp, err := session.EncryptBrokerMessage(finalPlaintext)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.telemetry.TotalEvaluations++
	m.mu.Unlock()

	return encryptedResp, nil
}

// GetTelemetry retrieves current snapshot of enclave metrics.
func (m *Manager) GetTelemetry() EnclaveTelemetry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := m.telemetry
	res.ActiveTunnels = m.tunnelMgr.ActiveCount()
	res.ActivePoliciesCount = len(m.policies)

	// Deep copy platform map
	res.QuotesByPlatform = make(map[string]int64)
	for k, v := range m.telemetry.QuotesByPlatform {
		res.QuotesByPlatform[k] = v
	}
	return res
}

func (m *Manager) recordFailure() {
	m.mu.Lock()
	m.telemetry.FailedAttestations++
	m.mu.Unlock()
}

func (m *Manager) nonceCleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for nonce, exp := range m.nonces {
			if now.After(exp) {
				delete(m.nonces, nonce)
			}
		}
		m.mu.Unlock()
	}
}
