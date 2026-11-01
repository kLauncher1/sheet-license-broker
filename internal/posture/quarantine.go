package posture

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// QuarantineRegistry manages quarantined endpoints and step-up authentication challenges.
type QuarantineRegistry struct {
	mu          sync.RWMutex
	quarantined map[string]*QuarantinedDevice
	challenges  map[string]*StepUpChallenge
}

// NewQuarantineRegistry constructs an initialized in-memory quarantine registry.
func NewQuarantineRegistry() *QuarantineRegistry {
	return &QuarantineRegistry{
		quarantined: make(map[string]*QuarantinedDevice),
		challenges:  make(map[string]*StepUpChallenge),
	}
}

func deviceKey(tenantID, deviceID string) string {
	return fmt.Sprintf("%s:%s", tenantID, deviceID)
}

// QuarantineDevice adds or updates a quarantined endpoint record.
func (r *QuarantineRegistry) QuarantineDevice(dev QuarantinedDevice) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := deviceKey(dev.TenantID, dev.DeviceID)
	r.quarantined[key] = &dev
}

// IsQuarantined checks if a specific device is currently quarantined.
func (r *QuarantineRegistry) IsQuarantined(tenantID, deviceID string) (bool, *QuarantinedDevice) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := deviceKey(tenantID, deviceID)
	dev, ok := r.quarantined[key]
	if !ok {
		return false, nil
	}
	cp := *dev
	return true, &cp
}

// IsDegradedAllowed returns true if the device is eligible for graceful degradation mode.
func (r *QuarantineRegistry) IsDegradedAllowed(tenantID, deviceID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := deviceKey(tenantID, deviceID)
	dev, ok := r.quarantined[key]
	if !ok {
		return false
	}
	return dev.DegradedModeAllowed
}

// ReleaseQuarantine removes a device from quarantine with reason tracking.
func (r *QuarantineRegistry) ReleaseQuarantine(tenantID, deviceID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := deviceKey(tenantID, deviceID)
	if _, ok := r.quarantined[key]; !ok {
		return false
	}
	delete(r.quarantined, key)
	return true
}

// ListQuarantined returns all quarantined endpoints, optionally filtered by tenant.
func (r *QuarantineRegistry) ListQuarantined(tenantID string) []QuarantinedDevice {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []QuarantinedDevice
	for _, dev := range r.quarantined {
		if tenantID == "" || dev.TenantID == tenantID {
			result = append(result, *dev)
		}
	}
	return result
}

// IssueStepUpChallenge generates a time-bound challenge for step-up verification.
func (r *QuarantineRegistry) IssueStepUpChallenge(tenantID, deviceID string, actions []string, ttl time.Duration) *StepUpChallenge {
	r.mu.Lock()
	defer r.mu.Unlock()

	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	challengeID := "chall-" + hex.EncodeToString(idBytes)

	nonceBytes := make([]byte, 24)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	now := time.Now().UTC()
	challenge := &StepUpChallenge{
		ChallengeID:     challengeID,
		DeviceID:        deviceID,
		TenantID:        tenantID,
		Nonce:           nonce,
		RequiredActions: actions,
		IssuedAt:        now,
		ExpiresAt:       now.Add(ttl),
		Completed:       false,
	}

	r.challenges[challengeID] = challenge
	return challenge
}

// VerifyStepUpChallenge validates a step-up challenge proof in constant time.
func (r *QuarantineRegistry) VerifyStepUpChallenge(challengeID, expectedNonce, submittedNonce string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ch, exists := r.challenges[challengeID]
	if !exists {
		return false, fmt.Errorf("challenge not found or already redeemed")
	}

	if time.Now().UTC().After(ch.ExpiresAt) {
		delete(r.challenges, challengeID)
		return false, fmt.Errorf("challenge has expired")
	}

	if ch.Completed {
		return false, fmt.Errorf("challenge has already been fulfilled")
	}

	// Constant-time nonce comparison
	if subtle.ConstantTimeCompare([]byte(ch.Nonce), []byte(submittedNonce)) != 1 {
		return false, fmt.Errorf("invalid step-up proof nonce")
	}

	ch.Completed = true
	return true, nil
}

// CleanupExpired purges stale challenges from memory.
func (r *QuarantineRegistry) CleanupExpired(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	purged := 0
	for id, ch := range r.challenges {
		if now.After(ch.ExpiresAt) || ch.Completed {
			delete(r.challenges, id)
			purged++
		}
	}
	return purged
}
