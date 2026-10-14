package ratelimit

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ViolationType identifies the class of security infraction.
type ViolationType string

const (
	ViolationRateLimitExceeded   ViolationType = "rate_limit_exceeded"
	ViolationFailedValidation    ViolationType = "failed_validation"
	ViolationAuthFailure         ViolationType = "auth_failure"
	ViolationReplayAttack        ViolationType = "replay_attack"
	ViolationSignatureMismatch   ViolationType = "signature_mismatch"
	ViolationTamperDetected      ViolationType = "tamper_detected"
	ViolationSuspiciousUserAgent ViolationType = "suspicious_user_agent"
)

// ViolationWeights defines point penalties per infraction type.
var DefaultViolationWeights = map[ViolationType]int{
	ViolationRateLimitExceeded:   5,
	ViolationFailedValidation:    10,
	ViolationAuthFailure:         15,
	ViolationReplayAttack:        25,
	ViolationSignatureMismatch:   25,
	ViolationTamperDetected:      50,
	ViolationSuspiciousUserAgent: 10,
}

// ViolationEvent represents a single recorded infraction.
type ViolationEvent struct {
	Type      ViolationType `json:"type"`
	Points    int           `json:"points"`
	Details   string        `json:"details,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// TemporaryBan represents an active temporary restriction against an IP or HWID.
type TemporaryBan struct {
	Key       string    `json:"key"`
	Reason    string    `json:"reason"`
	Score     int       `json:"score"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ReputationConfig configures sliding window and thresholds for reputation management.
type ReputationConfig struct {
	WindowDuration time.Duration
	BanThreshold   int
	BanDuration    time.Duration
	Weights        map[ViolationType]int
}

// DefaultReputationConfig provides standard production defaults.
func DefaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		WindowDuration: 15 * time.Minute,
		BanThreshold:   50,
		BanDuration:    15 * time.Minute,
		Weights:        DefaultViolationWeights,
	}
}

type clientReputation struct {
	events   []ViolationEvent
	lastSeen time.Time
}

// ReputationTracker tracks IP/HWID infractions in a sliding window and triggers automatic bans.
type ReputationTracker struct {
	mu          sync.RWMutex
	cfg         ReputationConfig
	reputations map[string]*clientReputation
	bans        map[string]*TemporaryBan
}

// NewReputationTracker constructs a thread-safe reputation tracker.
func NewReputationTracker(cfg ReputationConfig) *ReputationTracker {
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 15 * time.Minute
	}
	if cfg.BanThreshold <= 0 {
		cfg.BanThreshold = 50
	}
	if cfg.BanDuration <= 0 {
		cfg.BanDuration = 15 * time.Minute
	}
	if cfg.Weights == nil {
		cfg.Weights = DefaultViolationWeights
	}
	return &ReputationTracker{
		cfg:         cfg,
		reputations: make(map[string]*clientReputation),
		bans:        make(map[string]*TemporaryBan),
	}
}

// RecordViolation registers an infraction, computes updated score, and triggers auto-ban if threshold met.
func (rt *ReputationTracker) RecordViolation(key string, vType ViolationType, details string) (int, bool, *TemporaryBan) {
	normKey := strings.ToLower(strings.TrimSpace(key))
	if normKey == "" {
		return 0, false, nil
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	points, ok := rt.cfg.Weights[vType]
	if !ok {
		points = 10
	}

	rep, exists := rt.reputations[normKey]
	if !exists {
		rep = &clientReputation{
			events:   make([]ViolationEvent, 0, 8),
			lastSeen: now,
		}
		rt.reputations[normKey] = rep
	}
	rep.lastSeen = now

	// 1. Add event
	rep.events = append(rep.events, ViolationEvent{
		Type:      vType,
		Points:    points,
		Details:   details,
		Timestamp: now,
	})

	// 2. Prune events outside sliding window
	cutoff := now.Add(-rt.cfg.WindowDuration)
	valid := rep.events[:0]
	score := 0
	for _, ev := range rep.events {
		if ev.Timestamp.After(cutoff) {
			valid = append(valid, ev)
			score += ev.Points
		}
	}
	rep.events = valid

	// 3. Check if existing ban is active
	if existing, hasBan := rt.bans[normKey]; hasBan && now.Before(existing.ExpiresAt) {
		existing.Score = score
		return score, false, existing
	}

	// 4. Trigger auto-ban if score exceeds threshold
	if score >= rt.cfg.BanThreshold {
		ban := &TemporaryBan{
			Key:       normKey,
			Reason:    fmt.Sprintf("Reputation score %d exceeded threshold %d via %s", score, rt.cfg.BanThreshold, vType),
			Score:     score,
			BannedAt:  now,
			ExpiresAt: now.Add(rt.cfg.BanDuration),
		}
		rt.bans[normKey] = ban
		return score, true, ban
	}

	return score, false, nil
}

// IsBanned checks whether the key is under active temporary restriction.
func (rt *ReputationTracker) IsBanned(key string) (bool, *TemporaryBan) {
	normKey := strings.ToLower(strings.TrimSpace(key))
	if normKey == "" {
		return false, nil
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	ban, exists := rt.bans[normKey]
	if !exists {
		return false, nil
	}

	now := time.Now()
	if now.After(ban.ExpiresAt) {
		delete(rt.bans, normKey)
		return false, nil
	}

	return true, ban
}

// Ban manually imposes a temporary restriction.
func (rt *ReputationTracker) Ban(key, reason string, duration time.Duration) *TemporaryBan {
	normKey := strings.ToLower(strings.TrimSpace(key))
	if normKey == "" {
		return nil
	}
	if duration <= 0 {
		duration = rt.cfg.BanDuration
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	ban := &TemporaryBan{
		Key:       normKey,
		Reason:    reason,
		Score:     rt.cfg.BanThreshold,
		BannedAt:  now,
		ExpiresAt: now.Add(duration),
	}
	rt.bans[normKey] = ban
	return ban
}

// Unban manually lifts a restriction and clears recorded violations.
func (rt *ReputationTracker) Unban(key string) bool {
	normKey := strings.ToLower(strings.TrimSpace(key))
	if normKey == "" {
		return false
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	_, existed := rt.bans[normKey]
	delete(rt.bans, normKey)
	delete(rt.reputations, normKey)
	return existed
}

// GetScore returns the current sliding-window violation score for a key.
func (rt *ReputationTracker) GetScore(key string) int {
	normKey := strings.ToLower(strings.TrimSpace(key))
	if normKey == "" {
		return 0
	}

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	rep, exists := rt.reputations[normKey]
	if !exists {
		return 0
	}

	cutoff := time.Now().Add(-rt.cfg.WindowDuration)
	score := 0
	for _, ev := range rep.events {
		if ev.Timestamp.After(cutoff) {
			score += ev.Points
		}
	}
	return score
}

// ListBanned returns all currently active temporary restrictions.
func (rt *ReputationTracker) ListBanned() []*TemporaryBan {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	res := make([]*TemporaryBan, 0, len(rt.bans))
	for k, ban := range rt.bans {
		if now.Before(ban.ExpiresAt) {
			res = append(res, ban)
		} else {
			delete(rt.bans, k)
		}
	}
	return res
}

// Summary captures aggregated reputation telemetry.
type Summary struct {
	TotalTrackedKeys int             `json:"total_tracked_keys"`
	ActiveBansCount  int             `json:"active_bans_count"`
	BanThreshold     int             `json:"ban_threshold"`
	WindowMinutes    int             `json:"window_minutes"`
	ActiveBans       []*TemporaryBan `json:"active_bans"`
}

// GetSummary returns an overview for telemetry endpoints and dashboards.
func (rt *ReputationTracker) GetSummary() Summary {
	banned := rt.ListBanned()
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	return Summary{
		TotalTrackedKeys: len(rt.reputations),
		ActiveBansCount:  len(banned),
		BanThreshold:     rt.cfg.BanThreshold,
		WindowMinutes:    int(rt.cfg.WindowDuration.Minutes()),
		ActiveBans:       banned,
	}
}
