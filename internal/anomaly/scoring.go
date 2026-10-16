package anomaly

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// AdaptiveRiskScorer manages real-time entity risk scores, decay, and automated challenge escalation.
type AdaptiveRiskScorer struct {
	mu             sync.RWMutex
	scores         map[string]*RiskScore
	challengeStore map[string]string // token -> entityID
	tokenExpiry    map[string]time.Time
	decayStep      int
	challengeTTL   time.Duration
}

// NewAdaptiveRiskScorer initializes an adaptive risk scoring engine.
func NewAdaptiveRiskScorer(decayStep int, challengeTTL time.Duration) *AdaptiveRiskScorer {
	if decayStep <= 0 {
		decayStep = 3
	}
	if challengeTTL <= 0 {
		challengeTTL = 5 * time.Minute
	}
	return &AdaptiveRiskScorer{
		scores:         make(map[string]*RiskScore),
		challengeStore: make(map[string]string),
		tokenExpiry:    make(map[string]time.Time),
		decayStep:      decayStep,
		challengeTTL:   challengeTTL,
	}
}

// GetScore returns the current risk score for an entity.
func (ars *AdaptiveRiskScorer) GetScore(entityID string) *RiskScore {
	ars.mu.Lock()
	defer ars.mu.Unlock()

	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return &RiskScore{
			Level:       RiskLevelLow,
			EvaluatedAt: time.Now(),
		}
	}

	score, exists := ars.scores[entityID]
	if !exists {
		return &RiskScore{
			EntityID:    entityID,
			Score:       0,
			Level:       RiskLevelLow,
			Factors:     []RiskFactor{},
			EvaluatedAt: time.Now(),
		}
	}

	// Purge expired challenge token if past TTL
	if score.ChallengeEscalation && time.Now().After(score.ChallengeExpiresAt) {
		delete(ars.challengeStore, score.ChallengeToken)
		delete(ars.tokenExpiry, score.ChallengeToken)
		score.ChallengeEscalation = false
		score.ChallengeToken = ""
		score.ChallengeType = ChallengeNone
	}

	return cloneRiskScore(score)
}

// AddFactor registers an anomalous observation factor and updates the risk level.
func (ars *AdaptiveRiskScorer) AddFactor(entityID string, factor RiskFactor) *RiskScore {
	ars.mu.Lock()
	defer ars.mu.Unlock()

	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return nil
	}

	score, exists := ars.scores[entityID]
	if !exists {
		score = &RiskScore{
			EntityID: entityID,
			Score:    0,
			Level:    RiskLevelLow,
			Factors:  make([]RiskFactor, 0, 8),
		}
		ars.scores[entityID] = score
	}

	// Update score
	score.Score += factor.Severity
	if score.Score > 100 {
		score.Score = 100
	}
	score.Factors = append(score.Factors, factor)
	if len(score.Factors) > 10 {
		score.Factors = score.Factors[1:]
	}
	score.EvaluatedAt = time.Now()

	ars.reevaluateState(score)
	return cloneRiskScore(score)
}

// RecordNominalActivity applies progressive decay to an entity's risk score on healthy activity.
func (ars *AdaptiveRiskScorer) RecordNominalActivity(entityID string) *RiskScore {
	ars.mu.Lock()
	defer ars.mu.Unlock()

	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return nil
	}

	score, exists := ars.scores[entityID]
	if !exists {
		score = &RiskScore{
			EntityID:    entityID,
			Score:       0,
			Level:       RiskLevelLow,
			Factors:     []RiskFactor{},
			EvaluatedAt: time.Now(),
		}
		ars.scores[entityID] = score
		return cloneRiskScore(score)
	}

	if score.Score > 0 {
		score.Score -= ars.decayStep
		if score.Score < 0 {
			score.Score = 0
		}
	}
	score.EvaluatedAt = time.Now()

	ars.reevaluateState(score)
	return cloneRiskScore(score)
}

// IssueChallenge manually triggers a re-attestation challenge for an entity.
func (ars *AdaptiveRiskScorer) IssueChallenge(entityID string, challengeType ChallengeType) (*RiskScore, string) {
	ars.mu.Lock()
	defer ars.mu.Unlock()

	entityID = strings.TrimSpace(entityID)
	score, exists := ars.scores[entityID]
	if !exists {
		score = &RiskScore{
			EntityID: entityID,
			Score:    30,
			Level:    RiskLevelMedium,
			Factors:  []RiskFactor{},
		}
		ars.scores[entityID] = score
	}

	token := generateSecureToken()
	expiry := time.Now().Add(ars.challengeTTL)

	score.ChallengeEscalation = true
	score.ChallengeType = challengeType
	score.ChallengeToken = token
	score.ChallengeExpiresAt = expiry
	score.EvaluatedAt = time.Now()

	ars.challengeStore[token] = entityID
	ars.tokenExpiry[token] = expiry

	return cloneRiskScore(score), token
}

// VerifyChallengeResponse checks and clears an active challenge token, reducing risk.
func (ars *AdaptiveRiskScorer) VerifyChallengeResponse(token string) (string, bool) {
	ars.mu.Lock()
	defer ars.mu.Unlock()

	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}

	entityID, exists := ars.challengeStore[token]
	if !exists {
		return "", false
	}

	expiry := ars.tokenExpiry[token]
	delete(ars.challengeStore, token)
	delete(ars.tokenExpiry, token)

	if time.Now().After(expiry) {
		return entityID, false
	}

	// Successful challenge verification reduces risk significantly
	if score, ok := ars.scores[entityID]; ok {
		score.ChallengeEscalation = false
		score.ChallengeToken = ""
		score.ChallengeType = ChallengeNone
		score.Score -= 45
		if score.Score < 0 {
			score.Score = 0
		}
		score.QuarantineTriggered = false
		ars.reevaluateState(score)
	}

	return entityID, true
}

// reevaluateState updates risk level, challenge escalation, and quarantine flags based on current score.
func (ars *AdaptiveRiskScorer) reevaluateState(score *RiskScore) {
	switch {
	case score.Score >= 85:
		score.Level = RiskLevelCritical
		score.QuarantineTriggered = true
		if !score.ChallengeEscalation {
			token := generateSecureToken()
			expiry := time.Now().Add(ars.challengeTTL)
			score.ChallengeEscalation = true
			score.ChallengeType = ChallengeReAttestation
			score.ChallengeToken = token
			score.ChallengeExpiresAt = expiry
			ars.challengeStore[token] = score.EntityID
			ars.tokenExpiry[token] = expiry
		}
	case score.Score >= 50:
		score.Level = RiskLevelHigh
		score.QuarantineTriggered = false
		if !score.ChallengeEscalation {
			token := generateSecureToken()
			expiry := time.Now().Add(ars.challengeTTL)
			score.ChallengeEscalation = true
			score.ChallengeType = ChallengeReAttestation
			score.ChallengeToken = token
			score.ChallengeExpiresAt = expiry
			ars.challengeStore[token] = score.EntityID
			ars.tokenExpiry[token] = expiry
		}
	case score.Score >= 30:
		score.Level = RiskLevelMedium
		score.QuarantineTriggered = false
	default:
		score.Level = RiskLevelLow
		score.QuarantineTriggered = false
	}
}

// cloneRiskScore creates a detached copy of a RiskScore struct.
func cloneRiskScore(in *RiskScore) *RiskScore {
	out := *in
	out.Factors = make([]RiskFactor, len(in.Factors))
	copy(out.Factors, in.Factors)
	return &out
}

// generateSecureToken creates a cryptographically random hex challenge string.
func generateSecureToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
