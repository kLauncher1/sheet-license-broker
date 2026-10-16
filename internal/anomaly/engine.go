package anomaly

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Engine is the central coordinator for behavioral anomaly detection and adaptive risk scoring.
type Engine struct {
	mu                  sync.RWMutex
	driftAnalyzer       *HeartbeatDriftAnalyzer
	geoDetector         *GeoVelocityDetector
	riskScorer          *AdaptiveRiskScorer
	graphExporter       *IncidentGraphExporter
	totalObservations   atomic.Int64
	anomaliesDetected   atomic.Int64
	challengesIssued    atomic.Int64
	challengesCleared   atomic.Int64
	lastAnomalyTime     time.Time
}

// Config provides initialization parameters for the Engine.
type Config struct {
	MaxWindowSize int
	MaxSpeedKmH   float64
	DecayStep     int
	ChallengeTTL  time.Duration
	MaxIncidents  int
}

// DefaultConfig returns recommended production defaults.
func DefaultConfig() Config {
	return Config{
		MaxWindowSize: 32,
		MaxSpeedKmH:   950.0,
		DecayStep:     3,
		ChallengeTTL:  5 * time.Minute,
		MaxIncidents:  500,
	}
}

// NewEngine initializes a behavioral anomaly detection and risk scoring engine.
func NewEngine(cfg Config) *Engine {
	if cfg.MaxWindowSize <= 0 {
		cfg.MaxWindowSize = 32
	}
	if cfg.MaxSpeedKmH <= 0 {
		cfg.MaxSpeedKmH = 950.0
	}
	if cfg.DecayStep <= 0 {
		cfg.DecayStep = 3
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 5 * time.Minute
	}
	if cfg.MaxIncidents <= 0 {
		cfg.MaxIncidents = 500
	}

	return &Engine{
		driftAnalyzer: NewHeartbeatDriftAnalyzer(cfg.MaxWindowSize),
		geoDetector:   NewGeoVelocityDetector(cfg.MaxSpeedKmH),
		riskScorer:    NewAdaptiveRiskScorer(cfg.DecayStep, cfg.ChallengeTTL),
		graphExporter: NewIncidentGraphExporter(cfg.MaxIncidents),
	}
}

// RecordObservation analyzes incoming client telemetry, calculates risk factors, and updates the score.
func (e *Engine) RecordObservation(obs ClientObservation) (*RiskScore, bool) {
	e.totalObservations.Add(1)

	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}

	entityID := strings.TrimSpace(obs.LicenseKey)
	if entityID == "" {
		entityID = strings.TrimSpace(obs.HWID)
	}
	if entityID == "" {
		entityID = strings.TrimSpace(obs.IP)
	}
	if entityID == "" {
		return &RiskScore{Level: RiskLevelLow, EvaluatedAt: obs.Timestamp}, false
	}

	hasAnomaly := false

	// 1. Evaluate Heartbeat Timing Drift
	if obs.Action == "heartbeat" || obs.Action == "verify" || obs.Action == "" {
		drift := e.driftAnalyzer.RecordHeartbeat(entityID, obs.Timestamp)
		if drift != nil && (drift.DriftState == "accelerated" || drift.DriftState == "erratic") {
			hasAnomaly = true
			severity := 25
			if drift.DriftState == "accelerated" {
				severity = 35
			}
			factor := RiskFactor{
				Code:        "HEARTBEAT_DRIFT",
				Description: fmt.Sprintf("Abnormal heartbeat interval %dms (mean: %.1fms, z: %.2f, state: %s)", drift.LastIntervalMs, drift.MeanIntervalMs, drift.ZScore, drift.DriftState),
				Severity:    severity,
				DetectedAt:  obs.Timestamp,
			}
			e.riskScorer.AddFactor(entityID, factor)
			e.recordIncident(obs, "HEARTBEAT_DRIFT", severity, factor.Description)
		}
	}

	// 2. Evaluate Geographic Origin & Impossible Travel
	if obs.Country != "" && obs.IP != "" {
		geoAnomaly, isImpossible := e.geoDetector.RecordLocation(entityID, obs.IP, obs.Country, obs.Timestamp)
		if isImpossible && geoAnomaly != nil {
			hasAnomaly = true
			severity := 50
			desc := fmt.Sprintf("Impossible travel detected: %s -> %s (%.0f km in %.1fs, velocity %.0f km/h)",
				geoAnomaly.PreviousCountry, geoAnomaly.CurrentCountry, geoAnomaly.EstimatedDistanceKm, geoAnomaly.TimeDeltaSec, geoAnomaly.CalculatedSpeedKmH)
			factor := RiskFactor{
				Code:        "IMPOSSIBLE_TRAVEL",
				Description: desc,
				Severity:    severity,
				DetectedAt:  obs.Timestamp,
			}
			e.riskScorer.AddFactor(entityID, factor)
			e.recordIncident(obs, "IMPOSSIBLE_TRAVEL", severity, desc)
		}

		// 3. Evaluate Concurrent Subnet Access
		if subnets, isMultiSubnet := e.geoDetector.DetectConcurrentSubnets(entityID); isMultiSubnet {
			hasAnomaly = true
			severity := 25
			desc := fmt.Sprintf("Concurrent active subnets (%d) detected for single entity", subnets)
			factor := RiskFactor{
				Code:        "CONCURRENT_SUBNETS",
				Description: desc,
				Severity:    severity,
				DetectedAt:  obs.Timestamp,
			}
			e.riskScorer.AddFactor(entityID, factor)
			e.recordIncident(obs, "CONCURRENT_SUBNETS", severity, desc)
		}
	}

	if hasAnomaly {
		e.anomaliesDetected.Add(1)
		e.mu.Lock()
		e.lastAnomalyTime = obs.Timestamp
		e.mu.Unlock()
	} else {
		// Progressive score decay on nominal activity
		e.riskScorer.RecordNominalActivity(entityID)
	}

	score := e.riskScorer.GetScore(entityID)
	if score.ChallengeEscalation && score.ChallengeToken != "" {
		e.challengesIssued.Add(1)
	}

	return score, hasAnomaly
}

// GetRiskScore returns the current risk evaluation for a given license or HWID.
func (e *Engine) GetRiskScore(entityID string) *RiskScore {
	return e.riskScorer.GetScore(entityID)
}

// IssueChallenge manually issues an escalation challenge for an entity.
func (e *Engine) IssueChallenge(entityID string, challengeType ChallengeType) (*RiskScore, string) {
	score, token := e.riskScorer.IssueChallenge(entityID, challengeType)
	e.challengesIssued.Add(1)
	return score, token
}

// VerifyChallengeResponse verifies and clears a client's escalation challenge.
func (e *Engine) VerifyChallengeResponse(token string) (string, bool) {
	entityID, valid := e.riskScorer.VerifyChallengeResponse(token)
	if valid {
		e.challengesCleared.Add(1)
	}
	return entityID, valid
}

// ExportIncidentGraph synthesizes a real-time topology graph for SIEM ingestion.
func (e *Engine) ExportIncidentGraph(filter GraphFilter) *IncidentGraph {
	return e.graphExporter.ExportGraph(filter)
}

// IsQuarantined checks if an entity has crossed the critical risk threshold.
func (e *Engine) IsQuarantined(entityID string) bool {
	score := e.riskScorer.GetScore(entityID)
	return score.QuarantineTriggered
}

// GetTelemetry delivers operational metrics on anomaly detection.
func (e *Engine) GetTelemetry() TelemetrySummary {
	e.mu.RLock()
	lastAnomaly := e.lastAnomalyTime
	e.mu.RUnlock()

	return TelemetrySummary{
		TotalObservations:       e.totalObservations.Load(),
		ActiveMonitoredEntities: len(e.riskScorer.scores),
		AnomaliesDetected:       e.anomaliesDetected.Load(),
		ChallengesIssued:        e.challengesIssued.Load(),
		ChallengesCleared:       e.challengesCleared.Load(),
		ActiveQuarantines:       e.countQuarantines(),
		LastAnomalyDetectedAt:   lastAnomaly,
	}
}

func (e *Engine) countQuarantines() int64 {
	e.riskScorer.mu.RLock()
	defer e.riskScorer.mu.RUnlock()
	var count int64
	for _, sc := range e.riskScorer.scores {
		if sc.QuarantineTriggered {
			count++
		}
	}
	return count
}

func (e *Engine) recordIncident(obs ClientObservation, incType string, severity int, message string) {
	entityID := strings.TrimSpace(obs.LicenseKey)
	if entityID == "" {
		entityID = strings.TrimSpace(obs.HWID)
	}

	e.graphExporter.RecordIncident(IncidentEvent{
		EntityID:   entityID,
		LicenseKey: obs.LicenseKey,
		HWID:       obs.HWID,
		IP:         obs.IP,
		Country:    obs.Country,
		Type:       incType,
		Severity:   severity,
		Message:    message,
		Timestamp:  obs.Timestamp,
	})
}
