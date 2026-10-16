package anomaly

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestHeartbeatDriftAnalysis(t *testing.T) {
	analyzer := NewHeartbeatDriftAnalyzer(16)
	entityID := "LIC-DRIFT-TEST-001"
	baseTime := time.Now()

	// 1. Establish baseline heartbeat: 1000ms intervals
	for i := 0; i < 10; i++ {
		tStep := baseTime.Add(time.Duration(i*1000) * time.Millisecond)
		drift := analyzer.RecordHeartbeat(entityID, tStep)
		if drift == nil {
			t.Fatalf("expected drift evaluation at sample %d", i)
		}
	}

	// 2. Normal heartbeat: 1010ms (nominal)
	nominalTime := baseTime.Add(10010 * time.Millisecond)
	driftNominal := analyzer.RecordHeartbeat(entityID, nominalTime)
	if driftNominal.DriftState != "nominal" {
		t.Errorf("expected nominal drift state, got %s", driftNominal.DriftState)
	}

	// 3. Accelerated flood: suddenly 20ms interval (z-score should spike and state = accelerated)
	floodTime := nominalTime.Add(20 * time.Millisecond)
	driftFlood := analyzer.RecordHeartbeat(entityID, floodTime)
	if driftFlood.DriftState != "accelerated" {
		t.Errorf("expected accelerated drift state on 20ms flood, got %s (z: %.2f)", driftFlood.DriftState, driftFlood.ZScore)
	}
}

func TestGeoVelocityAndImpossibleTravel(t *testing.T) {
	detector := NewGeoVelocityDetector(950.0) // 950 km/h limit
	entityID := "LIC-GEO-TEST-001"
	t0 := time.Now()

	// Initial connection: United States
	_, isImp1 := detector.RecordLocation(entityID, "198.51.100.1", "US", t0)
	if isImp1 {
		t.Fatal("initial location should not trigger impossible travel")
	}

	// Connection 2: Japan within 60 seconds (approx 10,000 km in 1 minute = ~600,000 km/h)
	t1 := t0.Add(60 * time.Second)
	anomaly, isImp2 := detector.RecordLocation(entityID, "203.0.113.5", "JP", t1)
	if !isImp2 || anomaly == nil {
		t.Fatal("expected impossible travel alert for US -> JP in 60 seconds")
	}
	if anomaly.CalculatedSpeedKmH < 10000.0 {
		t.Errorf("expected calculated speed > 10,000 km/h, got %.1f", anomaly.CalculatedSpeedKmH)
	}

	// Concurrent subnets check: both US and JP IPs were within 5 minutes
	subnets, isMulti := detector.DetectConcurrentSubnets(entityID)
	if !isMulti || subnets < 2 {
		t.Errorf("expected multi-subnet detection, got subnets=%d, isMulti=%v", subnets, isMulti)
	}
}

func TestAdaptiveRiskScoringAndDecay(t *testing.T) {
	scorer := NewAdaptiveRiskScorer(5, 5*time.Minute)
	entityID := "LIC-RISK-001"

	score0 := scorer.GetScore(entityID)
	if score0.Score != 0 || score0.Level != RiskLevelLow {
		t.Errorf("expected initial score 0 low, got %d %s", score0.Score, score0.Level)
	}

	// Add mild factor (+15)
	scorer.AddFactor(entityID, RiskFactor{Code: "MILD", Severity: 15, DetectedAt: time.Now()})
	s1 := scorer.GetScore(entityID)
	if s1.Score != 15 || s1.Level != RiskLevelLow {
		t.Errorf("expected score 15 low, got %d %s", s1.Score, s1.Level)
	}

	// Add medium factor (+20) -> total 35 (medium)
	scorer.AddFactor(entityID, RiskFactor{Code: "MEDIUM", Severity: 20, DetectedAt: time.Now()})
	s2 := scorer.GetScore(entityID)
	if s2.Score != 35 || s2.Level != RiskLevelMedium {
		t.Errorf("expected score 35 medium, got %d %s", s2.Score, s2.Level)
	}

	// Nominal activity decay (-5)
	scorer.RecordNominalActivity(entityID)
	s3 := scorer.GetScore(entityID)
	if s3.Score != 30 {
		t.Errorf("expected score after decay to be 30, got %d", s3.Score)
	}
}

func TestChallengeEscalationAndClearance(t *testing.T) {
	scorer := NewAdaptiveRiskScorer(5, 5*time.Minute)
	entityID := "LIC-CHALLENGE-001"

	// Add heavy factor (+55) -> total 55 (high risk, challenge escalation triggered)
	scorer.AddFactor(entityID, RiskFactor{Code: "HEAVY_ANOMALY", Severity: 55, DetectedAt: time.Now()})
	s1 := scorer.GetScore(entityID)
	if !s1.ChallengeEscalation || s1.ChallengeToken == "" {
		t.Fatal("expected challenge escalation with active token for score >= 50")
	}

	// Verify with invalid token
	_, valid := scorer.VerifyChallengeResponse("invalid-token-1234")
	if valid {
		t.Fatal("invalid token should not verify")
	}

	// Verify with valid challenge token
	resolvedEntity, valid := scorer.VerifyChallengeResponse(s1.ChallengeToken)
	if !valid || resolvedEntity != entityID {
		t.Fatalf("expected challenge to clear successfully, got valid=%v, entity=%s", valid, resolvedEntity)
	}

	// Score should be reduced significantly and challenge cleared
	s2 := scorer.GetScore(entityID)
	if s2.ChallengeEscalation {
		t.Error("expected challenge escalation to be cleared")
	}
	if s2.Score >= 50 {
		t.Errorf("expected score to drop below 50 after challenge clearance, got %d", s2.Score)
	}
}

func TestQuarantineEnforcement(t *testing.T) {
	scorer := NewAdaptiveRiskScorer(5, 5*time.Minute)
	entityID := "LIC-QUARANTINE-001"

	// Add critical factors (+90)
	scorer.AddFactor(entityID, RiskFactor{Code: "CRITICAL_COMPROMISE", Severity: 90, DetectedAt: time.Now()})
	s := scorer.GetScore(entityID)

	if !s.QuarantineTriggered || s.Level != RiskLevelCritical {
		t.Errorf("expected quarantine triggered and critical level, got quarantined=%v level=%s", s.QuarantineTriggered, s.Level)
	}
}

func TestIncidentGraphExport(t *testing.T) {
	exporter := NewIncidentGraphExporter(100)
	now := time.Now()

	exporter.RecordIncident(IncidentEvent{
		EntityID:   "LIC-GRAPH-100",
		LicenseKey: "LIC-GRAPH-100",
		HWID:       "HWID-GRAPH-AAA",
		IP:         "198.51.100.50",
		Country:    "US",
		Type:       "IMPOSSIBLE_TRAVEL",
		Severity:   60,
		Message:    "Velocity anomaly detected",
		Timestamp:  now,
	})

	graph := exporter.ExportGraph(GraphFilter{MinRiskScore: 30})
	if graph.TotalNodes == 0 || graph.TotalEdges == 0 {
		t.Fatalf("expected non-empty graph, got nodes=%d edges=%d", graph.TotalNodes, graph.TotalEdges)
	}

	// Verify JSON serialization for SIEM ingestion
	data, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("failed to marshal incident graph to JSON: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty serialized JSON graph")
	}

	// Test filter by license
	filtered := exporter.ExportGraph(GraphFilter{LicenseKey: "LIC-GRAPH-100"})
	if filtered.TotalNodes == 0 {
		t.Error("expected filtered graph to match target license")
	}
}

func TestConcurrentAnomalyEngine(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	var wg sync.WaitGroup

	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			licKey := fmt.Sprintf("LIC-CONCUR-%02d", workerID)
			hwid := fmt.Sprintf("HWID-%02d", workerID)
			for j := 0; j < 10; j++ {
				obs := ClientObservation{
					LicenseKey: licKey,
					HWID:       hwid,
					IP:         fmt.Sprintf("192.0.2.%d", workerID),
					Country:    "US",
					Action:     "heartbeat",
					Timestamp:  time.Now().Add(time.Duration(j) * time.Second),
				}
				score, _ := engine.RecordObservation(obs)
				if score == nil {
					t.Errorf("worker %d got nil score", workerID)
				}
				_ = engine.GetRiskScore(licKey)
			}
		}(i)
	}
	wg.Wait()

	telemetry := engine.GetTelemetry()
	if telemetry.TotalObservations != 250 {
		t.Errorf("expected 250 total observations, got %d", telemetry.TotalObservations)
	}
	if telemetry.ActiveMonitoredEntities != 25 {
		t.Errorf("expected 25 active monitored entities, got %d", telemetry.ActiveMonitoredEntities)
	}
}
