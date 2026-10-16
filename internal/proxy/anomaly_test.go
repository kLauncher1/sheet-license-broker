package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anomaly"
)

func TestProxyAnomalyTelemetryAndScoring(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	ctx := context.Background()
	licKey := "LIC-PROXY-ANOMALY-001"
	hwid := "HWID-PROXY-AAA"

	// 1. Initial observation (nominal)
	obs1 := anomaly.ClientObservation{
		LicenseKey: licKey,
		HWID:       hwid,
		IP:         "198.51.100.10",
		Country:    "US",
		Action:     "heartbeat",
		Timestamp:  time.Now(),
	}

	score1, err := px.RecordClientTelemetry(ctx, obs1)
	if err != nil {
		t.Fatalf("RecordClientTelemetry failed: %v", err)
	}
	if score1.Score != 0 || score1.Level != anomaly.RiskLevelLow {
		t.Errorf("expected nominal score 0 low, got %d %s", score1.Score, score1.Level)
	}

	// 2. Query risk score directly
	qScore := px.GetAnomalyRiskScore(licKey, hwid)
	if qScore.Score != 0 {
		t.Errorf("expected queried score 0, got %d", qScore.Score)
	}

	// 3. Status delivers telemetry metrics
	status := px.GetAnomalyStatus()
	if total, ok := status["total_observations"].(int64); !ok || total != 1 {
		t.Errorf("expected total_observations=1, got %v", status["total_observations"])
	}
}

func TestProxyAnomalyChallengeAndQuarantine(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	licKey := "LIC-CHALLENGE-PROXY"
	hwid := "HWID-CHALLENGE-BBB"

	// 1. Issue challenge
	score, token, err := px.IssueAnomalyChallenge(licKey, hwid)
	if err != nil || token == "" {
		t.Fatalf("failed to issue challenge: %v, token=%s", err, token)
	}
	if !score.ChallengeEscalation {
		t.Error("expected challenge escalation to be active")
	}

	// 2. Verify challenge
	entity, valid, err := px.VerifyAnomalyChallenge(token)
	if err != nil || !valid || entity != licKey {
		t.Fatalf("challenge verification failed: valid=%v, entity=%s, err=%v", valid, entity, err)
	}

	// 3. Test Quarantine on VerifyLicense
	px.AnomalyEngine().RecordObservation(anomaly.ClientObservation{
		LicenseKey: licKey,
		HWID:       hwid,
		IP:         "198.51.100.20",
		Country:    "US",
		Action:     "heartbeat",
		Timestamp:  time.Now(),
	})
	// Trigger critical quarantine
	px.AnomalyEngine().GetRiskScore(licKey) // Ensure tracked
	px.AnomalyEngine().RecordObservation(anomaly.ClientObservation{
		LicenseKey: licKey,
		HWID:       hwid,
		IP:         "203.0.113.88",
		Country:    "JP", // Impossible travel US -> JP in 1 second
		Action:     "heartbeat",
		Timestamp:  time.Now().Add(1 * time.Second),
	})

	// Add more factor to push score over 85
	px.AnomalyEngine().RecordObservation(anomaly.ClientObservation{
		LicenseKey: licKey,
		HWID:       hwid,
		IP:         "198.51.100.99",
		Country:    "DE", // Another impossible travel jump
		Action:     "heartbeat",
		Timestamp:  time.Now().Add(2 * time.Second),
	})

	res, vErr := px.VerifyLicense(context.Background(), licKey, hwid)
	if vErr == nil || res.Valid {
		t.Fatalf("expected license check to be rejected due to quarantine, got valid=%v", res.Valid)
	}
	if res.Source != "quarantine" {
		t.Errorf("expected source quarantine, got %s", res.Source)
	}
}

func TestProxyExportIncidentGraph(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	licKey := "LIC-GRAPH-PROXY"
	obs := anomaly.ClientObservation{
		LicenseKey: licKey,
		HWID:       "HWID-GRAPH-123",
		IP:         "198.51.100.77",
		Country:    "US",
		Action:     "heartbeat",
		Timestamp:  time.Now(),
	}
	_, _ = px.RecordClientTelemetry(context.Background(), obs)

	graph := px.ExportIncidentGraph(anomaly.GraphFilter{Limit: 10})
	if graph == nil || graph.Format != "siem-topology-v1" {
		t.Fatalf("expected valid siem-topology-v1 graph, got %v", graph)
	}
}
