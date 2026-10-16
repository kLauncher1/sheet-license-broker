package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anomaly"
)

func TestGoClientAnomalyWorkflow(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/anomaly/record", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "recorded",
			"risk_score": anomaly.RiskScore{
				EntityID: "LIC-GO-TEST",
				Score:    0,
				Level:    anomaly.RiskLevelLow,
			},
		})
	})

	mux.HandleFunc("/api/anomaly/score", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(anomaly.RiskScore{
			EntityID: "LIC-GO-TEST",
			Score:    20,
			Level:    anomaly.RiskLevelLow,
		})
	})

	mux.HandleFunc("/api/anomaly/challenge/issue", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "challenge_issued",
			"challenge_token": "token-xyz-123",
			"risk_score": anomaly.RiskScore{
				EntityID:            "LIC-GO-TEST",
				Score:               55,
				ChallengeEscalation: true,
			},
		})
	})

	mux.HandleFunc("/api/anomaly/challenge/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "challenge_cleared",
			"valid":  true,
			"risk_score": anomaly.RiskScore{
				EntityID:            "LIC-GO-TEST",
				Score:               10,
				ChallengeEscalation: false,
			},
		})
	})

	mux.HandleFunc("/api/anomaly/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(anomaly.IncidentGraph{
			Format:      "siem-topology-v1",
			TotalNodes:  2,
			TotalEdges:  1,
			GeneratedAt: time.Now(),
		})
	})

	mux.HandleFunc("/api/anomaly/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total_observations": 100,
			"active_quarantines": 0,
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, []byte("test-secret"), 5*time.Second)

	ctx := context.Background()

	// 1. Record Observation
	score, err := client.RecordAnomalyObservation(ctx, anomaly.ClientObservation{
		LicenseKey: "LIC-GO-TEST",
		Action:     "heartbeat",
	})
	if err != nil || score == nil {
		t.Fatalf("failed to record anomaly observation: %v", err)
	}

	// 2. Query Score
	qScore, err := client.GetAnomalyRiskScore(ctx, "LIC-GO-TEST", "")
	if err != nil || qScore.Score != 20 {
		t.Fatalf("failed to query risk score: %v", err)
	}

	// 3. Issue Challenge
	token, cScore, err := client.IssueAnomalyChallenge(ctx, "LIC-GO-TEST", "")
	if err != nil || token != "token-xyz-123" || !cScore.ChallengeEscalation {
		t.Fatalf("failed to issue challenge: %v, token=%s", err, token)
	}

	// 4. Verify Challenge
	vScore, err := client.VerifyAnomalyChallenge(ctx, token)
	if err != nil || vScore.Score != 10 {
		t.Fatalf("failed to verify challenge: %v", err)
	}

	// 5. Export Incident Graph
	graph, err := client.ExportIncidentGraph(ctx, 0, 10)
	if err != nil || graph.Format != "siem-topology-v1" {
		t.Fatalf("failed to export incident graph: %v", err)
	}

	// 6. Get Anomaly Status
	status, err := client.GetAnomalyStatus(ctx)
	if err != nil || status["total_observations"] == nil {
		t.Fatalf("failed to query anomaly status: %v", err)
	}
}
