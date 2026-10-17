package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anomaly"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func setupTestAnomalyServer(t *testing.T) (*AppServer, *http.ServeMux) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	secGuard := security.NewGuard([]byte("test-anomaly-secret"), 5*time.Minute, false)
	server := &AppServer{proxy: px, guard: secGuard}

	apiMux := http.NewServeMux()
	server.registerAnomalyRoutes(apiMux)

	mux := http.NewServeMux()
	mux.Handle("/api/", apiMux)

	return server, mux
}

func TestRoutesAnomalyWorkflow(t *testing.T) {
	_, mux := setupTestAnomalyServer(t)

	licKey := "LIC-ROUTER-ANOMALY-001"
	hwid := "HWID-ROUTER-AAA"

	// 1. POST /api/anomaly/record
	obsPayload := anomaly.ClientObservation{
		LicenseKey: licKey,
		HWID:       hwid,
		IP:         "198.51.100.5",
		Country:    "US",
		Action:     "heartbeat",
		Timestamp:  time.Now(),
	}
	body, _ := json.Marshal(obsPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/anomaly/record", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected /api/anomaly/record status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var recResp struct {
		Status    string             `json:"status"`
		RiskScore *anomaly.RiskScore `json:"risk_score"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &recResp); err != nil {
		t.Fatalf("failed to unmarshal record response: %v", err)
	}
	if recResp.Status != "recorded" || recResp.RiskScore == nil {
		t.Errorf("unexpected record response: %+v", recResp)
	}

	// 2. GET /api/anomaly/score
	reqScore := httptest.NewRequest(http.MethodGet, "/api/anomaly/score?license_key="+licKey, nil)
	wScore := httptest.NewRecorder()
	mux.ServeHTTP(wScore, reqScore)

	if wScore.Code != http.StatusOK {
		t.Fatalf("expected /api/anomaly/score status 200, got %d", wScore.Code)
	}
	var scoreResp anomaly.RiskScore
	if err := json.Unmarshal(wScore.Body.Bytes(), &scoreResp); err != nil {
		t.Fatalf("failed to unmarshal score response: %v", err)
	}
	if scoreResp.EntityID != licKey {
		t.Errorf("expected entity ID %s, got %s", licKey, scoreResp.EntityID)
	}

	// 3. POST /api/anomaly/challenge/issue
	issueReq := map[string]string{"license_key": licKey, "hwid": hwid}
	issueBody, _ := json.Marshal(issueReq)
	reqIssue := httptest.NewRequest(http.MethodPost, "/api/anomaly/challenge/issue", bytes.NewReader(issueBody))
	reqIssue.Header.Set("Content-Type", "application/json")
	wIssue := httptest.NewRecorder()
	mux.ServeHTTP(wIssue, reqIssue)

	if wIssue.Code != http.StatusOK {
		t.Fatalf("expected /api/anomaly/challenge/issue status 200, got %d", wIssue.Code)
	}
	var issueResp struct {
		Status         string `json:"status"`
		ChallengeToken string `json:"challenge_token"`
	}
	if err := json.Unmarshal(wIssue.Body.Bytes(), &issueResp); err != nil || issueResp.ChallengeToken == "" {
		t.Fatalf("failed to parse issue response or empty token: %v", err)
	}

	// 4. POST /api/anomaly/challenge/verify
	verifyReq := map[string]string{"challenge_token": issueResp.ChallengeToken}
	verifyBody, _ := json.Marshal(verifyReq)
	reqVerify := httptest.NewRequest(http.MethodPost, "/api/anomaly/challenge/verify", bytes.NewReader(verifyBody))
	reqVerify.Header.Set("Content-Type", "application/json")
	wVerify := httptest.NewRecorder()
	mux.ServeHTTP(wVerify, reqVerify)

	if wVerify.Code != http.StatusOK {
		t.Fatalf("expected /api/anomaly/challenge/verify status 200, got %d (body: %s)", wVerify.Code, wVerify.Body.String())
	}

	// 5. GET /api/anomaly/graph
	reqGraph := httptest.NewRequest(http.MethodGet, "/api/anomaly/graph?min_score=0&limit=10", nil)
	wGraph := httptest.NewRecorder()
	mux.ServeHTTP(wGraph, reqGraph)

	if wGraph.Code != http.StatusOK {
		t.Fatalf("expected /api/anomaly/graph status 200, got %d", wGraph.Code)
	}
	var graphResp anomaly.IncidentGraph
	if err := json.Unmarshal(wGraph.Body.Bytes(), &graphResp); err != nil {
		t.Fatalf("failed to parse graph response: %v", err)
	}
	if graphResp.Format != "siem-topology-v1" {
		t.Errorf("expected siem-topology-v1 format, got %s", graphResp.Format)
	}

	// 6. GET /api/anomaly/status
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/anomaly/status", nil)
	wStatus := httptest.NewRecorder()
	mux.ServeHTTP(wStatus, reqStatus)

	if wStatus.Code != http.StatusOK {
		t.Fatalf("expected /api/anomaly/status status 200, got %d", wStatus.Code)
	}
}
