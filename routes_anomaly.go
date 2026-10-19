package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anomaly"
)

// registerAnomalyRoutes mounts REST endpoints for behavioral anomaly detection and adaptive risk scoring.
func (s *AppServer) registerAnomalyRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/anomaly/record", s.handleAnomalyRecord)
	apiMux.HandleFunc("/api/anomaly/score", s.handleAnomalyScore)
	apiMux.HandleFunc("/api/anomaly/challenge/issue", s.handleAnomalyChallengeIssue)
	apiMux.HandleFunc("/api/anomaly/challenge/verify", s.handleAnomalyChallengeVerify)
	apiMux.HandleFunc("/api/anomaly/graph", s.handleAnomalyGraph)
	apiMux.HandleFunc("/api/anomaly/status", s.handleAnomalyStatus)
}

func (s *AppServer) handleAnomalyRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var obs anomaly.ClientObservation
	if err := json.NewDecoder(r.Body).Decode(&obs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	// Auto-fill IP from RemoteAddr if empty
	if obs.IP == "" {
		remote := r.RemoteAddr
		if idx := strings.LastIndex(remote, ":"); idx != -1 {
			obs.IP = remote[:idx]
		} else {
			obs.IP = remote
		}
	}
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}

	score, err := s.proxy.RecordClientTelemetry(r.Context(), obs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "recorded",
		"risk_score": score,
	})
}

func (s *AppServer) handleAnomalyScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	licenseKey := strings.TrimSpace(r.URL.Query().Get("license_key"))
	hwid := strings.TrimSpace(r.URL.Query().Get("hwid"))

	if licenseKey == "" && hwid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key or hwid required"})
		return
	}

	score := s.proxy.GetAnomalyRiskScore(licenseKey, hwid)
	writeJSON(w, http.StatusOK, score)
}

func (s *AppServer) handleAnomalyChallengeIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		HWID       string `json:"hwid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	score, token, err := s.proxy.IssueAnomalyChallenge(req.LicenseKey, req.HWID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "challenge_issued",
		"challenge_token": token,
		"risk_score":      score,
	})
}

func (s *AppServer) handleAnomalyChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ChallengeToken string `json:"challenge_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ChallengeToken) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_token is required"})
		return
	}

	entityID, valid, err := s.proxy.VerifyAnomalyChallenge(req.ChallengeToken)
	if err != nil || !valid {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"valid": false,
			"error": "Invalid or expired challenge token",
		})
		return
	}

	score := s.proxy.GetAnomalyRiskScore(entityID, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "challenge_cleared",
		"valid":           true,
		"entity_id":       entityID,
		"risk_score":      score,
	})
}

func (s *AppServer) handleAnomalyGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filter := anomaly.GraphFilter{
		LicenseKey: strings.TrimSpace(r.URL.Query().Get("license_key")),
		HWID:       strings.TrimSpace(r.URL.Query().Get("hwid")),
	}

	if minStr := r.URL.Query().Get("min_score"); minStr != "" {
		if val, err := strconv.Atoi(minStr); err == nil {
			filter.MinRiskScore = val
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = val
		}
	}
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			filter.Since = t
		}
	}

	graph := s.proxy.ExportIncidentGraph(filter)
	writeJSON(w, http.StatusOK, graph)
}

func (s *AppServer) handleAnomalyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetAnomalyStatus())
}
