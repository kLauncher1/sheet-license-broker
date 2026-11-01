package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/posture"
)

// registerPostureRoutes registers REST API endpoints for zero-trust posture attestation and device health.
func (s *AppServer) registerPostureRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/posture/status", s.handlePostureStatus)
	apiMux.HandleFunc("/api/posture/evaluate", s.handlePostureEvaluate)
	apiMux.HandleFunc("/api/posture/quarantine", s.handlePostureQuarantine)
	apiMux.HandleFunc("/api/posture/quarantine/release", s.handlePostureQuarantineRelease)
	apiMux.HandleFunc("/api/posture/step-up/challenge", s.handlePostureStepUpChallenge)
	apiMux.HandleFunc("/api/posture/step-up/verify", s.handlePostureStepUpVerify)
	apiMux.HandleFunc("/api/posture/device", s.handlePostureDevice)
}

func (s *AppServer) handlePostureStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetPostureStatus())
}

func (s *AppServer) handlePostureEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req posture.DevicePostureReport
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json posture payload"})
		return
	}

	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}

	scores := s.proxy.EvaluateDevicePosture(req)
	writeJSON(w, http.StatusOK, scores)
}

func (s *AppServer) handlePostureQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	quarantined := s.proxy.PostureManager().Registry().ListQuarantined(tenantID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id":   tenantID,
		"quarantined": quarantined,
		"count":       len(quarantined),
	})
}

type quarantineReleaseRequest struct {
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
}

func (s *AppServer) handlePostureQuarantineRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req quarantineReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}

	released := s.proxy.ReleaseDeviceQuarantine(req.TenantID, req.DeviceID)
	if !released {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found in quarantine"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "released",
		"device_id": req.DeviceID,
		"tenant_id": req.TenantID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

type stepUpChallengeRequest struct {
	TenantID string   `json:"tenant_id"`
	DeviceID string   `json:"device_id"`
	Actions  []string `json:"actions"`
}

func (s *AppServer) handlePostureStepUpChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req stepUpChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}
	if len(req.Actions) == 0 {
		req.Actions = []string{"hardware_token", "re_attestation"}
	}

	challenge := s.proxy.IssueDeviceStepUpChallenge(req.TenantID, req.DeviceID, req.Actions, 5*time.Minute)
	writeJSON(w, http.StatusOK, challenge)
}

type stepUpVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
}

func (s *AppServer) handlePostureStepUpVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req stepUpVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.ChallengeID = strings.TrimSpace(req.ChallengeID)
	req.Nonce = strings.TrimSpace(req.Nonce)
	if req.ChallengeID == "" || req.Nonce == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_id and nonce are required"})
		return
	}

	ok, err := s.proxy.VerifyDeviceStepUpChallenge(req.ChallengeID, req.Nonce)
	if !ok || err != nil {
		msg := "verification failed"
		if err != nil {
			msg = err.Error()
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "verified",
		"challenge_id": req.ChallengeID,
		"verified_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *AppServer) handlePostureDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = "default"
	}
	deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}

	scores, found := s.proxy.PostureManager().GetDevicePosture(tenantID, deviceID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device posture not found"})
		return
	}

	isQ, qDev := s.proxy.IsDeviceQuarantined(tenantID, deviceID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scores":      scores,
		"quarantined": isQ,
		"quarantine":  qDev,
	})
}
