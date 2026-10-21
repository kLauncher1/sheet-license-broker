package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/airgap"
)

// registerAirgapRoutes mounts REST endpoints for air-gapped license vault and offline dongle emulation.
func (s *AppServer) registerAirgapRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/airgap/token/issue", s.handleAirgapTokenIssue)
	apiMux.HandleFunc("/api/airgap/token/verify", s.handleAirgapTokenVerify)
	apiMux.HandleFunc("/api/airgap/activate/request", s.handleAirgapActivateRequest)
	apiMux.HandleFunc("/api/airgap/activate/fulfill", s.handleAirgapActivateFulfill)
	apiMux.HandleFunc("/api/airgap/rollback/unlock", s.handleAirgapRollbackUnlock)
	apiMux.HandleFunc("/api/airgap/rollback/state", s.handleAirgapRollbackState)
	apiMux.HandleFunc("/api/airgap/status", s.handleAirgapStatus)
}

func (s *AppServer) handleAirgapTokenIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req airgap.IssueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.LicenseKey) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key is required"})
		return
	}

	token, compact, qrPayload, err := s.proxy.IssueAirgapToken(r.Context(), req)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, airgap.ErrVaultTampered) || errors.Is(err, airgap.ErrClockRollback) {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"token":        token,
		"dongle_token": compact,
		"qr_payload":   qrPayload,
	})
}

func (s *AppServer) handleAirgapTokenVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token     string `json:"token"`
		HWID      string `json:"hwid"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.Token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	if req.Timestamp <= 0 {
		req.Timestamp = time.Now().Unix()
	}

	token, err := s.proxy.VerifyAirgapToken(r.Context(), req.Token, req.HWID, req.Timestamp)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, airgap.ErrVaultTampered) || errors.Is(err, airgap.ErrClockRollback) {
			status = http.StatusForbidden
		} else if errors.Is(err, airgap.ErrInvalidToken) {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]interface{}{
			"status": "error",
			"valid":  false,
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"valid":  true,
		"token":  token,
	})
}

func (s *AppServer) handleAirgapActivateRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req airgap.ActivationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.LicenseKey) == "" || strings.TrimSpace(req.HWID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key and hwid are required"})
		return
	}

	res, err := s.proxy.RequestAirgapActivation(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "success",
		"activation": res,
	})
}

func (s *AppServer) handleAirgapActivateFulfill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		QRPayload string `json:"qr_payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.QRPayload) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "qr_payload is required"})
		return
	}

	token, err := s.proxy.FulfillAirgapActivation(r.Context(), req.QRPayload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"token":  token,
	})
}

func (s *AppServer) handleAirgapRollbackUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req airgap.UnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.HWID) == "" || strings.TrimSpace(req.AdminSignature) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hwid and admin_signature are required"})
		return
	}

	st, err := s.proxy.UnlockAirgapRollback(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"state":  st,
	})
}

func (s *AppServer) handleAirgapRollbackState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hwid := r.URL.Query().Get("hwid")
	st := s.proxy.GetAirgapRollbackState(hwid)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"state":  st,
	})
}

func (s *AppServer) handleAirgapStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetAirgapStatus())
}
