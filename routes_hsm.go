package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/hsm"
)

// registerHSMRoutes mounts REST endpoints for the PKCS#11 Hardware Security Module vault.
func (s *AppServer) registerHSMRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/hsm/status", s.handleHSMStatus)
	apiMux.HandleFunc("/api/hsm/slots", s.handleHSMSlots)
	apiMux.HandleFunc("/api/hsm/login", s.handleHSMLogin)
	apiMux.HandleFunc("/api/hsm/logout", s.handleHSMLogout)
	apiMux.HandleFunc("/api/hsm/derive", s.handleHSMDerive)
	apiMux.HandleFunc("/api/hsm/encrypt", s.handleHSMEncrypt)
	apiMux.HandleFunc("/api/hsm/decrypt", s.handleHSMDecrypt)
	apiMux.HandleFunc("/api/hsm/fips/selftest", s.handleHSMSelfTest)
	apiMux.HandleFunc("/api/hsm/fips/report", s.handleHSMFIPSReport)
	apiMux.HandleFunc("/api/hsm/tamper/simulate", s.handleHSMTamperSimulate)
	apiMux.HandleFunc("/api/hsm/zeroize", s.handleHSMZeroize)
}

func (s *AppServer) handleHSMStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetHSMStatus())
}

func (s *AppServer) handleHSMSlots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"slots": s.proxy.ListHSMSlots(),
	})
}

type hsmLoginRequest struct {
	SlotID   int    `json:"slot_id"`
	UserType string `json:"user_type"`
	PIN      string `json:"pin"`
}

func (s *AppServer) handleHSMLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req hsmLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	uType := uint32(hsm.CKU_USER)
	if strings.ToUpper(req.UserType) == "SO" || strings.ToUpper(req.UserType) == "ADMIN" {
		uType = hsm.CKU_SO
	}

	if err := s.proxy.HSMLogin(req.SlotID, uType, req.PIN); err != nil {
		status := http.StatusUnauthorized
		if err == hsm.ErrPINLocked {
			status = http.StatusLocked
		} else if err == hsm.ErrTamperDetected {
			status = http.StatusGone
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"slot_id":       req.SlotID,
		"user_type":     req.UserType,
	})
}

type hsmSlotRequest struct {
	SlotID int `json:"slot_id"`
}

func (s *AppServer) handleHSMLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req hsmSlotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.SlotID = 0
	}

	if err := s.proxy.HSMLogout(req.SlotID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logged_out": true,
		"slot_id":    req.SlotID,
	})
}

func (s *AppServer) handleHSMDerive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req hsm.KeyDerivationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid derivation request"})
		return
	}

	resp, err := s.proxy.DeriveHSMKey(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *AppServer) handleHSMEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req hsm.EnvelopeEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid encryption request"})
		return
	}

	resp, err := s.proxy.EncryptHSMEnvelope(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *AppServer) handleHSMDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req hsm.EnvelopeDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid decryption request"})
		return
	}

	resp, err := s.proxy.DecryptHSMEnvelope(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *AppServer) handleHSMSelfTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	results := s.proxy.RunHSMSelfTest()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"self_tests": results,
		"count":      len(results),
	})
}

func (s *AppServer) handleHSMFIPSReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, s.proxy.GetHSMFIPSReport())
}

type hsmTamperRequest struct {
	SensorID string `json:"sensor_id"`
}

func (s *AppServer) handleHSMTamperSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req hsmTamperRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.SensorID = "DEFAULT_SIMULATED_BREACH"
	}

	if err := s.proxy.SimulateHSMTamper(req.SensorID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tamper_latched": true,
		"sensor_id":      req.SensorID,
		"zeroized":       true,
	})
}

func (s *AppServer) handleHSMZeroize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.proxy.ZeroizeHSM()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"zeroized": true,
	})
}
