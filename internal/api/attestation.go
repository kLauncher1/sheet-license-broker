package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/attestation"
)

// registerAttestationRoutes mounts hardware attestation and anti-tamper endpoints.
func (s *Server) registerAttestationRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/attestation/challenge", s.handleAttestationChallenge)
	apiMux.HandleFunc("/api/attestation/verify", s.handleAttestationVerify)
	apiMux.HandleFunc("/api/attestation/status", s.handleAttestationStatus)
	apiMux.HandleFunc("/api/attestation/telemetry", s.handleAttestationTelemetry)
}

// handleAttestationChallenge generates a single-use random nonce challenge for TPM quote or enclave binding.
func (s *Server) handleAttestationChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		HWID       string `json:"hwid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	normKey := strings.TrimSpace(req.LicenseKey)
	normHWID := strings.TrimSpace(req.HWID)
	if normKey == "" || normHWID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key and hwid are required"})
		return
	}

	c, err := s.proxy.CreateAttestationChallenge(normKey, normHWID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"challenge_id": c.ChallengeID,
		"nonce":        c.Nonce,
		"expires_at":   c.ExpiresAt,
	})
}

// handleAttestationVerify validates a TPM 2.0 PCR quote or Secure Enclave assertion statement.
func (s *Server) handleAttestationVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey      string                          `json:"license_key"`
		HWID            string                          `json:"hwid"`
		ChallengeID     string                          `json:"challenge_id"`
		AttestationType attestation.AttestationType     `json:"attestation_type"`
		TPMQuote        *attestation.PCRQuote           `json:"tpm_quote,omitempty"`
		Enclave         *attestation.EnclaveAttestation `json:"enclave,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	normKey := strings.TrimSpace(req.LicenseKey)
	normHWID := strings.TrimSpace(req.HWID)
	normChID := strings.TrimSpace(req.ChallengeID)
	if normKey == "" || normHWID == "" || normChID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key, hwid, and challenge_id are required"})
		return
	}

	ctx := r.Context()
	var rec *attestation.AttestationRecord
	var err error

	switch req.AttestationType {
	case attestation.TypeTPM2:
		if req.TPMQuote == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tpm_quote is required for tpm2 attestation"})
			return
		}
		rec, err = s.proxy.VerifyTPMAttestation(ctx, normKey, normHWID, normChID, req.TPMQuote)
	case attestation.TypeSecureEnclave, attestation.TypeWindowsHello:
		if req.Enclave == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enclave is required for enclave attestation"})
			return
		}
		rec, err = s.proxy.VerifyEnclaveAttestation(ctx, normKey, normHWID, normChID, req.Enclave)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported attestation_type (expected tpm2, secure_enclave, or windows_hello)"})
		return
	}

	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"record": rec,
	})
}

// handleAttestationStatus returns the verified attestation record or list of all device records.
func (s *Server) handleAttestationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := strings.TrimSpace(r.URL.Query().Get("license_key"))
	hwid := strings.TrimSpace(r.URL.Query().Get("hwid"))

	if key != "" && hwid != "" {
		rec, found := s.proxy.GetAttestationStatus(key, hwid)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "No attestation record found for device"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "success",
			"record": rec,
		})
		return
	}

	records := s.proxy.ListAttestations()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"records": records,
		"count":   len(records),
	})
}

// handleAttestationTelemetry ingests anti-debugging and integrity telemetry from client instances.
func (s *Server) handleAttestationTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string                      `json:"license_key"`
		HWID       string                      `json:"hwid"`
		Report     *attestation.TelemetryReport `json:"report"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	normKey := strings.TrimSpace(req.LicenseKey)
	normHWID := strings.TrimSpace(req.HWID)
	if normKey == "" || normHWID == "" || req.Report == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key, hwid, and report are required"})
		return
	}

	score, tampered, rec, err := s.proxy.SubmitAttestationTelemetry(r.Context(), normKey, normHWID, req.Report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"tamper_score": score,
		"tampered":     tampered,
		"trust_level":  rec.TrustLevel,
		"details":      rec.Details,
	})
}
