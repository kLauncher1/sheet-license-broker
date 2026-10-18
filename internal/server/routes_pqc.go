package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/pqc"
)

// handlePQCParams returns the supported post-quantum cryptography algorithms and active key info.
func (s *AppServer) handlePQCParams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := s.proxy.GetPQCStatus()
	activeKey := s.proxy.PQCManager().ActiveKey()

	var activePub interface{}
	if activeKey != nil && activeKey.MLDSAPublic != nil {
		activePub = map[string]interface{}{
			"key_id":     activeKey.KeyID,
			"algorithm":  activeKey.Algorithm,
			"public_hex": activeKey.MLDSAPublic.RawHex,
			"created_at": activeKey.CreatedAt.Format(time.RFC3339),
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "success",
		"lattice_degree":    pqc.DegreeN,
		"prime_modulus_q":   pqc.ModulusQ,
		"dropped_bits_d":    pqc.PowerD,
		"default_algorithm": status.DefaultAlgorithm,
		"supported_algorithms": status.SupportedAlgorithms,
		"active_key":        activePub,
	})
}

// handlePQCKeys returns the set of active and grace-period public keys for client-side verification.
func (s *AppServer) handlePQCKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys := s.proxy.PQCManager().GetPublicKeys()
	var list []map[string]interface{}
	for _, k := range keys {
		list = append(list, map[string]interface{}{
			"key_id":     k.KeyID,
			"algorithm":  k.Algorithm,
			"public_hex": k.RawHex,
			"created_at": k.CreatedAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"count":  len(list),
		"keys":   list,
	})
}

// handlePQCSign issues a quantum-resistant hybrid signature for an authenticated client license.
func (s *AppServer) handlePQCSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		HWID       string `json:"hwid"`
		Payload    string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON request payload"})
		return
	}

	if strings.TrimSpace(req.LicenseKey) == "" || strings.TrimSpace(req.Payload) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key and payload are required"})
		return
	}

	sig, err := s.proxy.PQCSignLicense(r.Context(), req.LicenseKey, req.HWID, []byte(req.Payload))
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "success",
		"signature": sig,
	})
}

// handlePQCVerify evaluates dual classical and post-quantum digital signatures.
func (s *AppServer) handlePQCVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Payload   string            `json:"payload"`
		Signature pqc.HybridSignature `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON request payload"})
		return
	}

	res := s.proxy.PQCVerifyHybrid(&req.Signature, []byte(req.Payload))
	if !res.Valid {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"status": "failed",
			"result": res,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"result": res,
	})
}

// handlePQCRotate advances the key epoch and triggers an audit log and storage sync.
func (s *AppServer) handlePQCRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Algorithm string `json:"algorithm"`
		GraceDays int    `json:"grace_days"`
		Reason    string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	grace := 7 * 24 * time.Hour
	if req.GraceDays > 0 {
		grace = time.Duration(req.GraceDays) * 24 * time.Hour
	}
	if req.Reason == "" {
		req.Reason = "Administrative key rotation"
	}

	rec, err := s.proxy.PQCRotateKey(r.Context(), req.Algorithm, grace, req.Reason)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"rotation": rec,
	})
}

// handlePQCRevoke revokes a compromised key and broadcasts an immediate kill-switch alert.
func (s *AppServer) handlePQCRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		KeyID  string `json:"key_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.KeyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key_id is required"})
		return
	}

	if req.Reason == "" {
		req.Reason = "Emergency revocation by operator"
	}

	if err := s.proxy.PQCRevokeKey(r.Context(), req.KeyID, req.Reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"key_id":  req.KeyID,
		"message": "Key revoked successfully and broadcast to clients",
	})
}

// handlePQCStatus reports operational telemetry for PQC signatures and key management.
func (s *AppServer) handlePQCStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := s.proxy.GetPQCStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"pqc":    status,
	})
}

// registerPQCRoutes binds all PQC endpoints to the API serve mux.
func (s *AppServer) registerPQCRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/pqc/params", s.handlePQCParams)
	apiMux.HandleFunc("/api/pqc/keys", s.handlePQCKeys)
	apiMux.HandleFunc("/api/pqc/sign", s.handlePQCSign)
	apiMux.HandleFunc("/api/pqc/verify", s.handlePQCVerify)
	apiMux.HandleFunc("/api/pqc/rotate", s.handlePQCRotate)
	apiMux.HandleFunc("/api/pqc/revoke", s.handlePQCRevoke)
	apiMux.HandleFunc("/api/pqc/status", s.handlePQCStatus)
}
