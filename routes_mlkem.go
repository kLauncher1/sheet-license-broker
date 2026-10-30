package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/mlkem"
)

// registerMLKEMRoutes mounts REST endpoints for the NIST FIPS 203 ML-KEM lattice key encapsulation engine.
func (s *AppServer) registerMLKEMRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/pqc/kem/status", s.handleMLKEMStatus)
	apiMux.HandleFunc("/api/pqc/kem/keys", s.handleMLKEMKeys)
	apiMux.HandleFunc("/api/pqc/kem/keys/generate", s.handleMLKEMGenerateKey)
	apiMux.HandleFunc("/api/pqc/kem/encapsulate", s.handleMLKEMEncapsulate)
	apiMux.HandleFunc("/api/pqc/kem/decapsulate", s.handleMLKEMDecapsulate)
	apiMux.HandleFunc("/api/pqc/kem/handshake", s.handleMLKEMHandshake)
	apiMux.HandleFunc("/api/pqc/kem/sessions/verify", s.handleMLKEMVerifySession)
}

func (s *AppServer) handleMLKEMStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetMLKEMStatus())
}

func (s *AppServer) handleMLKEMKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys": s.proxy.ListMLKEMKeys(),
	})
}

type mlkemGenerateKeyRequest struct {
	Algorithm string `json:"algorithm"`
}

func (s *AppServer) handleMLKEMGenerateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mlkemGenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	pk, err := s.proxy.GenerateMLKEMKey(req.Algorithm)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, pk)
}

type mlkemEncapsulateRequest struct {
	KeyID string `json:"key_id"`
}

func (s *AppServer) handleMLKEMEncapsulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mlkemEncapsulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	res, err := s.proxy.EncapsulateMLKEM(req.KeyID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, res)
}

type mlkemDecapsulateRequest struct {
	KeyID         string `json:"key_id"`
	CiphertextHex string `json:"ciphertext_hex"`
}

func (s *AppServer) handleMLKEMDecapsulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mlkemDecapsulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	cBytes, err := hex.DecodeString(strings.TrimSpace(req.CiphertextHex))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ciphertext hex"})
		return
	}

	ss, err := s.proxy.DecapsulateMLKEM(req.KeyID, cBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"key_id":            req.KeyID,
		"shared_secret_hex": hex.EncodeToString(ss),
	})
}

func (s *AppServer) handleMLKEMHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mlkem.HybridHandshakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	resp, err := s.proxy.HandleHybridKEMHandshake(req)
	if err != nil {
		status := http.StatusBadRequest
		if err == mlkem.ErrDowngradeRejected {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

type mlkemVerifySessionRequest struct {
	SessionID string `json:"session_id"`
}

func (s *AppServer) handleMLKEMVerifySession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" && r.Method == http.MethodPost {
		var req mlkemVerifySessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			sessionID = req.SessionID
		}
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing session_id"})
		return
	}

	session, err := s.proxy.VerifyHybridKEMSession(sessionID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":             true,
		"session_id":        session.SessionID,
		"agreed_mode":       session.AgreedMode,
		"algorithm":         session.Algorithm,
		"quantum_resistant": session.QuantumResistant,
		"created_at":        session.CreatedAt,
		"expires_at":        session.ExpiresAt,
	})
}
