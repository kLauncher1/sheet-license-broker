package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/enclave"
)

// registerEnclaveRoutes mounts REST endpoints for confidential computing and hardware enclave attestation.
func (s *AppServer) registerEnclaveRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/enclave/challenge", s.handleEnclaveChallenge)
	apiMux.HandleFunc("/api/enclave/attest", s.handleEnclaveAttest)
	apiMux.HandleFunc("/api/enclave/tunnel/handshake", s.handleEnclaveTunnelHandshake)
	apiMux.HandleFunc("/api/enclave/tunnel/evaluate", s.handleEnclaveTunnelEvaluate)
	apiMux.HandleFunc("/api/enclave/policy", s.handleEnclavePolicy)
	apiMux.HandleFunc("/api/enclave/status", s.handleEnclaveStatus)
}

func (s *AppServer) handleEnclaveChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nonce, err := s.proxy.GenerateEnclaveChallenge()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge":  nonce,
		"expires_in": 300,
	})
}

type enclaveAttestReq struct {
	Platform enclave.PlatformType `json:"platform"`
	QuoteHex string               `json:"quote"`
	Nonce    string               `json:"nonce"`
	PolicyID string               `json:"policy_id,omitempty"`
}

func (s *AppServer) handleEnclaveAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enclaveAttestReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	rawQuote, err := hex.DecodeString(strings.TrimSpace(req.QuoteHex))
	if err != nil || len(rawQuote) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid hex-encoded quote payload"})
		return
	}

	res, err := s.proxy.AttestEnclaveQuote(req.Platform, rawQuote, req.Nonce, req.PolicyID)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":       true,
		"attestation": res,
	})
}

type enclaveHandshakeReq struct {
	Platform        enclave.PlatformType `json:"platform"`
	QuoteHex        string               `json:"quote"`
	Nonce           string               `json:"nonce"`
	PolicyID        string               `json:"policy_id,omitempty"`
	ClientPublicKey string               `json:"client_public_key"`
}

func (s *AppServer) handleEnclaveTunnelHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enclaveHandshakeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	rawQuote, err := hex.DecodeString(strings.TrimSpace(req.QuoteHex))
	if err != nil || len(rawQuote) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid hex-encoded quote payload"})
		return
	}

	session, brokerPubHex, err := s.proxy.EstablishEnclaveTunnel(req.Platform, rawQuote, req.Nonce, req.PolicyID, req.ClientPublicKey)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"established": false,
			"error":       err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"established":       true,
		"session_id":        session.SessionID,
		"broker_public_key": brokerPubHex,
		"expires_at":        session.ExpiresAt,
	})
}

type enclaveTunnelMsgReq struct {
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	NonceHex  string `json:"nonce"`
	CipherHex string `json:"payload"`
}

func (s *AppServer) handleEnclaveTunnelEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enclaveTunnelMsgReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	msg := &enclave.EncryptedTunnelMessage{
		SessionID:  strings.TrimSpace(req.SessionID),
		Sequence:   req.Sequence,
		NonceHex:   strings.TrimSpace(req.NonceHex),
		PayloadHex: strings.TrimSpace(req.CipherHex),
	}

	respMsg, err := s.proxy.EvaluateLicenseInEnclave(r.Context(), msg.SessionID, msg)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": respMsg.SessionID,
		"sequence":   respMsg.Sequence,
		"nonce":      respMsg.NonceHex,
		"payload":    respMsg.PayloadHex,
	})
}

func (s *AppServer) handleEnclavePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var pol enclave.EnclavePolicy
	if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid policy JSON"})
		return
	}

	if err := s.proxy.RegisterEnclavePolicy(&pol); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "registered",
		"policy_id": pol.ID,
	})
}

func (s *AppServer) handleEnclaveStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	telemetry := s.proxy.GetEnclaveTelemetry()
	var policies []*enclave.EnclavePolicy
	if s.proxy.EnclaveManager() != nil {
		policies = s.proxy.EnclaveManager().ListPolicies()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"telemetry": telemetry,
		"policies":  policies,
	})
}
