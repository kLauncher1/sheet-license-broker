package main

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
	apiMux.HandleFunc("/api/enclave/tdx/verify", s.handleEnclaveTDXVerify)
	apiMux.HandleFunc("/api/enclave/token/issue", s.handleEnclaveTokenIssue)
	apiMux.HandleFunc("/api/enclave/token/verify", s.handleEnclaveTokenVerify)
	apiMux.HandleFunc("/api/enclave/isolated/decrypt", s.handleEnclaveIsolatedDecrypt)
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

type tdxVerifyReq struct {
	QuoteHex string `json:"quote"`
	Nonce    string `json:"nonce"`
	PolicyID string `json:"policy_id,omitempty"`
}

func (s *AppServer) handleEnclaveTDXVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tdxVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	rawQuote, err := hex.DecodeString(strings.TrimSpace(req.QuoteHex))
	if err != nil || len(rawQuote) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid hex-encoded TDX quote payload"})
		return
	}

	res, err := s.proxy.VerifyTDXQuote(rawQuote, req.Nonce, req.PolicyID)
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

type tokenIssueReq struct {
	Platform     enclave.PlatformType `json:"platform"`
	Measurement  string               `json:"measurement"`
	RTMR0        string               `json:"rtmr0,omitempty"`
	SVN          uint32               `json:"svn"`
	Debug        bool                 `json:"debug"`
	Nonce        string               `json:"nonce"`
	PubKeyHex    string               `json:"enclave_pub_key,omitempty"`
	TTLSeconds   int                  `json:"ttl_seconds,omitempty"`
}

func (s *AppServer) handleEnclaveTokenIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tokenIssueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	if req.Platform == "" {
		req.Platform = enclave.PlatformTDX
	}

	tok, err := s.proxy.IssueEnclaveAttestationToken(
		req.Platform,
		req.Measurement,
		req.RTMR0,
		req.SVN,
		req.Debug,
		req.Nonce,
		req.PubKeyHex,
		req.TTLSeconds,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": tok,
	})
}

type tokenVerifyReq struct {
	TokenID    string                    `json:"token_id,omitempty"`
	Token      *enclave.AttestationToken `json:"token,omitempty"`
	MinSVN     uint32                    `json:"min_svn,omitempty"`
	AllowDebug bool                      `json:"allow_debug,omitempty"`
}

func (s *AppServer) handleEnclaveTokenVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tokenVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	targetToken := req.Token
	if targetToken == nil && req.TokenID != "" && s.proxy.EnclaveManager() != nil && s.proxy.EnclaveManager().TokenManager() != nil {
		targetToken, _ = s.proxy.EnclaveManager().TokenManager().GetToken(req.TokenID)
	}

	if targetToken == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"valid": false,
			"error": "token not found",
		})
		return
	}

	res, err := s.proxy.VerifyEnclaveAttestationToken(targetToken, req.MinSVN, req.AllowDebug)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":  true,
		"result": res,
	})
}

type isolatedDecryptReq struct {
	Platform            enclave.PlatformType      `json:"platform"`
	TokenID             string                    `json:"token_id,omitempty"`
	Token               *enclave.AttestationToken `json:"token,omitempty"`
	EncryptedPayloadHex string                    `json:"encrypted_payload_hex"`
	NonceHex            string                    `json:"nonce_hex"`
	SessionKeyHex       string                    `json:"session_key_hex"`
}

func (s *AppServer) handleEnclaveIsolatedDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req isolatedDecryptReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	targetToken := req.Token
	if targetToken == nil && req.TokenID != "" && s.proxy.EnclaveManager() != nil && s.proxy.EnclaveManager().TokenManager() != nil {
		targetToken, _ = s.proxy.EnclaveManager().TokenManager().GetToken(req.TokenID)
	}

	if targetToken == nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "attestation token required for isolated decryption",
		})
		return
	}

	sessionKey, err := hex.DecodeString(strings.TrimSpace(req.SessionKeyHex))
	if err != nil || len(sessionKey) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Session key must be 32-byte hex for AES-256-GCM"})
		return
	}

	decReq := &enclave.IsolatedDecryptionRequest{
		Platform:            req.Platform,
		EnclaveToken:        targetToken.TokenID,
		EncryptedPayloadHex: req.EncryptedPayloadHex,
		NonceHex:            req.NonceHex,
	}

	res, err := s.proxy.ExecuteIsolatedLicenseDecryption(r.Context(), decReq, sessionKey, targetToken)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"result": res,
	})
}
