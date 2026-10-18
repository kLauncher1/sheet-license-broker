package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/zkp"
)

// handleZKPParams serves the public curve generators and issuer public key.
func (s *AppServer) handleZKPParams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, cp := zkp.GetCurve()
	pubKey := s.proxy.ZKPVerifier().IssuerPublicKey()

	var pubX, pubY string
	if pubKey != nil {
		if pubKey.X != nil {
			pubX = pubKey.X.Text(16)
		}
		if pubKey.Y != nil {
			pubY = pubKey.Y.Text(16)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"curve":  "P-256",
		"generator_g": map[string]string{
			"x": cp.Gx.Text(16),
			"y": cp.Gy.Text(16),
		},
		"generator_h": map[string]string{
			"x": cp.Hx.Text(16),
			"y": cp.Hy.Text(16),
		},
		"order_n": cp.N.Text(16),
		"issuer_public_key": map[string]string{
			"x":   pubX,
			"y":   pubY,
			"hex": s.proxy.ZKPVerifier().IssuerPublicKeyHex(),
		},
	})
}

// handleZKPIssueCredential issues an anonymous entitlement credential for an authenticated license.
func (s *AppServer) handleZKPIssueCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey     string                 `json:"license_key"`
		HWID           string                 `json:"hwid"`
		HWIDCommitment *zkp.PedersenCommitment `json:"hwid_commitment"`
		Tier           string                 `json:"tier"`
		ValidDays      int                    `json:"valid_days"`
		Scope          string                 `json:"scope"`
		TenantID       string                 `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	licKey := strings.TrimSpace(req.LicenseKey)
	if licKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key is required"})
		return
	}

	targetTenant := strings.TrimSpace(req.TenantID)
	if targetTenant == "" {
		targetTenant = s.proxy.TenantManager().ResolveFromRequest(r).ID
	}

	cred, rScalar, err := s.proxy.IssueAnonymousCredential(
		r.Context(),
		licKey,
		req.HWIDCommitment,
		strings.TrimSpace(req.HWID),
		req.Tier,
		req.ValidDays,
		req.Scope,
		targetTenant,
	)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	resp := map[string]interface{}{
		"status":     "success",
		"credential": cred,
	}
	if rScalar != nil {
		resp["blinding_factor"] = rScalar.Text(16)
	}

	writeJSON(w, http.StatusCreated, resp)
}

// handleZKPVerify checks a zero-knowledge presentation proof.
func (s *AppServer) handleZKPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Proof        *zkp.ZKPProof `json:"proof"`
		RequiredTier string        `json:"required_tier"`
		Epoch        int64         `json:"epoch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if req.Proof == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "proof object is required"})
		return
	}

	if req.Epoch <= 0 {
		req.Epoch = time.Now().UTC().Unix() / 3600
	}

	res := s.proxy.VerifyZKPProof(r.Context(), req.Proof, req.RequiredTier, req.Epoch)
	if !res.Valid {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"status":  "rejected",
			"valid":   false,
			"reason":  res.Reason,
			"details": res,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"valid":   true,
		"details": res,
	})
}

// handleZKPNullifierCheck reports whether a nullifier has already been recorded.
func (s *AppServer) handleZKPNullifierCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Nullifier string `json:"nullifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	nullifier := strings.TrimSpace(req.Nullifier)
	if nullifier == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nullifier is required"})
		return
	}

	spent, epoch := s.proxy.CheckNullifier(nullifier)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"nullifier": nullifier,
		"spent":     spent,
		"epoch":     epoch,
	})
}

// handleZKPStatus returns overall telemetry on zero-knowledge verifications.
func (s *AppServer) handleZKPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := s.proxy.GetZKPStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"zkp":    status,
	})
}

// registerZKPRoutes registers zero-knowledge proof endpoints onto the API multiplexer.
func (s *AppServer) registerZKPRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/zkp/params", s.handleZKPParams)
	apiMux.HandleFunc("/api/zkp/credential/issue", s.handleZKPIssueCredential)
	apiMux.HandleFunc("/api/zkp/verify", s.handleZKPVerify)
	apiMux.HandleFunc("/api/zkp/nullifiers/check", s.handleZKPNullifierCheck)
	apiMux.HandleFunc("/api/zkp/status", s.handleZKPStatus)
}
