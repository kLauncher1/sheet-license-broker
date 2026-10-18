package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/zkp"
)

func TestZKPParamsEndpoint(t *testing.T) {
	server, err := newAppServer()
	if err != nil {
		t.Fatalf("Failed to initialize server: %v", err)
	}
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerZKPRoutes(apiMux)

	req := httptest.NewRequest(http.MethodGet, "/api/zkp/params", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if resp["curve"] != "P-256" {
		t.Errorf("Expected curve 'P-256', got '%v'", resp["curve"])
	}
	if resp["generator_g"] == nil || resp["generator_h"] == nil {
		t.Errorf("Expected generator_g and generator_h in params response")
	}
}

func TestZKPIssueAndVerifyWorkflow(t *testing.T) {
	server, err := newAppServer()
	if err != nil {
		t.Fatalf("Failed to initialize server: %v", err)
	}
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerZKPRoutes(apiMux)

	// Pre-seed a license
	ctx := context.Background()
	lic, err := server.proxy.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	hwid := "HWID-TEST-ZKP-DEVICE-01"

	// 1. Issue anonymous credential
	issueReqBody, _ := json.Marshal(map[string]interface{}{
		"license_key": lic.LicenseKey,
		"hwid":        hwid,
		"tier":        "pro",
		"valid_days":  30,
		"scope":       "production",
		"tenant_id":   "default",
	})
	issueReq := httptest.NewRequest(http.MethodPost, "/api/zkp/credential/issue", bytes.NewReader(issueReqBody))
	issueReq.Header.Set("Content-Type", "application/json")
	issueW := httptest.NewRecorder()
	apiMux.ServeHTTP(issueW, issueReq)

	if issueW.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created for issue credential, got %d: %s", issueW.Code, issueW.Body.String())
	}

	var issueResp struct {
		Status         string                   `json:"status"`
		Credential     *zkp.AnonymousCredential `json:"credential"`
		BlindingFactor string                   `json:"blinding_factor"`
	}
	if err := json.Unmarshal(issueW.Body.Bytes(), &issueResp); err != nil {
		t.Fatalf("Failed to unmarshal issue response: %v", err)
	}

	if issueResp.Credential == nil || issueResp.BlindingFactor == "" {
		t.Fatalf("Expected credential and blinding_factor, got nil")
	}

	rScalar, ok := new(big.Int).SetString(issueResp.BlindingFactor, 16)
	if !ok {
		t.Fatalf("Failed to parse blinding factor as hex big.Int")
	}

	// 2. Generate ZKP Presentation Proof
	epoch := time.Now().Unix() / 3600
	proof, err := zkp.GenerateZKPProof(hwid, rScalar, issueResp.Credential, epoch, "default")
	if err != nil {
		t.Fatalf("Failed to generate ZKP presentation proof: %v", err)
	}

	// 3. Verify ZKP Presentation Proof
	verifyReqBody, _ := json.Marshal(map[string]interface{}{
		"proof":         proof,
		"required_tier": "pro",
		"epoch":         epoch,
	})
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/zkp/verify", bytes.NewReader(verifyReqBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyW := httptest.NewRecorder()
	apiMux.ServeHTTP(verifyW, verifyReq)

	if verifyW.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid proof verification, got %d: %s", verifyW.Code, verifyW.Body.String())
	}

	var verifyResp struct {
		Status  string                  `json:"status"`
		Valid   bool                    `json:"valid"`
		Details *zkp.VerificationResult `json:"details"`
	}
	if err := json.Unmarshal(verifyW.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("Failed to unmarshal verify response: %v", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("Expected valid proof, got false")
	}

	// 4. Duplicate proof presentation should be rejected (Nullifier spent)
	verifyReq2 := httptest.NewRequest(http.MethodPost, "/api/zkp/verify", bytes.NewReader(verifyReqBody))
	verifyReq2.Header.Set("Content-Type", "application/json")
	verifyW2 := httptest.NewRecorder()
	apiMux.ServeHTTP(verifyW2, verifyReq2)

	if verifyW2.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for replay proof presentation, got %d", verifyW2.Code)
	}

	// 5. Query nullifier status
	nullReqBody, _ := json.Marshal(map[string]string{"nullifier": proof.Nullifier})
	nullReq := httptest.NewRequest(http.MethodPost, "/api/zkp/nullifiers/check", bytes.NewReader(nullReqBody))
	nullReq.Header.Set("Content-Type", "application/json")
	nullW := httptest.NewRecorder()
	apiMux.ServeHTTP(nullW, nullReq)

	if nullW.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for nullifier check, got %d", nullW.Code)
	}
	var nullResp struct {
		Nullifier string `json:"nullifier"`
		Spent     bool   `json:"spent"`
		Epoch     int64  `json:"epoch"`
	}
	if err := json.Unmarshal(nullW.Body.Bytes(), &nullResp); err != nil {
		t.Fatalf("Failed to unmarshal nullifier response: %v", err)
	}
	if !nullResp.Spent {
		t.Errorf("Expected nullifier to be marked as spent")
	}

	// 6. Check ZKP telemetry status
	statusReq := httptest.NewRequest(http.MethodGet, "/api/zkp/status", nil)
	statusW := httptest.NewRecorder()
	apiMux.ServeHTTP(statusW, statusReq)

	if statusW.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for status, got %d", statusW.Code)
	}
}
