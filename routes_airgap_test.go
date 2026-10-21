package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/airgap"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func setupTestAppServerForAirgap(t *testing.T) (*AppServer, *http.ServeMux) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("Failed to init proxy: %v", err)
	}

	secGuard := security.NewGuard([]byte("test-secret"), 5*time.Minute, false)
	server := &AppServer{proxy: px, guard: secGuard}

	apiMux := http.NewServeMux()
	server.registerAirgapRoutes(apiMux)
	return server, apiMux
}

func TestRoutesAirgapLifecycle(t *testing.T) {
	server, mux := setupTestAppServerForAirgap(t)
	defer server.proxy.Close()

	// 1. GET /api/airgap/status
	req := httptest.NewRequest(http.MethodGet, "/api/airgap/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/airgap/status, got %d", rec.Code)
	}

	var statusRes map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&statusRes); err != nil {
		t.Fatalf("Decode status response failed: %v", err)
	}
	if statusRes["status"] != "success" || statusRes["vault_active"] != true {
		t.Fatalf("Unexpected status payload: %+v", statusRes)
	}

	// 2. POST /api/airgap/token/issue
	issueBody, _ := json.Marshal(airgap.IssueTokenRequest{
		LicenseKey: "LIC-AIRGAP-ROUTE-1",
		HWID:       "HWID-ROUTE-NODE",
		Tier:       "enterprise",
		DaysValid:  30,
		MaxDevices: 1,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/airgap/token/issue", bytes.NewReader(issueBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/airgap/token/issue, got %d: %s", rec.Code, rec.Body.String())
	}

	var issueRes struct {
		Status      string              `json:"status"`
		Token       *airgap.DongleToken `json:"token"`
		DongleToken string              `json:"dongle_token"`
		QRPayload   string              `json:"qr_payload"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&issueRes); err != nil {
		t.Fatalf("Decode issue response failed: %v", err)
	}
	if issueRes.DongleToken == "" || issueRes.QRPayload == "" {
		t.Fatalf("Expected dongle token and qr payload to be returned")
	}

	// 3. POST /api/airgap/token/verify
	verifyBody, _ := json.Marshal(map[string]interface{}{
		"token":     issueRes.DongleToken,
		"hwid":      "HWID-ROUTE-NODE",
		"timestamp": time.Now().Unix(),
	})
	req = httptest.NewRequest(http.MethodPost, "/api/airgap/token/verify", bytes.NewReader(verifyBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/airgap/token/verify, got %d: %s", rec.Code, rec.Body.String())
	}

	// 4. POST /api/airgap/activate/request
	actBody, _ := json.Marshal(airgap.ActivationRequest{
		LicenseKey: "LIC-ACT-ROUTE-01",
		HWID:       "HWID-OFFLINE-BOX",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/airgap/activate/request", bytes.NewReader(actBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/airgap/activate/request, got %d: %s", rec.Code, rec.Body.String())
	}

	var actRes struct {
		Status     string                     `json:"status"`
		Activation *airgap.ActivationResponse `json:"activation"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&actRes); err != nil {
		t.Fatalf("Decode activation response failed: %v", err)
	}
	if actRes.Activation.QRPayload == "" {
		t.Fatalf("Expected activation QR payload to be present")
	}

	// 5. POST /api/airgap/activate/fulfill
	fulfillBody, _ := json.Marshal(map[string]string{
		"qr_payload": actRes.Activation.QRPayload,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/airgap/activate/fulfill", bytes.NewReader(fulfillBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/airgap/activate/fulfill, got %d: %s", rec.Code, rec.Body.String())
	}

	// 6. GET /api/airgap/rollback/state?hwid=HWID-ROUTE-NODE
	req = httptest.NewRequest(http.MethodGet, "/api/airgap/rollback/state?hwid=HWID-ROUTE-NODE", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/airgap/rollback/state, got %d", rec.Code)
	}

	// 7. POST /api/airgap/rollback/unlock (admin unlock recovery)
	now := time.Now().Unix()
	adminToken, err := server.proxy.AirGapManager().GenerateAdminUnlockToken("VAULT-HWID-ROUTE-NODE", "HWID-ROUTE-NODE", "ROUTE-NONCE-1", now+100)
	if err != nil {
		t.Fatalf("Failed to generate admin unlock token: %v", err)
	}

	unlockBody, _ := json.Marshal(airgap.UnlockRequest{
		VaultID:        adminToken.VaultID,
		HWID:           adminToken.HWID,
		Nonce:          adminToken.Nonce,
		Timestamp:      adminToken.Timestamp,
		AdminSignature: adminToken.AdminSignature,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/airgap/rollback/unlock", bytes.NewReader(unlockBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/airgap/rollback/unlock, got %d: %s", rec.Code, rec.Body.String())
	}
}
