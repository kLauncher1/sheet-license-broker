package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
	"github.com/kLauncher1/sheet-license-broker/internal/tenant"
)

func setupTestServer(t *testing.T, secret string, enforce bool) (*AppServer, http.Handler) {
	t.Helper()
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	secGuard := security.NewGuard([]byte(secret), 5*time.Minute, enforce)
	server := &AppServer{
		proxy: px,
		guard: secGuard,
	}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/health", server.handleHealth)
	apiMux.HandleFunc("/api/licenses", server.handleLicenses)
	apiMux.HandleFunc("/api/licenses/validate", server.handleValidateLicense)
	apiMux.HandleFunc("/api/licenses/revoke", server.handleRevokeLicense)
	apiMux.HandleFunc("/api/security/blacklist", server.handleBlacklist)
	apiMux.HandleFunc("/api/security/blacklist/remove", server.handleBlacklistRemove)
	apiMux.HandleFunc("/api/security/status", server.handleSecurityStatus)
	apiMux.HandleFunc("/api/tenants", server.handleTenants)
	apiMux.HandleFunc("/api/tenants/register", server.handleRegisterTenant)
	apiMux.HandleFunc("/api/backup/export", server.handleBackupExport)
	apiMux.HandleFunc("/api/backup/restore", server.handleBackupRestore)
	apiMux.HandleFunc("/api/webhooks/test", server.handleTestWebhook)

	mux := http.NewServeMux()
	mux.Handle("/api/", server.guard.Middleware(apiMux))
	server.registerHARoutes(apiMux, mux)
	server.registerFeatureRoutes(apiMux)
	server.registerAttestationRoutes(apiMux)
	server.registerConsensusRoutes(apiMux)
	server.registerStreamRoutes(apiMux, mux)
	server.registerZKPRoutes(apiMux)
	server.registerAnycastRoutes(apiMux)
	server.registerMarketplaceRoutes(apiMux, mux)

	return server, mux
}

func TestHealthAndSecurityStatus(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", w.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse health response: %v", err)
	}

	if res["version"] != "1.8.0" {
		t.Fatalf("expected version 1.8.0, got: %v", res["version"])
	}
	if res["consensus"] == nil {
		t.Fatalf("expected consensus telemetry in health response")
	}
	if res["zkp"] == nil {
		t.Fatalf("expected zkp telemetry in health response")
	}
	if res["sso"] == nil {
		t.Fatalf("expected sso telemetry in health response")
	}
	if res["pqc"] == nil {
		t.Fatalf("expected pqc telemetry in health response")
	}
	if res["anomaly"] == nil {
		t.Fatalf("expected anomaly telemetry in health response")
	}
	if res["enclave"] == nil {
		t.Fatalf("expected enclave telemetry in health response")
	}
	if res["anycast"] == nil {
		t.Fatalf("expected anycast telemetry in health response")
	}
	if res["marketplace"] == nil {
		t.Fatalf("expected marketplace telemetry in health response")
	}
}

func TestRevocationAndBlacklistEndpoints(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	// 1. Create a license
	licRes, err := server.proxy.CreateLicense(context.Background(), 30, 1)
	if err != nil {
		t.Fatalf("failed to create license: %v", err)
	}

	// 2. Validate license initially
	valBody := fmt.Sprintf(`{"license_key":"%s","hwid":"HWID-INTEG-1"}`, licRes.LicenseKey)
	req := httptest.NewRequest("POST", "/api/licenses/validate", bytes.NewBufferString(valBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected validation 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Revoke license via endpoint
	revokeBody := fmt.Sprintf(`{"license_key":"%s","reason":"Testing chargeback"}`, licRes.LicenseKey)
	revReq := httptest.NewRequest("POST", "/api/licenses/revoke", bytes.NewBufferString(revokeBody))
	revW := httptest.NewRecorder()
	handler.ServeHTTP(revW, revReq)

	if revW.Code != http.StatusOK {
		t.Fatalf("expected revocation 200 OK, got %d: %s", revW.Code, revW.Body.String())
	}

	// 4. Validate again -> must be rejected
	req2 := httptest.NewRequest("POST", "/api/licenses/validate", bytes.NewBufferString(valBody))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after revocation, got %d: %s", w2.Code, w2.Body.String())
	}

	// 5. Blacklist a device HWID via endpoint
	blBody := `{"type":"device","target":"HWID-BAD-DEVICE","reason":"Bot farm activity"}`
	blReq := httptest.NewRequest("POST", "/api/security/blacklist", bytes.NewBufferString(blBody))
	blW := httptest.NewRecorder()
	handler.ServeHTTP(blW, blReq)

	if blW.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on blacklist add, got %d", blW.Code)
	}

	// 6. List blacklist entries
	listReq := httptest.NewRequest("GET", "/api/security/blacklist", nil)
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on blacklist list, got %d", listW.Code)
	}

	var entries []map[string]interface{}
	_ = json.Unmarshal(listW.Body.Bytes(), &entries)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 blacklist entries, got: %d", len(entries))
	}
}

func TestHMACProtectionMiddleware(t *testing.T) {
	secret := "production-hmac-secret-key-xyz"
	server, handler := setupTestServer(t, secret, true)
	defer server.proxy.Close()

	// 1. Unsigned request when enforced -> must be 401
	unReq := httptest.NewRequest("GET", "/api/security/status", nil)
	unW := httptest.NewRecorder()
	handler.ServeHTTP(unW, unReq)

	if unW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unsigned request, got: %d", unW.Code)
	}

	// 2. Properly signed request -> must be 200 OK
	ts := time.Now().Unix()
	nonce := "random-nonce-middleware-test-1"
	body := []byte{}
	sig := security.Sign([]byte(secret), "GET", "/api/security/status", ts, nonce, body)

	signedReq := httptest.NewRequest("GET", "/api/security/status", bytes.NewReader(body))
	signedReq.Header.Set(security.HeaderSignature, sig)
	signedReq.Header.Set(security.HeaderTimestamp, fmt.Sprintf("%d", ts))
	signedReq.Header.Set(security.HeaderNonce, nonce)

	signedW := httptest.NewRecorder()
	handler.ServeHTTP(signedW, signedReq)

	if signedW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid signed request, got %d: %s", signedW.Code, signedW.Body.String())
	}

	// 3. Replay with same nonce -> must be 401 Unauthorized
	replayReq := httptest.NewRequest("GET", "/api/security/status", bytes.NewReader(body))
	replayReq.Header.Set(security.HeaderSignature, sig)
	replayReq.Header.Set(security.HeaderTimestamp, fmt.Sprintf("%d", ts))
	replayReq.Header.Set(security.HeaderNonce, nonce)

	replayW := httptest.NewRecorder()
	handler.ServeHTTP(replayW, replayReq)

	if replayW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for replayed nonce, got: %d", replayW.Code)
	}

	bodyResp, _ := io.ReadAll(replayW.Body)
	if !bytes.Contains(bodyResp, []byte("replay attack detected")) {
		t.Fatalf("expected replay attack error message, got: %s", string(bodyResp))
	}
}

func TestTenantEndpoints(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	// 1. Register a tenant
	tBody := `{"id":"tenant-apex","name":"Apex Studio","namespace_prefix":"APEX","max_licenses":25}`
	req := httptest.NewRequest("POST", "/api/tenants/register", bytes.NewBufferString(tBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on tenant register, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Query tenant by ID
	getReq := httptest.NewRequest("GET", "/api/tenants?id=tenant-apex", nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on tenant query, got %d", getW.Code)
	}

	var tFound tenant.Tenant
	_ = json.Unmarshal(getW.Body.Bytes(), &tFound)
	if tFound.NamespacePrefix != "APEX" {
		t.Errorf("expected prefix APEX, got %s", tFound.NamespacePrefix)
	}

	// 3. Create a tenant-namespaced license
	licReqBody := `{"tenant_id":"tenant-apex","days":45,"max_devices":2}`
	licReq := httptest.NewRequest("POST", "/api/licenses", bytes.NewBufferString(licReqBody))
	licW := httptest.NewRecorder()
	handler.ServeHTTP(licW, licReq)

	if licW.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on license create, got %d: %s", licW.Code, licW.Body.String())
	}

	var licRes map[string]interface{}
	_ = json.Unmarshal(licW.Body.Bytes(), &licRes)
	key, _ := licRes["license_key"].(string)
	if prefix, ok := tenant.ParseLicenseKey(key); !ok || prefix != "APEX" {
		t.Errorf("expected APEX prefix on generated key, got %s", key)
	}
}

func TestBackupExportAndRestoreEndpoints(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	// Export encrypted backup
	expReq := httptest.NewRequest("POST", "/api/backup/export", bytes.NewBufferString(`{"secret_key":"test-backup-pw"}`))
	expW := httptest.NewRecorder()
	handler.ServeHTTP(expW, expReq)

	if expW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on backup export, got %d: %s", expW.Code, expW.Body.String())
	}

	var expRes map[string]interface{}
	_ = json.Unmarshal(expW.Body.Bytes(), &expRes)
	payload, ok := expRes["encrypted_payload"].(string)
	if !ok || len(payload) == 0 {
		t.Fatalf("expected encrypted_payload in export response")
	}

	// Restore backup
	restoreBody := fmt.Sprintf(`{"secret_key":"test-backup-pw","encrypted_payload":"%s"}`, payload)
	restReq := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewBufferString(restoreBody))
	restW := httptest.NewRecorder()
	handler.ServeHTTP(restW, restReq)

	if restW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on backup restore, got %d: %s", restW.Code, restW.Body.String())
	}
}

func TestWebhookTestEndpoint(t *testing.T) {
	received := false
	mockEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer mockEndpoint.Close()

	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	body := fmt.Sprintf(`{"event_type":"license.created","target_url":"%s","secret":"wh-secret"}`, mockEndpoint.URL)
	req := httptest.NewRequest("POST", "/api/webhooks/test", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on webhook probe test, got %d: %s", w.Code, w.Body.String())
	}
	if !received {
		t.Errorf("expected mock webhook endpoint to receive probe event")
	}
}
