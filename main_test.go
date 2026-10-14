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

	mux := http.NewServeMux()
	mux.Handle("/api/", server.guard.Middleware(apiMux))

	return server, mux
}

func TestHealthAndSecurityStatus(t *testing.T) {
	_, handler := setupTestServer(t, "test-secret", false)

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

	if res["version"] != "0.3.0" {
		t.Fatalf("expected version 0.3.0, got: %v", res["version"])
	}
}

func TestRevocationAndBlacklistEndpoints(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)

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
	_, handler := setupTestServer(t, secret, true)

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
