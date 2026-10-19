package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func setupTestSecurityServer(t *testing.T) (*AppServer, *http.ServeMux) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}
	secGuard := security.NewGuard([]byte(""), 5*time.Minute, false)
	srv := &AppServer{proxy: px, guard: secGuard}

	apiMux := http.NewServeMux()
	srv.registerSecurityRoutes(apiMux)
	apiMux.HandleFunc("/api/test/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "pong"})
	})

	rootMux := http.NewServeMux()
	rootMux.Handle("/api/", srv.securityRateLimitMiddleware(srv.guard.Middleware(apiMux)))

	return srv, rootMux
}

func TestSecurityRateLimitStatusEndpoint(t *testing.T) {
	_, mux := setupTestSecurityServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/security/ratelimit/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var res map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res["status"] != "success" || res["stats"] == nil {
		t.Fatalf("expected success with stats, got: %+v", res)
	}
}

func TestSecurityReputationAndBansLifecycle(t *testing.T) {
	_, mux := setupTestSecurityServer(t)

	// 1. Check initial reputation status
	req1 := httptest.NewRequest(http.MethodGet, "/api/security/reputation", nil)
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec1.Code)
	}

	// 2. Impose a manual ban
	banPayload, _ := json.Marshal(map[string]interface{}{
		"key":              "198.51.100.99",
		"reason":           "credential stuffing",
		"duration_minutes": 10,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/security/bans", bytes.NewReader(banPayload))
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 on manual ban, got %d", rec2.Code)
	}

	// 3. Verify request from banned IP is rejected with 429
	reqBanned := httptest.NewRequest(http.MethodGet, "/api/test/ping", nil)
	reqBanned.RemoteAddr = "198.51.100.99:54321"
	recBanned := httptest.NewRecorder()
	mux.ServeHTTP(recBanned, reqBanned)
	if recBanned.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for banned IP, got %d", recBanned.Code)
	}

	// 4. List active bans
	reqList := httptest.NewRequest(http.MethodGet, "/api/security/bans", nil)
	recList := httptest.NewRecorder()
	mux.ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 on list bans, got %d", recList.Code)
	}

	// 5. Unban IP
	unbanPayload, _ := json.Marshal(map[string]string{"key": "198.51.100.99"})
	reqUnban := httptest.NewRequest(http.MethodPost, "/api/security/bans/unban", bytes.NewReader(unbanPayload))
	recUnban := httptest.NewRecorder()
	mux.ServeHTTP(recUnban, reqUnban)
	if recUnban.Code != http.StatusOK {
		t.Fatalf("expected 200 on unban, got %d", recUnban.Code)
	}

	// 6. Verify request from unbanned IP now succeeds
	reqAllowed := httptest.NewRequest(http.MethodGet, "/api/test/ping", nil)
	reqAllowed.RemoteAddr = "198.51.100.99:54321"
	recAllowed := httptest.NewRecorder()
	mux.ServeHTTP(recAllowed, reqAllowed)
	if recAllowed.Code != http.StatusOK {
		t.Fatalf("expected 200 after unban, got %d", recAllowed.Code)
	}
}

func TestSecurityAuditExportAndVerifyEndpoints(t *testing.T) {
	srv, mux := setupTestSecurityServer(t)

	// Seed audit records
	srv.proxy.RecordAuditEvent(audit.AuditRecord{
		EventType: "AUTH_FAILURE",
		Severity:  "WARNING",
		ActorIP:   "203.0.113.8",
		Details:   "incorrect password",
	})
	srv.proxy.RecordAuditEvent(audit.AuditRecord{
		EventType: "LICENSE_VALIDATED",
		Severity:  "INFO",
		ActorIP:   "203.0.113.8",
		Details:   "license valid",
	})

	// 1. Query audit records
	reqRec := httptest.NewRequest(http.MethodGet, "/api/security/audit/records?limit=10", nil)
	recRec := httptest.NewRecorder()
	mux.ServeHTTP(recRec, reqRec)
	if recRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recRec.Code)
	}

	// 2. Export encrypted audit bundle
	auditSecret := "custom-audit-export-passkey-123"
	exportBody, _ := json.Marshal(map[string]interface{}{
		"secret_key": auditSecret,
		"limit":      50,
	})
	reqExp := httptest.NewRequest(http.MethodPost, "/api/security/audit/export", bytes.NewReader(exportBody))
	recExp := httptest.NewRecorder()
	mux.ServeHTTP(recExp, reqExp)
	if recExp.Code != http.StatusOK {
		t.Fatalf("expected 200 on audit export, got %d: %s", recExp.Code, recExp.Body.String())
	}

	var expRes struct {
		Status string                      `json:"status"`
		Bundle *audit.EncryptedAuditBundle `json:"bundle"`
	}
	if err := json.NewDecoder(recExp.Body).Decode(&expRes); err != nil {
		t.Fatalf("failed to decode export bundle: %v", err)
	}
	if expRes.Bundle == nil || expRes.Bundle.CiphertextHex == "" {
		t.Fatalf("exported bundle is empty or invalid")
	}

	// 3. Verify and decrypt audit bundle
	verifyBody, _ := json.Marshal(map[string]interface{}{
		"bundle":     expRes.Bundle,
		"secret_key": auditSecret,
	})
	reqVer := httptest.NewRequest(http.MethodPost, "/api/security/audit/verify", bytes.NewReader(verifyBody))
	recVer := httptest.NewRecorder()
	mux.ServeHTTP(recVer, reqVer)
	if recVer.Code != http.StatusOK {
		t.Fatalf("expected 200 on verify, got %d: %s", recVer.Code, recVer.Body.String())
	}

	var verRes struct {
		Status      string              `json:"status"`
		Verified    bool                `json:"verified"`
		RecordCount int                 `json:"record_count"`
		Records     []audit.AuditRecord `json:"records"`
	}
	if err := json.NewDecoder(recVer.Body).Decode(&verRes); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}
	if !verRes.Verified || verRes.RecordCount < 2 {
		t.Fatalf("expected verified=true and record_count >= 2, got: %+v", verRes)
	}
}
