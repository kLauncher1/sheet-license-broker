package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/healing"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func newTestHealingServer(t *testing.T) *AppServer {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:  true,
		GlobalSecret: "test-routes-healing-secret",
	})
	if err != nil {
		t.Fatalf("Failed to init proxy: %v", err)
	}
	secGuard := security.NewGuard([]byte("test-routes-healing-secret"), 0, false)
	return &AppServer{proxy: px, guard: secGuard}
}

func TestRoutesHealingLifecycle(t *testing.T) {
	server := newTestHealingServer(t)
	apiMux := http.NewServeMux()
	server.registerHealingRoutes(apiMux)

	// 1. GET /api/healing/status
	req := httptest.NewRequest(http.MethodGet, "/api/healing/status", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /api/healing/status, got %d: %s", w.Code, w.Body.String())
	}

	var status healing.HealingStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to parse status response: %v", err)
	}
	if status.Bucket.Capacity <= 0 {
		t.Fatalf("Expected valid bucket capacity, got %f", status.Bucket.Capacity)
	}

	// 2. POST /api/healing/bucket/consume
	body, _ := json.Marshal(map[string]interface{}{"tokens": 2.0})
	req = httptest.NewRequest(http.MethodPost, "/api/healing/bucket/consume", bytes.NewReader(body))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /api/healing/bucket/consume, got %d: %s", w.Code, w.Body.String())
	}

	// 3. POST /api/healing/tunnel/ticket
	body, _ = json.Marshal(map[string]interface{}{
		"session_id":   "routes-test-sess",
		"client_id":    "routes-client-1",
		"hwid":         "HWID-ROUTES-1",
		"tenant_id":    "tenant-primary",
		"last_ack_seq": 0,
		"ttl_seconds":  120,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/healing/tunnel/ticket", bytes.NewReader(body))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /api/healing/tunnel/ticket, got %d: %s", w.Code, w.Body.String())
	}

	var ticket healing.HealingTicket
	if err := json.NewDecoder(w.Body).Decode(&ticket); err != nil {
		t.Fatalf("Failed to decode ticket: %v", err)
	}
	if ticket.Signature == "" {
		t.Fatalf("Expected non-empty ticket signature")
	}

	// 4. POST /api/healing/tunnel/resume
	body, _ = json.Marshal(ticket)
	req = httptest.NewRequest(http.MethodPost, "/api/healing/tunnel/resume", bytes.NewReader(body))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /api/healing/tunnel/resume, got %d: %s", w.Code, w.Body.String())
	}

	// 5. POST /api/healing/quota/borrow
	body, _ = json.Marshal(map[string]interface{}{
		"borrower_tenant":  "tenant-secondary",
		"lender_tenant":    "tenant-primary",
		"amount":           300,
		"duration_minutes": 10,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/healing/quota/borrow", bytes.NewReader(body))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /api/healing/quota/borrow, got %d: %s", w.Code, w.Body.String())
	}

	var borrowResp struct {
		Status string             `json:"status"`
		Lease  healing.QuotaLease `json:"lease"`
	}
	if err := json.NewDecoder(w.Body).Decode(&borrowResp); err != nil {
		t.Fatalf("Failed to decode borrow response: %v", err)
	}
	leaseID := borrowResp.Lease.LeaseID
	if leaseID == "" || borrowResp.Lease.Amount != 300 {
		t.Fatalf("Unexpected borrow lease: %+v", borrowResp.Lease)
	}

	// 6. POST /api/healing/quota/return
	body, _ = json.Marshal(map[string]interface{}{
		"lease_id": leaseID,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/healing/quota/return", bytes.NewReader(body))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /api/healing/quota/return, got %d: %s", w.Code, w.Body.String())
	}

	// 7. POST /api/healing/quota/rebalance
	req = httptest.NewRequest(http.MethodPost, "/api/healing/quota/rebalance", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /api/healing/quota/rebalance, got %d: %s", w.Code, w.Body.String())
	}
}
