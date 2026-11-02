package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/failover"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func newTestAppServerWithFailover(t *testing.T) *AppServer {
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}
	secGuard := security.NewGuard([]byte("test-secret"), 5*time.Minute, false)
	return &AppServer{proxy: px, guard: secGuard}
}

func TestRoutesFailoverStatusAndProviders(t *testing.T) {
	server := newTestAppServerWithFailover(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerFailoverRoutes(apiMux)

	// GET /api/multicloud/status
	req := httptest.NewRequest(http.MethodGet, "/api/multicloud/status", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var status failover.MultiCloudStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse status json: %v", err)
	}
	if status.TotalProviders != 3 {
		t.Errorf("expected 3 total providers, got %d", status.TotalProviders)
	}

	// GET /api/multicloud/providers
	req = httptest.NewRequest(http.MethodGet, "/api/multicloud/providers", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on providers, got %d", w.Code)
	}
	var provResp struct {
		Providers []failover.CloudProvider `json:"providers"`
		Count     int                      `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &provResp); err != nil {
		t.Fatalf("failed to parse providers json: %v", err)
	}
	if provResp.Count != 3 {
		t.Errorf("expected 3 providers, got %d", provResp.Count)
	}
}

func TestRoutesFailoverRoute(t *testing.T) {
	server := newTestAppServerWithFailover(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerFailoverRoutes(apiMux)

	routePayload := []byte(`{"client_region":"ap-northeast","client_ip":"203.0.113.88"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/multicloud/route", bytes.NewReader(routePayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Provider failover.CloudProvider         `json:"provider"`
		Token    failover.MultiCloudRoutingToken `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse route json: %v", err)
	}
	if resp.Provider.ID == "" || resp.Token.Signature == "" {
		t.Fatalf("expected non-empty provider ID and token signature")
	}
}

func TestRoutesFailoverProbe(t *testing.T) {
	server := newTestAppServerWithFailover(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerFailoverRoutes(apiMux)

	probePayload := []byte(`{
		"provider_id": "fastly",
		"success": true,
		"latency_ms": 29.5,
		"status_code": 200,
		"origin_region": "us-west"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/multicloud/probe", bytes.NewReader(probePayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRoutesFailoverSyncAndAck(t *testing.T) {
	server := newTestAppServerWithFailover(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerFailoverRoutes(apiMux)

	// 1. Submit sync delta
	deltaPayload := []byte(`{
		"origin_provider": "cloudflare",
		"action": "quota_deduct",
		"payload": {"tenant_id":"acme-corp","seats":2}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/multicloud/sync/delta", bytes.NewReader(deltaPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	var deltaResp struct {
		Success bool                `json:"success"`
		Delta   failover.SyncDelta  `json:"delta"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &deltaResp); err != nil {
		t.Fatalf("failed to unmarshal delta response: %v", err)
	}
	deltaID := deltaResp.Delta.DeltaID

	// 2. Query pending deltas for fastly
	req = httptest.NewRequest(http.MethodGet, "/api/multicloud/sync/pending?provider_id=fastly", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on pending, got %d: %s", w.Code, w.Body.String())
	}
	var pendingResp struct {
		ProviderID string                `json:"provider_id"`
		Pending    []failover.SyncDelta  `json:"pending"`
		Count      int                   `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("failed to parse pending json: %v", err)
	}
	if pendingResp.Count != 1 {
		t.Errorf("expected 1 pending delta, got %d", pendingResp.Count)
	}

	// 3. Acknowledge sync
	ackPayload, _ := json.Marshal(map[string]interface{}{
		"provider_id": "fastly",
		"delta_id":    deltaID,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/multicloud/sync/acknowledge", bytes.NewReader(ackPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on ack, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRoutesFailoverSimulate(t *testing.T) {
	server := newTestAppServerWithFailover(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerFailoverRoutes(apiMux)

	simPayload := []byte(`{"provider_id":"cloudfront","reason":"Fiber optic cut drill"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/multicloud/failover/simulate", bytes.NewReader(simPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on simulate, got %d: %s", w.Code, w.Body.String())
	}

	var simResp struct {
		Success       bool                   `json:"success"`
		FailoverEvent failover.FailoverEvent `json:"failover_event"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &simResp); err != nil {
		t.Fatalf("failed to parse simulate response: %v", err)
	}
	if simResp.FailoverEvent.PreviousProvider != "cloudfront" {
		t.Errorf("expected previous cloudfront, got %s", simResp.FailoverEvent.PreviousProvider)
	}
}
