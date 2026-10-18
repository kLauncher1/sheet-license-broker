package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrometheusMetricsEndpoint(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /metrics, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("unexpected content type: %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "process_uptime_seconds") {
		t.Errorf("expected process_uptime_seconds in Prometheus output")
	}
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("expected go_goroutines in Prometheus output")
	}
}

func TestHAStatusAndReconcileEndpoints(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	// 1. GET /api/ha/status
	req := httptest.NewRequest(http.MethodGet, "/api/ha/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/ha/status, got %d", w.Code)
	}

	var statusRes map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &statusRes); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if statusRes["active_role"] != "primary_only" {
		t.Errorf("expected active_role 'primary_only', got %v", statusRes["active_role"])
	}

	// 2. POST /api/ha/reconcile
	recReq := httptest.NewRequest(http.MethodPost, "/api/ha/reconcile", nil)
	recW := httptest.NewRecorder()
	handler.ServeHTTP(recW, recReq)

	if recW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/ha/reconcile, got %d: %s", recW.Code, recW.Body.String())
	}

	var recRes map[string]interface{}
	if err := json.Unmarshal(recW.Body.Bytes(), &recRes); err != nil {
		t.Fatalf("failed to decode reconcile response: %v", err)
	}
	if recRes["status"] != "success" {
		t.Errorf("expected status 'success', got %v", recRes["status"])
	}
}

func TestHASpoolDrainEndpoint(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/ha/spool/drain", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/ha/spool/drain, got %d: %s", w.Code, w.Body.String())
	}

	var res map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res["status"] != "success" {
		t.Errorf("expected status 'success', got %v", res["status"])
	}
}

func TestAlertsTestEndpoint(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	payload := `{"type":"tamper_detected","severity":"WARNING","summary":"Unit test alert check"}`
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/test", bytes.NewBufferString(payload))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/alerts/test, got %d: %s", w.Code, w.Body.String())
	}

	var res map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res["status"] != "success" {
		t.Errorf("expected success, got %v", res["status"])
	}
}
