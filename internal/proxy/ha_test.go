package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/queue"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

func TestProxyHAStatusAndLocalReconcile(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "proxy-ha-test-*")
	defer os.RemoveAll(tmpDir)

	spoolPath := filepath.Join(tmpDir, "spool.bin")

	p, err := NewProxy(ProxyConfig{
		OfflineMode: true,
		SpoolPath:   spoolPath,
		SpoolSecret: "test-spool-secret-32-bytes-long",
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	ctx := context.Background()

	// 1. Check HAStatus in standalone mode
	st := p.HAStatus(ctx)
	if st["active_role"] != "primary_only" {
		t.Errorf("expected primary_only in standalone mode, got %v", st["active_role"])
	}

	// 2. Test SpoolEvent
	pItem := &queue.SpoolItem{
		Action:   "test_action",
		TenantID: "CORP",
		Payload:  json.RawMessage(`{"key":"value"}`),
	}
	err = p.SpoolEvent(pItem)
	if err != nil {
		t.Fatalf("SpoolEvent failed: %v", err)
	}

	stAfter := p.HAStatus(ctx)
	if stAfter["spool_depth"] != 1 {
		t.Errorf("expected spool_depth 1, got %v", stAfter["spool_depth"])
	}

	// 3. Test local reconciliation
	rep, err := p.ReconcileDualSheets(ctx)
	if err != nil {
		t.Fatalf("ReconcileDualSheets failed: %v", err)
	}
	if !rep.SyncedToPrimary {
		t.Errorf("expected SyncedToPrimary to be true")
	}
}

func TestProxyDispatchSecurityIncident(t *testing.T) {
	alertReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertReceived = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	p, err := NewProxy(ProxyConfig{
		OfflineMode:   true,
		SlackAlertURL: server.URL,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	alert := webhook.SecurityAlert{
		Type:     "replay_attack",
		Severity: webhook.SeverityCritical,
		Summary:  "Replay detected in proxy test",
	}

	err = p.DispatchSecurityIncident(context.Background(), alert)
	if err != nil {
		t.Fatalf("DispatchSecurityIncident failed: %v", err)
	}
	if !alertReceived {
		t.Errorf("expected test alert receiver to receive notification")
	}
}

func TestProxyDrainSpoolWithMock(t *testing.T) {
	drainedAction := ""
	gasServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if act, ok := req["action"].(string); ok {
			drainedAction = act
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer gasServer.Close()

	tmpDir, _ := os.MkdirTemp("", "proxy-drain-test-*")
	defer os.RemoveAll(tmpDir)

	spoolPath := filepath.Join(tmpDir, "spool.bin")

	p, err := NewProxy(ProxyConfig{
		WebAppURL:   gasServer.URL,
		SpoolPath:   spoolPath,
		SpoolSecret: "test-spool-secret-32-bytes-long",
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	_ = p.SpoolEvent(&queue.SpoolItem{
		Action:   "sync_record",
		TenantID: "PROD",
		Payload:  json.RawMessage(`{"doc_id":"123"}`),
	})

	flushed, err := p.DrainSpool(context.Background())
	if err != nil {
		t.Fatalf("DrainSpool error: %v", err)
	}
	if flushed != 1 {
		t.Errorf("expected 1 flushed item, got %d", flushed)
	}
	if !strings.EqualFold(drainedAction, "sync_record") {
		t.Errorf("expected drainedAction 'sync_record', got %s", drainedAction)
	}
}
