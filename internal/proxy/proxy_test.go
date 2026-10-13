package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyLocalStandalone(t *testing.T) {
	p, err := NewProxy(ProxyConfig{
		WebAppURL:   "",
		OfflineMode: false,
		CacheTTL:    5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to initialize proxy: %v", err)
	}

	if p.IsRemoteEnabled() {
		t.Error("Expected remote to be disabled in standalone mode")
	}

	ctx := context.Background()

	// 1. Ping
	ping, err := p.Ping(ctx)
	if err != nil || ping["mode"] != "local_standalone" {
		t.Fatalf("Unexpected ping response: %+v, err: %v", ping, err)
	}

	// 2. Create and verify license
	lic, err := p.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("CreateLicense failed: %v", err)
	}
	if lic.Source != "local_fallback" {
		t.Errorf("Expected source local_fallback, got %s", lic.Source)
	}

	res, err := p.VerifyLicense(ctx, lic.LicenseKey, "HWID-TEST")
	if err != nil || !res.Valid {
		t.Fatalf("VerifyLicense failed: %v", err)
	}
	if res.HWIDBound != "HWID-TEST" {
		t.Errorf("Expected HWID-TEST, got %s", res.HWIDBound)
	}

	// 3. User Register & Login
	u, err := p.RegisterUser(ctx, "admin1", "secret123", "admin")
	if err != nil || u.Username != "admin1" {
		t.Fatalf("RegisterUser failed: %v", err)
	}

	authU, err := p.AuthenticateUser(ctx, "admin1", "secret123")
	if err != nil || authU.Username != "admin1" {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}

	// 4. Put & Get Document
	doc, err := p.PutDocument(ctx, "configs", "app", `{"theme":"dark"}`)
	if err != nil || doc.DocID != "app" {
		t.Fatalf("PutDocument failed: %v", err)
	}

	getDoc, err := p.GetDocument(ctx, "configs", "app")
	if err != nil || getDoc.Payload != `{"theme":"dark"}` {
		t.Fatalf("GetDocument failed: %v", err)
	}
}

func TestProxyRemoteWithCacheAndFallback(t *testing.T) {
	// Mock GAS Web App
	gasServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		action, _ := payload["action"].(string)

		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "ping":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "success",
				"message":   "Remote GAS ready",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		case "verify_license":
			key, _ := payload["license_key"].(string)
			hwid, _ := payload["hwid"].(string)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "success",
				"verified":   true,
				"license_key": key,
				"hwid_bound":  hwid,
				"expires_at":  time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"message":     "Validated by remote sheet",
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success"})
		}
	}))
	defer gasServer.Close()

	p, err := NewProxy(ProxyConfig{
		WebAppURL:   gasServer.URL,
		OfflineMode: false,
		CacheTTL:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to initialize proxy: %v", err)
	}

	if !p.IsRemoteEnabled() {
		t.Fatal("Expected remote to be enabled")
	}

	ctx := context.Background()

	// 1. Verify license via remote GAS
	v1, err := p.VerifyLicense(ctx, "KEY-REMOTE-01", "HWID-REMOTE")
	if err != nil || !v1.Valid || v1.Source != "remote_gas" {
		t.Fatalf("Expected remote_gas verification, got: %+v, err: %v", v1, err)
	}

	// 2. Second verify should hit local cache immediately
	v2, err := p.VerifyLicense(ctx, "KEY-REMOTE-01", "HWID-REMOTE")
	if err != nil || !v2.Valid || v2.Source != "cache" {
		t.Fatalf("Expected cache hit, got: %+v, err: %v", v2, err)
	}

	// 3. Status inspection
	status := p.Status()
	if status["mode"] != "remote_gas_proxy" || status["cache_entries"].(int) < 1 {
		t.Fatalf("Unexpected status: %+v", status)
	}
}
