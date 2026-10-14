package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/tenant"
)

func TestProxyTenantRegistrationAndListing(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	ctx := context.Background()

	created, err := px.RegisterTenant(ctx, &tenant.Tenant{
		ID:              "tenant-phoenix",
		Name:            "Phoenix Systems",
		NamespacePrefix: "PHX",
		HMACSecret:      "phx-secret",
		MaxLicenses:     50,
		IsActive:        true,
	})
	if err != nil {
		t.Fatalf("unexpected error registering tenant: %v", err)
	}
	if created.NamespacePrefix != "PHX" {
		t.Errorf("expected prefix PHX, got %s", created.NamespacePrefix)
	}

	found, ok := px.GetTenant("tenant-phoenix")
	if !ok || found.Name != "Phoenix Systems" {
		t.Errorf("failed to lookup tenant: %+v, ok=%v", found, ok)
	}

	list, err := px.ListTenants(ctx)
	if err != nil {
		t.Fatalf("failed to list tenants: %v", err)
	}
	if len(list) < 2 { // default + phoenix
		t.Errorf("expected at least 2 tenants, got %d", len(list))
	}
}

func TestProxyCreateTenantLicenseAndWebhook(t *testing.T) {
	var webhookDelivered int32

	whServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookDelivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer whServer.Close()

	px, err := NewProxy(ProxyConfig{
		OfflineMode:      true,
		GlobalWebhookURL: whServer.URL,
	})
	if err != nil {
		t.Fatalf("failed to initialize proxy: %v", err)
	}
	defer px.Close()

	ctx := context.Background()

	_, err = px.RegisterTenant(ctx, &tenant.Tenant{
		ID:              "tenant-cloud",
		Name:            "Cloud Works",
		NamespacePrefix: "CLD",
		WebhookURL:      whServer.URL,
		IsActive:        true,
	})
	if err != nil {
		t.Fatalf("failed to register tenant: %v", err)
	}

	res, err := px.CreateTenantLicense(ctx, "tenant-cloud", 30, 2)
	if err != nil {
		t.Fatalf("failed to create tenant license: %v", err)
	}

	prefix, isNamespaced := tenant.ParseLicenseKey(res.LicenseKey)
	if !isNamespaced || prefix != "CLD" {
		t.Errorf("expected CLD-LIC-... key format, got %s", res.LicenseKey)
	}

	// Wait for async webhook worker to deliver
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&webhookDelivered) == 0 {
		t.Errorf("expected webhook delivery to be triggered on license creation")
	}
}

func TestProxyBackupExportAndRestore(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}
	defer px.Close()

	ctx := context.Background()

	// Seed data in px
	_, _ = px.RegisterTenant(ctx, &tenant.Tenant{
		ID:              "tenant-backup",
		Name:            "Backup Corp",
		NamespacePrefix: "BCK",
		IsActive:        true,
	})
	_, _ = px.RegisterUser(ctx, "backup-user", "SecretPass123!", "admin")
	_, _ = px.CreateTenantLicense(ctx, "tenant-backup", 60, 1)
	_ = px.BlacklistDevice(ctx, "BANNED-DEVICE-X", "Suspected bot")
	_, _ = px.PutDocument(ctx, "configs", "site", `{"title":"License Hub"}`)

	secretKey := []byte("aes-256-gcm-master-backup-key-32")
	encrypted, snapshot, err := px.ExportBackup(ctx, secretKey)
	if err != nil {
		t.Fatalf("failed to export backup: %v", err)
	}
	if len(encrypted) == 0 || snapshot == nil {
		t.Fatalf("expected encrypted bytes and snapshot structure")
	}

	// Create a brand new, empty proxy
	freshPx, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init fresh proxy: %v", err)
	}
	defer freshPx.Close()

	restoredSnapshot, err := freshPx.RestoreBackup(ctx, encrypted, secretKey, nil)
	if err != nil {
		t.Fatalf("failed to restore encrypted backup on fresh proxy: %v", err)
	}
	if restoredSnapshot.Checksum != snapshot.Checksum {
		t.Errorf("restored checksum mismatch: %s != %s", restoredSnapshot.Checksum, snapshot.Checksum)
	}

	// Verify restored data in freshPx
	tFound, ok := freshPx.GetTenant("tenant-backup")
	if !ok || tFound.Name != "Backup Corp" {
		t.Errorf("tenant not restored properly: %+v", tFound)
	}

	uFound, err := freshPx.AuthenticateUser(ctx, "backup-user", "SecretPass123!")
	if err != nil || uFound.Username != "backup-user" {
		t.Errorf("user authentication failed after restore: %v", err)
	}

	doc, err := freshPx.GetDocument(ctx, "configs", "site")
	if err != nil || doc.DocID != "site" {
		t.Errorf("document not restored properly: %v", err)
	}
}
