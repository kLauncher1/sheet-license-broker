package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/license"
)

func TestProxyBlacklistLocal(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	ctx := context.Background()

	// 1. Create license and verify initial valid state
	licRes, err := px.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("CreateLicense failed: %v", err)
	}

	v1, err := px.VerifyLicense(ctx, licRes.LicenseKey, "HWID-USER-1")
	if err != nil || !v1.Valid {
		t.Fatalf("expected valid initial verification, err: %v", err)
	}

	// 2. Blacklist device
	if err := px.BlacklistDevice(ctx, "HWID-USER-1", "Unauthorized scraping detected"); err != nil {
		t.Fatalf("BlacklistDevice failed: %v", err)
	}

	// Subsequent verification with banned HWID must fail
	_, err = px.VerifyLicense(ctx, licRes.LicenseKey, "HWID-USER-1")
	if err == nil || !strings.Contains(err.Error(), "blacklisted") {
		t.Fatalf("expected blacklisted error, got: %v", err)
	}

	// 3. Revoke license
	licRes2, err := px.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("CreateLicense 2 failed: %v", err)
	}

	if err := px.RevokeLicense(ctx, licRes2.LicenseKey, "Subscription refunded"); err != nil {
		t.Fatalf("RevokeLicense failed: %v", err)
	}

	_, err = px.VerifyLicense(ctx, licRes2.LicenseKey, "HWID-CLEAN")
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked error, got: %v", err)
	}

	// 4. List blacklist entries
	entries, err := px.ListBlacklist(ctx)
	if err != nil || len(entries) < 2 {
		t.Fatalf("expected at least 2 blacklist entries, got: %d, err: %v", len(entries), err)
	}

	// 5. Remove blacklist entry
	if err := px.RemoveBlacklist(ctx, license.BlacklistTypeDevice, "HWID-USER-1"); err != nil {
		t.Fatalf("RemoveBlacklist failed: %v", err)
	}
}

func TestProxyBlacklistCacheEviction(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true, CacheTTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	ctx := context.Background()
	licRes, _ := px.CreateLicense(ctx, 30, 1)

	// Populate cache
	_, _ = px.VerifyLicense(ctx, licRes.LicenseKey, "HWID-CACHE-1")

	// Revoke license -> must evict from cache and block
	_ = px.RevokeLicense(ctx, licRes.LicenseKey, "Chargeback")

	v, err := px.VerifyLicense(ctx, licRes.LicenseKey, "HWID-CACHE-1")
	if err == nil || (v != nil && v.Valid) {
		t.Fatalf("expected verification failure after revocation, got: %v", v)
	}
}
