package proxy

import (
	"context"
	"testing"
	"time"
)

func TestProxyFeatureCheckAndTiers(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()

	// 1. Create a Pro license
	licRes, err := px.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("failed to create license: %v", err)
	}
	key := licRes.LicenseKey

	// Check standard Pro features
	enabled, tier, err := px.CheckFeature(ctx, key, "analytics")
	if err != nil || !enabled || tier != "pro" {
		t.Errorf("expected analytics enabled on pro tier; got enabled=%v, tier=%s, err=%v", enabled, tier, err)
	}

	// Check Enterprise feature (should be disabled by default on Pro)
	enabled, _, err = px.CheckFeature(ctx, key, "sso")
	if err != nil || enabled {
		t.Errorf("expected sso disabled on pro tier; got enabled=%v", enabled)
	}

	// 2. Upgrade license to Enterprise
	px.SetLicenseFeatures(key, "enterprise", nil)
	enabled, tier, err = px.CheckFeature(ctx, key, "sso")
	if err != nil || !enabled || tier != "enterprise" {
		t.Errorf("expected sso enabled after upgrading to enterprise; got enabled=%v, tier=%s", enabled, tier)
	}

	// 3. Add custom feature tag
	px.SetLicenseFeatures(key, "free", []string{"custom_beta_tool"})
	enabled, _, _ = px.CheckFeature(ctx, key, "custom_beta_tool")
	if !enabled {
		t.Errorf("expected custom_beta_tool to be enabled")
	}
}

func TestProxyUsageRecordingAndQuota(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()
	key := "KEY-USAGE-TEST"
	metric := "api_calls"
	period := time.Now().UTC().Format("2006-01-02")

	// Consume 100 units with quota 250
	rec, exceeded, err := px.RecordUsage(ctx, key, metric, period, 100, 250)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Count != 100 || exceeded {
		t.Errorf("expected count 100, exceeded false; got count %d, exceeded %v", rec.Count, exceeded)
	}

	// Consume 160 more units -> total 260 > limit 250
	rec, exceeded, err = px.RecordUsage(ctx, key, metric, period, 160, 250)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Count != 260 || !exceeded {
		t.Errorf("expected count 260, exceeded true; got count %d, exceeded %v", rec.Count, exceeded)
	}

	// Query usage
	records, err := px.GetUsage(ctx, key)
	if err != nil || len(records) != 1 {
		t.Fatalf("expected 1 usage record; got %d, err: %v", len(records), err)
	}
	if records[0].Count != 260 {
		t.Errorf("expected count 260, got %d", records[0].Count)
	}
}
