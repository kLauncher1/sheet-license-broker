package feature

import (
	"sync"
	"testing"
)

func TestTierDefaultsAndInheritance(t *testing.T) {
	mgr := NewManager()

	// Free tier checks
	if !mgr.IsFeatureEnabled("KEY-FREE-1", "basic_license", TierFree) {
		t.Errorf("expected basic_license enabled for TierFree")
	}
	if !mgr.IsFeatureEnabled("KEY-FREE-1", "community_support", TierFree) {
		t.Errorf("expected community_support enabled for TierFree")
	}
	if mgr.IsFeatureEnabled("KEY-FREE-1", "analytics", TierFree) {
		t.Errorf("expected analytics disabled for TierFree")
	}
	if mgr.IsFeatureEnabled("KEY-FREE-1", "sso", TierFree) {
		t.Errorf("expected sso disabled for TierFree")
	}

	// Pro tier checks
	if !mgr.IsFeatureEnabled("KEY-PRO-1", "analytics", TierPro) {
		t.Errorf("expected analytics enabled for TierPro")
	}
	if !mgr.IsFeatureEnabled("KEY-PRO-1", "csv_export", TierPro) {
		t.Errorf("expected csv_export enabled for TierPro")
	}
	if mgr.IsFeatureEnabled("KEY-PRO-1", "sso", TierPro) {
		t.Errorf("expected sso disabled for TierPro")
	}

	// Enterprise tier checks
	if !mgr.IsFeatureEnabled("KEY-ENT-1", "sso", TierEnterprise) {
		t.Errorf("expected sso enabled for TierEnterprise")
	}
	if !mgr.IsFeatureEnabled("KEY-ENT-1", "audit_export", TierEnterprise) {
		t.Errorf("expected audit_export enabled for TierEnterprise")
	}
	if !mgr.IsFeatureEnabled("KEY-ENT-1", "unlimited_seats", TierEnterprise) {
		t.Errorf("expected unlimited_seats enabled for TierEnterprise")
	}
}

func TestLicenseCustomOverrides(t *testing.T) {
	mgr := NewManager()

	// Give a Free tier license an explicit custom entitlement for 'analytics'
	mgr.SetLicenseFeatures("KEY-SPECIAL-FREE", TierFree, []string{"analytics", "beta_ai"})

	if !mgr.IsFeatureEnabled("KEY-SPECIAL-FREE", "analytics", TierFree) {
		t.Errorf("expected custom tagged feature 'analytics' to be enabled")
	}
	if !mgr.IsFeatureEnabled("KEY-SPECIAL-FREE", "beta_ai", TierFree) {
		t.Errorf("expected custom tagged feature 'beta_ai' to be enabled")
	}
	if mgr.IsFeatureEnabled("KEY-SPECIAL-FREE", "sso", TierFree) {
		t.Errorf("expected 'sso' to remain disabled")
	}

	tier, allFeats := mgr.GetEffectiveFeatures("KEY-SPECIAL-FREE", TierFree)
	if tier != TierFree {
		t.Errorf("expected tier %s, got %s", TierFree, tier)
	}

	featMap := make(map[string]bool)
	for _, f := range allFeats {
		featMap[f] = true
	}
	if !featMap["basic_license"] || !featMap["community_support"] || !featMap["analytics"] || !featMap["beta_ai"] {
		t.Errorf("missing expected effective features: %v", allFeats)
	}
}

func TestRegisterCustomFeature(t *testing.T) {
	mgr := NewManager()

	customFeat := Feature{
		Key:          "cloud_sync",
		Name:         "Cloud Sync",
		Description:  "Multi-device cloud synchronization",
		DefaultTiers: []Tier{TierPro, TierEnterprise},
	}
	mgr.RegisterFeature(customFeat)

	if !mgr.IsFeatureEnabled("KEY-PRO-2", "cloud_sync", TierPro) {
		t.Errorf("expected custom registered feature 'cloud_sync' to be enabled on Pro")
	}
	if mgr.IsFeatureEnabled("KEY-FREE-2", "cloud_sync", TierFree) {
		t.Errorf("expected custom registered feature 'cloud_sync' to be disabled on Free")
	}

	feats := mgr.ListFeatures()
	found := false
	for _, f := range feats {
		if f.Key == "cloud_sync" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("registered feature not found in ListFeatures")
	}
}

func TestUsageRecordingAndQuotaLimits(t *testing.T) {
	mgr := NewManager()

	key := "LIC-TEST-USAGE"
	metric := "api_calls"
	period := "2026-10-14"

	// Record initial 50 units with limit 100
	rec, exceeded, err := mgr.RecordUsage(key, metric, period, 50, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Count != 50 || exceeded {
		t.Errorf("expected count 50, exceeded false; got count %d, exceeded %v", rec.Count, exceeded)
	}

	// Increment 40 more -> count = 90 (still under limit 100)
	rec, exceeded, err = mgr.RecordUsage(key, metric, period, 40, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Count != 90 || exceeded {
		t.Errorf("expected count 90, exceeded false; got count %d, exceeded %v", rec.Count, exceeded)
	}

	// Increment 20 more -> count = 110 (exceeded limit 100)
	rec, exceeded, err = mgr.RecordUsage(key, metric, period, 20, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Count != 110 || !exceeded {
		t.Errorf("expected count 110, exceeded true; got count %d, exceeded %v", rec.Count, exceeded)
	}

	// GetUsage inspection
	fetched, ok := mgr.GetUsage(key, metric, period)
	if !ok || fetched.Count != 110 {
		t.Errorf("expected GetUsage to return count 110, got ok=%v, count=%d", ok, fetched.Count)
	}

	// ListUsage inspection
	list := mgr.ListUsage(key)
	if len(list) != 1 || list[0].Count != 110 {
		t.Errorf("expected 1 record in ListUsage, got %d", len(list))
	}

	// Reset
	mgr.ResetUsage(key, metric, period)
	_, ok = mgr.GetUsage(key, metric, period)
	if ok {
		t.Errorf("expected usage record to be purged after ResetUsage")
	}
}

func TestConcurrentUsageRecording(t *testing.T) {
	mgr := NewManager()
	key := "LIC-CONCURRENT"
	metric := "api_calls"
	period := "today"

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _, _ = mgr.RecordUsage(key, metric, period, 1, 5000)
			}
		}()
	}

	wg.Wait()

	rec, ok := mgr.GetUsage(key, metric, period)
	if !ok {
		t.Fatalf("expected usage record to exist")
	}
	expected := int64(workers * iterations)
	if rec.Count != expected {
		t.Errorf("concurrent usage mismatch: expected %d, got %d", expected, rec.Count)
	}
}
