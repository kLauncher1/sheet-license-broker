package proxy

import (
	"context"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/feature"
)

// FeatureManager returns the attached dynamic feature and tier metering manager.
func (p *Proxy) FeatureManager() *feature.Manager {
	return p.featureManager
}

// CheckFeature verifies whether a given feature is entitled for a license key.
func (p *Proxy) CheckFeature(ctx context.Context, licenseKey, featureKey string) (bool, string, error) {
	normKey := strings.ToUpper(strings.TrimSpace(licenseKey))
	normFeat := strings.ToLower(strings.TrimSpace(featureKey))

	fallbackTier := feature.TierPro

	// 1. Check local license store for tier and key validity
	if lic, err := p.localLicense.VerifyAndBind(normKey, ""); err == nil && lic != nil {
		if lic.Tier != "" {
			fallbackTier = feature.NormalizeTier(lic.Tier)
		}
	} else if p.cache != nil {
		// 2. Check cache if remote mode
		if licCached, found, _ := p.cache.GetLicense(normKey); found && licCached != nil {
			fallbackTier = feature.TierPro
		}
	}

	enabled := p.featureManager.IsFeatureEnabled(normKey, normFeat, fallbackTier)
	activeTier, _ := p.featureManager.GetEffectiveFeatures(normKey, fallbackTier)

	return enabled, string(activeTier), nil
}

// RecordUsage increments usage consumption and returns whether quota is exceeded.
func (p *Proxy) RecordUsage(ctx context.Context, key, metric, period string, units int64, limit int64) (feature.UsageRecord, bool, error) {
	rec, exceeded, err := p.featureManager.RecordUsage(key, metric, period, units, limit)
	if err != nil {
		return rec, false, err
	}

	// In remote GAS mode, forward async event if configured
	if p.IsRemoteEnabled() && p.gasClient != nil {
		go func(k, m, prd string, u, lim int64) {
			// Best effort async telemetry push
			_, _ = p.gasClient.ExecuteAction(context.Background(), "usage_record", map[string]interface{}{
				"key":    k,
				"metric": m,
				"period": prd,
				"units":  u,
				"limit":  lim,
			})
		}(key, metric, rec.Period, units, limit)
	}

	return rec, exceeded, nil
}

// GetUsage retrieves all usage metrics for a given license key or tenant ID.
func (p *Proxy) GetUsage(ctx context.Context, key string) ([]feature.UsageRecord, error) {
	normKey := strings.ToUpper(strings.TrimSpace(key))
	records := p.featureManager.ListUsage(normKey)
	return records, nil
}

// SetLicenseFeatures assigns custom tier and feature tags to a license key.
func (p *Proxy) SetLicenseFeatures(key string, tier string, features []string) {
	p.featureManager.SetLicenseFeatures(key, feature.NormalizeTier(tier), features)
}

// GetEffectiveFeatures returns the active tier and all enabled feature keys for a license.
func (p *Proxy) GetEffectiveFeatures(key string) (string, []string) {
	tier, feats := p.featureManager.GetEffectiveFeatures(key, feature.TierPro)
	return string(tier), feats
}
