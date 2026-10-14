package feature

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Tier represents standard subscription or license tiers.
type Tier string

const (
	TierFree       Tier = "free"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
)

// NormalizeTier cleans and normalizes a tier string, defaulting to TierPro.
func NormalizeTier(t string) Tier {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case string(TierFree):
		return TierFree
	case string(TierEnterprise):
		return TierEnterprise
	default:
		return TierPro
	}
}

// Feature describes an individual capability or entitlement tag.
type Feature struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	DefaultTiers []Tier   `json:"default_tiers"`
}

// LicenseFeatures contains the tier and explicit feature flags for a license key.
type LicenseFeatures struct {
	LicenseKey      string   `json:"license_key"`
	Tier            Tier     `json:"tier"`
	EnabledFeatures []string `json:"enabled_features"`
}

// UsageRecord tracks consumption of a metered resource for a given period.
type UsageRecord struct {
	Key       string    `json:"key"`        // License key or tenant ID
	Metric    string    `json:"metric"`     // e.g. "api_calls", "seat_count", "storage_mb"
	Period    string    `json:"period"`     // e.g. "2026-10-14" (daily) or "default"
	Count     int64     `json:"count"`      // Consumed units
	Limit     int64     `json:"limit"`      // Max quota (0 = unlimited)
	UpdatedAt time.Time `json:"updated_at"` // Timestamp of last consumption
}

// Manager orchestrates dynamic feature flags and usage-based tier metering.
type Manager struct {
	mu           sync.RWMutex
	features     map[string]*Feature
	tierDefaults map[Tier][]string
	licenses     map[string]*LicenseFeatures
	usage        map[string]*UsageRecord
}

// NewManager initializes the feature and metering manager with industry defaults.
func NewManager() *Manager {
	m := &Manager{
		features:     make(map[string]*Feature),
		tierDefaults: make(map[Tier][]string),
		licenses:     make(map[string]*LicenseFeatures),
		usage:        make(map[string]*UsageRecord),
	}

	// Register standard platform features
	m.registerStandardFeatures()
	return m
}

func (m *Manager) registerStandardFeatures() {
	standardFeatures := []Feature{
		{
			Key:          "basic_license",
			Name:         "Basic License Validation",
			Description:  "Core hardware-bound license activation and validation",
			DefaultTiers: []Tier{TierFree, TierPro, TierEnterprise},
		},
		{
			Key:          "community_support",
			Name:         "Community Support",
			Description:  "Standard public documentation and forum support",
			DefaultTiers: []Tier{TierFree, TierPro, TierEnterprise},
		},
		{
			Key:          "analytics",
			Name:         "Usage Analytics",
			Description:  "Telemetry and usage consumption analytics dashboard",
			DefaultTiers: []Tier{TierPro, TierEnterprise},
		},
		{
			Key:          "csv_export",
			Name:         "Data Export",
			Description:  "CSV and JSON telemetry and license records export",
			DefaultTiers: []Tier{TierPro, TierEnterprise},
		},
		{
			Key:          "extended_logs",
			Name:         "Extended Audit Logs",
			Description:  "Comprehensive tamper and security event logging",
			DefaultTiers: []Tier{TierPro, TierEnterprise},
		},
		{
			Key:          "sso",
			Name:         "Single Sign-On (SSO)",
			Description:  "SAML and OAuth2 federated identity management",
			DefaultTiers: []Tier{TierEnterprise},
		},
		{
			Key:          "audit_export",
			Name:         "SIEM Audit Feed",
			Description:  "Real-time audit log streaming to enterprise SIEM platforms",
			DefaultTiers: []Tier{TierEnterprise},
		},
		{
			Key:          "unlimited_seats",
			Name:         "Unlimited Device Seats",
			Description:  "Unrestricted hardware device binding per license",
			DefaultTiers: []Tier{TierEnterprise},
		},
		{
			Key:          "priority_support",
			Name:         "24/7 Dedicated Support",
			Description:  "Guaranteed SLA response times and dedicated engineer",
			DefaultTiers: []Tier{TierEnterprise},
		},
	}

	for _, f := range standardFeatures {
		m.features[strings.ToLower(f.Key)] = &f
		for _, tier := range f.DefaultTiers {
			m.tierDefaults[tier] = append(m.tierDefaults[tier], strings.ToLower(f.Key))
		}
	}
}

// RegisterFeature adds or updates a feature definition.
func (m *Manager) RegisterFeature(f Feature) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normKey := strings.ToLower(strings.TrimSpace(f.Key))
	if normKey == "" {
		return
	}
	f.Key = normKey
	m.features[normKey] = &f

	for _, tier := range f.DefaultTiers {
		normTier := NormalizeTier(string(tier))
		exists := false
		for _, k := range m.tierDefaults[normTier] {
			if k == normKey {
				exists = true
				break
			}
		}
		if !exists {
			m.tierDefaults[normTier] = append(m.tierDefaults[normTier], normKey)
		}
	}
}

// ListFeatures returns all registered feature definitions.
func (m *Manager) ListFeatures() []Feature {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]Feature, 0, len(m.features))
	for _, f := range m.features {
		list = append(list, *f)
	}
	return list
}

// SetLicenseFeatures associates a license key with a tier and custom feature tags.
func (m *Manager) SetLicenseFeatures(key string, tier Tier, customFeatures []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	normTier := NormalizeTier(string(tier))

	cleaned := make([]string, 0, len(customFeatures))
	for _, f := range customFeatures {
		cf := strings.ToLower(strings.TrimSpace(f))
		if cf != "" {
			cleaned = append(cleaned, cf)
		}
	}

	m.licenses[normKey] = &LicenseFeatures{
		LicenseKey:      normKey,
		Tier:            normTier,
		EnabledFeatures: cleaned,
	}
}

// GetLicenseFeatures retrieves the tier and custom features for a license key.
func (m *Manager) GetLicenseFeatures(key string) (*LicenseFeatures, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lf, ok := m.licenses[strings.ToUpper(strings.TrimSpace(key))]
	if !ok {
		return nil, false
	}
	// Return a copy
	res := *lf
	res.EnabledFeatures = append([]string(nil), lf.EnabledFeatures...)
	return &res, true
}

// IsFeatureEnabled determines whether a feature is permitted for a license key.
func (m *Manager) IsFeatureEnabled(key string, featureKey string, fallbackTier Tier) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	normFeat := strings.ToLower(strings.TrimSpace(featureKey))

	activeTier := NormalizeTier(string(fallbackTier))

	if lf, ok := m.licenses[normKey]; ok {
		activeTier = lf.Tier
		for _, f := range lf.EnabledFeatures {
			if strings.ToLower(f) == normFeat {
				return true
			}
		}
	}

	for _, f := range m.tierDefaults[activeTier] {
		if strings.ToLower(f) == normFeat {
			return true
		}
	}

	return false
}

// GetEffectiveFeatures returns the active tier and all deduplicated enabled features.
func (m *Manager) GetEffectiveFeatures(key string, fallbackTier Tier) (Tier, []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	activeTier := NormalizeTier(string(fallbackTier))

	seen := make(map[string]bool)
	var result []string

	if lf, ok := m.licenses[normKey]; ok {
		activeTier = lf.Tier
		for _, f := range lf.EnabledFeatures {
			norm := strings.ToLower(f)
			if !seen[norm] {
				seen[norm] = true
				result = append(result, norm)
			}
		}
	}

	for _, f := range m.tierDefaults[activeTier] {
		norm := strings.ToLower(f)
		if !seen[norm] {
			seen[norm] = true
			result = append(result, norm)
		}
	}

	return activeTier, result
}

// RecordUsage increments consumption for a metric and validates against limits.
func (m *Manager) RecordUsage(key, metric, period string, units int64, limit int64) (UsageRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	normMetric := strings.ToLower(strings.TrimSpace(metric))
	if normKey == "" || normMetric == "" {
		return UsageRecord{}, false, errors.New("key and metric are required")
	}

	normPeriod := strings.TrimSpace(period)
	if normPeriod == "" {
		normPeriod = time.Now().UTC().Format("2006-01-02")
	}

	id := fmt.Sprintf("%s:%s:%s", normKey, normMetric, normPeriod)
	rec, ok := m.usage[id]
	if !ok {
		rec = &UsageRecord{
			Key:    normKey,
			Metric: normMetric,
			Period: normPeriod,
			Count:  0,
			Limit:  limit,
		}
		m.usage[id] = rec
	}

	rec.Count += units
	rec.UpdatedAt = time.Now().UTC()
	if limit > 0 {
		rec.Limit = limit
	}

	exceeded := rec.Limit > 0 && rec.Count > rec.Limit
	return *rec, exceeded, nil
}

// GetUsage retrieves a specific usage record.
func (m *Manager) GetUsage(key, metric, period string) (UsageRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	normMetric := strings.ToLower(strings.TrimSpace(metric))
	normPeriod := strings.TrimSpace(period)
	if normPeriod == "" {
		normPeriod = time.Now().UTC().Format("2006-01-02")
	}

	id := fmt.Sprintf("%s:%s:%s", normKey, normMetric, normPeriod)
	rec, ok := m.usage[id]
	if !ok {
		return UsageRecord{}, false
	}
	return *rec, true
}

// ListUsage returns all usage records associated with a key.
func (m *Manager) ListUsage(key string) []UsageRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	var list []UsageRecord
	for _, rec := range m.usage {
		if rec.Key == normKey {
			list = append(list, *rec)
		}
	}
	return list
}

// ResetUsage clears recorded consumption for a specific metric and period.
func (m *Manager) ResetUsage(key, metric, period string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	normMetric := strings.ToLower(strings.TrimSpace(metric))
	normPeriod := strings.TrimSpace(period)
	if normPeriod == "" {
		normPeriod = time.Now().UTC().Format("2006-01-02")
	}

	id := fmt.Sprintf("%s:%s:%s", normKey, normMetric, normPeriod)
	delete(m.usage, id)
}
