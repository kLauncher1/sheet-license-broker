package license

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// BlacklistTypeDevice flags hardware IDs.
	BlacklistTypeDevice = "device"
	// BlacklistTypeLicense flags revoked license keys.
	BlacklistTypeLicense = "license"
)

// BlacklistEntry represents a revoked license or banned hardware device.
type BlacklistEntry struct {
	Type      string    `json:"type"`       // "device" or "license"
	Target    string    `json:"target"`     // HWID or License Key
	Reason    string    `json:"reason"`     // Human rationale or breach notice
	CreatedAt time.Time `json:"created_at"` // Timestamp when action was taken
}

// BlacklistManager manages in-memory and synchronized revocations.
type BlacklistManager struct {
	mu      sync.RWMutex
	entries map[string]*BlacklistEntry
}

// NewBlacklistManager initializes a new blacklist registry.
func NewBlacklistManager() *BlacklistManager {
	return &BlacklistManager{
		entries: make(map[string]*BlacklistEntry),
	}
}

func makeKey(entryType, target string) string {
	return strings.ToLower(strings.TrimSpace(entryType)) + ":" + strings.ToUpper(strings.TrimSpace(target))
}

// Add inserts or updates a blacklist entry.
func (b *BlacklistManager) Add(entryType, target, reason string) *BlacklistEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	normType := strings.ToLower(strings.TrimSpace(entryType))
	if normType != BlacklistTypeDevice && normType != BlacklistTypeLicense {
		normType = BlacklistTypeDevice
	}
	normTarget := strings.ToUpper(strings.TrimSpace(target))
	key := normType + ":" + normTarget

	entry := &BlacklistEntry{
		Type:      normType,
		Target:    normTarget,
		Reason:    strings.TrimSpace(reason),
		CreatedAt: time.Now().UTC(),
	}
	b.entries[key] = entry
	return entry
}

// Remove clears a target from the blacklist.
func (b *BlacklistManager) Remove(entryType, target string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	k := makeKey(entryType, target)
	if _, exists := b.entries[k]; exists {
		delete(b.entries, k)
		return true
	}
	return false
}

// IsDeviceBlacklisted returns true and the ban reason if the HWID is blacklisted.
func (b *BlacklistManager) IsDeviceBlacklisted(hwid string) (bool, string) {
	if strings.TrimSpace(hwid) == "" {
		return false, ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	k := makeKey(BlacklistTypeDevice, hwid)
	if entry, exists := b.entries[k]; exists {
		reason := entry.Reason
		if reason == "" {
			reason = "Hardware device is blacklisted"
		}
		return true, reason
	}
	return false, ""
}

// IsLicenseBlacklisted returns true and the revocation reason if the key is blacklisted.
func (b *BlacklistManager) IsLicenseBlacklisted(key string) (bool, string) {
	if strings.TrimSpace(key) == "" {
		return false, ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	k := makeKey(BlacklistTypeLicense, key)
	if entry, exists := b.entries[k]; exists {
		reason := entry.Reason
		if reason == "" {
			reason = "License key has been remotely revoked"
		}
		return true, reason
	}
	return false, ""
}

// Check evaluates both license key and device HWID against the blacklist.
func (b *BlacklistManager) Check(licenseKey, hwid string) error {
	if blacklisted, reason := b.IsLicenseBlacklisted(licenseKey); blacklisted {
		return fmt.Errorf("license revoked: %s", reason)
	}
	if blacklisted, reason := b.IsDeviceBlacklisted(hwid); blacklisted {
		return fmt.Errorf("device blacklisted: %s", reason)
	}
	return nil
}

// ListEntries returns a snapshot of all active blacklist entries.
func (b *BlacklistManager) ListEntries() []BlacklistEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	res := make([]BlacklistEntry, 0, len(b.entries))
	for _, e := range b.entries {
		res = append(res, *e)
	}
	return res
}
