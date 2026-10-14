package proxy

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/license"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// BlacklistManager provides access to the underlying local blacklist registry.
func (p *Proxy) BlacklistManager() *license.BlacklistManager {
	return p.localLicense.Blacklist()
}

// RevokeLicense invalidates a license key instantly across local cache, local store, and remote Google Sheets.
func (p *Proxy) RevokeLicense(ctx context.Context, licenseKey, reason string) error {
	normKey := strings.ToUpper(strings.TrimSpace(licenseKey))
	p.cache.DeleteLicense(normKey)

	// Record in local license manager
	_ = p.localLicense.RevokeLicense(normKey, reason)

	if p.IsRemoteEnabled() {
		_, err := p.gasClient.RevokeLicense(ctx, normKey, reason)
		if err != nil {
			log.Printf("[Proxy] Remote license revocation warning (%v), recorded locally", err)
		}
	}
	p.PushRevocation(normKey, "", reason)
	p.NotifyLicenseEvent(webhook.EventLicenseRevoked, normKey, "", reason)
	return nil
}

// BlacklistDevice registers a banned hardware identifier.
func (p *Proxy) BlacklistDevice(ctx context.Context, hwid, reason string) error {
	normHWID := strings.TrimSpace(hwid)
	p.localLicense.Blacklist().Add(license.BlacklistTypeDevice, normHWID, reason)

	if p.IsRemoteEnabled() {
		_, err := p.gasClient.BlacklistAdd(ctx, license.BlacklistTypeDevice, normHWID, reason)
		if err != nil {
			log.Printf("[Proxy] Remote device blacklist warning (%v), recorded locally", err)
		}
	}
	p.PushRevocation("", normHWID, reason)
	p.NotifyLicenseEvent(webhook.EventDeviceBanned, "", normHWID, reason)
	return nil
}

// RemoveBlacklist clears an entry from the blacklist.
func (p *Proxy) RemoveBlacklist(ctx context.Context, entryType, target string) error {
	p.localLicense.Blacklist().Remove(entryType, target)

	if p.IsRemoteEnabled() {
		_, err := p.gasClient.BlacklistRemove(ctx, entryType, target)
		if err != nil {
			log.Printf("[Proxy] Remote blacklist removal warning (%v), removed locally", err)
		}
	}
	return nil
}

// ListBlacklist returns all active blacklist records, syncing with remote GAS if available.
func (p *Proxy) ListBlacklist(ctx context.Context) ([]license.BlacklistEntry, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.BlacklistList(ctx)
		if err == nil && resp != nil {
			// Sync remote entries into local blacklist
			for _, e := range resp.Entries {
				t, err := time.Parse(time.RFC3339, e.CreatedAt)
				if err != nil {
					t = time.Now().UTC()
				}
				entry := p.localLicense.Blacklist().Add(e.Type, e.Target, e.Reason)
				entry.CreatedAt = t
			}
		}
	}

	return p.localLicense.Blacklist().ListEntries(), nil
}
