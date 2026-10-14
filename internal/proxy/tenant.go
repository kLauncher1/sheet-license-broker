package proxy

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/backup"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
	"github.com/kLauncher1/sheet-license-broker/internal/tenant"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// TenantManager returns the thread-safe tenant registry.
func (p *Proxy) TenantManager() *tenant.TenantManager {
	return p.localTenant
}

// Dispatcher returns the asynchronous webhook event dispatcher.
func (p *Proxy) Dispatcher() *webhook.Dispatcher {
	return p.dispatcher
}

// RegisterTenant stores a new tenant namespace.
func (p *Proxy) RegisterTenant(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	created, err := p.localTenant.RegisterTenant(t)
	if err != nil {
		return nil, err
	}
	return created, nil
}

// GetTenant retrieves a tenant by ID or returns the default fallback.
func (p *Proxy) GetTenant(id string) (*tenant.Tenant, bool) {
	return p.localTenant.GetTenant(id)
}

// ListTenants returns all registered tenant configurations.
func (p *Proxy) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	return p.localTenant.ListTenants(), nil
}

// CreateTenantLicense generates a namespaced license key for a specific tenant.
func (p *Proxy) CreateTenantLicense(ctx context.Context, tenantID string, days, maxDevices int) (*LicenseResult, error) {
	t, found := p.localTenant.GetTenant(tenantID)
	if !found {
		t = p.localTenant.DefaultTenant()
	}

	key := p.localTenant.FormatLicenseKey(t.NamespacePrefix)
	now := time.Now().UTC()
	if days <= 0 {
		days = 30
	}
	if maxDevices <= 0 {
		maxDevices = 1
	}

	expiresAt := now.Add(time.Duration(days) * 24 * time.Hour)
	lic := &license.License{
		LicenseKey: key,
		BoundHWID:  "",
		MaxDevices: maxDevices,
		Status:     "ACTIVE",
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
	}

	// Persist locally
	p.localLicense.PutLicense(lic)

	// Persist in remote GAS if active
	source := "local_fallback"
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.CreateLicense(ctx, key, days, maxDevices)
		if err == nil {
			source = "remote_gas"
			if resp.ExpiresAt != "" {
				if parsedExp, err := time.Parse(time.RFC3339, resp.ExpiresAt); err == nil {
					lic.ExpiresAt = parsedExp
				}
			}
		} else {
			log.Printf("[Proxy] Remote tenant license creation warning: %v", err)
		}
	}

	// Dispatch asynchronous webhook notification
	evt := webhook.NewEvent(webhook.EventLicenseCreated, t.ID, map[string]interface{}{
		"license_key": key,
		"tenant_id":   t.ID,
		"max_devices": maxDevices,
		"expires_at":  lic.ExpiresAt.Format(time.RFC3339),
		"status":      lic.Status,
	})
	p.dispatcher.Dispatch(evt, t.WebhookURL, t.HMACSecret)

	return &LicenseResult{
		LicenseKey: key,
		ExpiresAt:  lic.ExpiresAt.Format(time.RFC3339),
		Status:     lic.Status,
		Source:     source,
	}, nil
}

// NotifyLicenseEvent fires a webhook event for a given license key.
func (p *Proxy) NotifyLicenseEvent(eventType, licenseKey, hwid, message string) {
	t := p.localTenant.ResolveTenantByKey(licenseKey)
	evt := webhook.NewEvent(eventType, t.ID, map[string]interface{}{
		"license_key": licenseKey,
		"hwid":        hwid,
		"tenant_id":   t.ID,
		"message":     message,
	})
	p.dispatcher.Dispatch(evt, t.WebhookURL, t.HMACSecret)
}

// ExportBackup generates a consolidated point-in-time snapshot, optionally encrypted with AES-256-GCM.
func (p *Proxy) ExportBackup(ctx context.Context, secretKey []byte) ([]byte, *backup.BackupSnapshot, error) {
	// Aggregate Tenants
	tenantsRaw := p.localTenant.ListTenants()
	tenants := make([]tenant.Tenant, 0, len(tenantsRaw))
	for _, t := range tenantsRaw {
		tenants = append(tenants, *t)
	}

	// Aggregate Users, Licenses, Blacklist, Documents
	users := p.localAuth.ListUsers()
	licenses := p.localLicense.ListLicenses()
	blacklist := p.localLicense.Blacklist().ListEntries()
	docs := p.localDB.ListAll()

	data := backup.SnapshotData{
		Tenants:   tenants,
		Users:     users,
		Licenses:  licenses,
		Blacklist: blacklist,
		Documents: docs,
	}

	snapshot, err := backup.CreateSnapshot(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build snapshot: %w", err)
	}

	var encrypted []byte
	if len(secretKey) > 0 {
		encrypted, err = backup.EncryptSnapshot(snapshot, secretKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt snapshot: %w", err)
		}
	}

	return encrypted, snapshot, nil
}

// RestoreBackup restores entities from an authenticated snapshot or encrypted payload.
func (p *Proxy) RestoreBackup(ctx context.Context, encryptedData []byte, secretKey []byte, snapshot *backup.BackupSnapshot) (*backup.BackupSnapshot, error) {
	target := snapshot
	var err error

	if len(encryptedData) > 0 {
		target, err = backup.DecryptSnapshot(encryptedData, secretKey)
		if err != nil {
			return nil, err
		}
	}

	if target == nil {
		return nil, backup.ErrInvalidSnapshot
	}

	if valid, err := target.VerifyIntegrity(); !valid || err != nil {
		return nil, backup.ErrChecksumMismatch
	}

	// Restore Tenants
	for _, t := range target.Data.Tenants {
		copyTenant := t
		_, _ = p.localTenant.RegisterTenant(&copyTenant)
	}

	// Restore Users
	for _, u := range target.Data.Users {
		copyUser := u
		p.localAuth.PutUser(&copyUser)
	}

	// Restore Licenses
	for _, l := range target.Data.Licenses {
		copyLic := l
		p.localLicense.PutLicense(&copyLic)
	}

	// Restore Blacklist
	for _, b := range target.Data.Blacklist {
		p.localLicense.Blacklist().Add(b.Type, b.Target, b.Reason)
	}

	// Restore Documents
	for _, d := range target.Data.Documents {
		p.localDB.Put(d.Collection, d.DocID, d.Payload)
	}

	return target, nil
}

// Close gracefully releases proxy resources and worker threads.
func (p *Proxy) Close() {
	if p.dispatcher != nil {
		p.dispatcher.Close()
	}
	if p.consensusEngine != nil {
		p.consensusEngine.Close()
	}
	if p.p2pMesh != nil {
		p.p2pMesh.Close()
	}
}
