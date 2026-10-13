package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/auth"
	"github.com/kLauncher1/sheet-license-broker/internal/db"
	"github.com/kLauncher1/sheet-license-broker/internal/gas"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrLicenseInvalid    = errors.New("invalid or expired license")
)

// ProxyConfig defines construction options for the proxy coordinator.
type ProxyConfig struct {
	WebAppURL   string
	OfflineMode bool
	CacheTTL    time.Duration
}

// VerifyResult captures the unified result of a license check.
type VerifyResult struct {
	Valid      bool   `json:"valid"`
	LicenseKey string `json:"license_key"`
	HWIDBound  string `json:"hwid_bound"`
	ExpiresAt  string `json:"expires_at"`
	Source     string `json:"source"` // "cache", "remote_gas", "local_fallback", "offline_cache"
	Message    string `json:"message,omitempty"`
}

// LicenseResult captures unified license creation outcome.
type LicenseResult struct {
	LicenseKey string `json:"license_key"`
	ExpiresAt  string `json:"expires_at"`
	Status     string `json:"status"`
	Source     string `json:"source"`
}

// Proxy coordinates calls between Google Apps Script, local memory engines, and cache.
type Proxy struct {
	gasClient    *gas.Client
	cache        *gas.Cache
	localAuth    *auth.Manager
	localLicense *license.Manager
	localDB      *db.Storage
	offlineMode  bool
	cacheTTL     time.Duration
	startTime    time.Time
}

// NewProxy creates a proxy orchestrator. If WebAppURL is empty or OfflineMode is true,
// it uses local in-memory engines.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 10 * time.Minute
	}

	p := &Proxy{
		cache:        gas.NewCache(),
		localAuth:    auth.NewManager(),
		localLicense: license.NewManager(),
		localDB:      db.NewStorage(),
		offlineMode:  cfg.OfflineMode,
		cacheTTL:     cacheTTL,
		startTime:    time.Now(),
	}

	trimmedURL := strings.TrimSpace(cfg.WebAppURL)
	if trimmedURL != "" && !cfg.OfflineMode {
		client, err := gas.NewClient(gas.ClientConfig{
			WebAppURL:   trimmedURL,
			Timeout:     10 * time.Second,
			MaxRetries:  3,
			BackoffBase: 200 * time.Millisecond,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize gas client: %w", err)
		}
		p.gasClient = client
	}

	return p, nil
}

// IsRemoteEnabled indicates whether a remote Google Apps Script backend is wired.
func (p *Proxy) IsRemoteEnabled() bool {
	return p.gasClient != nil && !p.offlineMode
}

// WebAppURL returns the configured Apps Script endpoint or empty.
func (p *Proxy) WebAppURL() string {
	if p.gasClient == nil {
		return ""
	}
	return p.gasClient.WebAppURL()
}

// Ping checks remote connectivity if enabled, or confirms local health.
func (p *Proxy) Ping(ctx context.Context) (map[string]interface{}, error) {
	if p.IsRemoteEnabled() {
		res, err := p.gasClient.Ping(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"status":    res.Status,
			"mode":      "remote_gas",
			"message":   res.Message,
			"timestamp": res.Timestamp,
		}, nil
	}

	return map[string]interface{}{
		"status":    "success",
		"mode":      "local_standalone",
		"message":   "Local standalone memory broker active",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// VerifyLicense checks license entitlement with cache and offline fallback.
func (p *Proxy) VerifyLicense(ctx context.Context, key, hwid string) (*VerifyResult, error) {
	key = strings.TrimSpace(key)
	hwid = strings.TrimSpace(hwid)

	// 1. Check local cache
	if lic, found, expired := p.cache.GetLicense(key); found && !expired {
		if lic.HWIDBound != "" && hwid != "" && lic.HWIDBound != hwid {
			return &VerifyResult{
				Valid:      false,
				LicenseKey: key,
				Source:     "cache",
				Message:    "Hardware ID mismatch",
			}, ErrLicenseInvalid
		}
		return &VerifyResult{
			Valid:      true,
			LicenseKey: key,
			HWIDBound:  lic.HWIDBound,
			ExpiresAt:  lic.ExpiresAt,
			Source:     "cache",
			Message:    "Verified from local cache",
		}, nil
	}

	// 2. Query remote Google Apps Script if enabled
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.VerifyLicense(ctx, key, hwid)
		if err == nil && resp.Verified {
			p.cache.SetLicense(key, resp, p.cacheTTL)
			return &VerifyResult{
				Valid:      true,
				LicenseKey: key,
				HWIDBound:  resp.HWIDBound,
				ExpiresAt:  resp.ExpiresAt,
				Source:     "remote_gas",
				Message:    resp.Message,
			}, nil
		}

		// On remote failure (rate limit, timeout, network error), attempt offline fallback
		log.Printf("[Proxy] Remote verification failed (%v), checking offline fallback...", err)
		if lic, found, expired := p.cache.GetLicense(key); found {
			source := "offline_cache"
			if expired {
				source = "offline_cache_expired_grace"
			}
			return &VerifyResult{
				Valid:      true,
				LicenseKey: key,
				HWIDBound:  lic.HWIDBound,
				ExpiresAt:  lic.ExpiresAt,
				Source:     source,
				Message:    "Served via offline grace cache during remote outage",
			}, nil
		}
	}

	// 3. Fallback to local in-memory engine
	lic, err := p.localLicense.VerifyAndBind(key, hwid)
	if err != nil {
		return nil, err
	}

	return &VerifyResult{
		Valid:      true,
		LicenseKey: lic.LicenseKey,
		HWIDBound:  lic.BoundHWID,
		ExpiresAt:  lic.ExpiresAt.Format(time.RFC3339),
		Source:     "local_fallback",
		Message:    "Verified against local memory database",
	}, nil
}

// CreateLicense generates a new license key in remote GAS or local store.
func (p *Proxy) CreateLicense(ctx context.Context, days, maxDevices int) (*LicenseResult, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.CreateLicense(ctx, "", days, maxDevices)
		if err == nil {
			return &LicenseResult{
				LicenseKey: resp.LicenseKey,
				ExpiresAt:  resp.ExpiresAt,
				Status:     resp.Status,
				Source:     "remote_gas",
			}, nil
		}
		log.Printf("[Proxy] Remote license creation failed: %v. Falling back to local store.", err)
	}

	lic := p.localLicense.CreateLicense(days, maxDevices)
	return &LicenseResult{
		LicenseKey: lic.LicenseKey,
		ExpiresAt:  lic.ExpiresAt.Format(time.RFC3339),
		Status:     lic.Status,
		Source:     "local_fallback",
	}, nil
}

// RegisterUser registers a user via remote GAS or local engine.
func (p *Proxy) RegisterUser(ctx context.Context, username, password, role string) (*auth.User, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.RegisterUser(ctx, username, password)
		if err == nil {
			return &auth.User{
				UserID:   resp.UserID,
				Username: resp.Username,
				Role:     role,
			}, nil
		}
		log.Printf("[Proxy] Remote registration failed: %v. Falling back to local engine.", err)
	}

	return p.localAuth.RegisterUser(username, password, role)
}

// AuthenticateUser verifies user credentials against remote GAS or local store.
func (p *Proxy) AuthenticateUser(ctx context.Context, username, password string) (*auth.User, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.LoginUser(ctx, username, password)
		if err == nil {
			return &auth.User{
				UserID:   resp.UserID,
				Username: resp.Username,
				Role:     resp.Role,
			}, nil
		}
		return nil, ErrInvalidCredentials
	}

	return p.localAuth.Authenticate(username, password)
}

// PutDocument stores a document in remote GAS or local store with cache update.
func (p *Proxy) PutDocument(ctx context.Context, collection, docID, payload string) (*db.Document, error) {
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.PutDocument(ctx, collection, docID, payload)
		if err == nil {
			p.cache.SetDoc(collection, docID, resp, p.cacheTTL)
			return &db.Document{
				Collection: collection,
				DocID:      docID,
				Payload:    payload,
				UpdatedAt:  time.Now(),
			}, nil
		}
		log.Printf("[Proxy] Remote PutDocument failed: %v. Storing locally.", err)
	}

	return p.localDB.Put(collection, docID, payload), nil
}

// GetDocument retrieves a document by collection and ID.
func (p *Proxy) GetDocument(ctx context.Context, collection, docID string) (*db.Document, error) {
	// 1. Check local cache
	if cached, found, _ := p.cache.GetDoc(collection, docID); found {
		return &db.Document{
			Collection: collection,
			DocID:      docID,
			Payload:    fmt.Sprintf("%v", cached.Data),
			UpdatedAt:  time.Now(),
		}, nil
	}

	// 2. Remote GAS
	if p.IsRemoteEnabled() {
		resp, err := p.gasClient.GetDocument(ctx, collection, docID)
		if err == nil {
			p.cache.SetDoc(collection, docID, resp, p.cacheTTL)
			return &db.Document{
				Collection: collection,
				DocID:      docID,
				Payload:    fmt.Sprintf("%v", resp.Data),
				UpdatedAt:  time.Now(),
			}, nil
		}
	}

	// 3. Local DB
	return p.localDB.Get(collection, docID)
}

// ListLicenses returns cached or local licenses for UI presentation.
func (p *Proxy) ListLicenses() []license.License {
	return p.localLicense.ListLicenses()
}

// ListUsers returns local users for UI presentation.
func (p *Proxy) ListUsers() []auth.User {
	return p.localAuth.ListUsers()
}

// ListDocuments returns all local documents.
func (p *Proxy) ListDocuments() []db.Document {
	return p.localDB.ListAll()
}

// Status delivers diagnostic metrics on proxy state.
func (p *Proxy) Status() map[string]interface{} {
	mode := "local_standalone"
	if p.IsRemoteEnabled() {
		mode = "remote_gas_proxy"
	} else if p.offlineMode {
		mode = "offline_forced"
	}

	return map[string]interface{}{
		"mode":             mode,
		"remote_enabled":   p.IsRemoteEnabled(),
		"webapp_url":       p.WebAppURL(),
		"cache_entries":    p.cache.Len(),
		"cache_ttl":        p.cacheTTL.String(),
		"uptime_seconds":   int(time.Since(p.startTime).Seconds()),
	}
}
