package tenant

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidTenantID    = errors.New("invalid or empty tenant id")
	ErrInvalidPrefix      = errors.New("invalid namespace prefix: must be 2-8 uppercase alphanumeric characters")
	ErrTenantAlreadyExist = errors.New("tenant id or prefix already registered")
	ErrTenantNotFound     = errors.New("tenant not found")

	prefixRegex = regexp.MustCompile(`^[A-Z0-9]{2,8}$`)
)

// Tenant encapsulates an isolated application namespace with independent credentials and policies.
type Tenant struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	NamespacePrefix string    `json:"namespace_prefix"`
	HMACSecret      string    `json:"hmac_secret,omitempty"`
	MaxLicenses     int       `json:"max_licenses"`
	WebhookURL      string    `json:"webhook_url,omitempty"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
}

// TenantManager coordinates thread-safe multi-tenant isolation, namespacing, and resolution.
type TenantManager struct {
	mu            sync.RWMutex
	tenants       map[string]*Tenant
	byPrefix      map[string]*Tenant
	defaultTenant *Tenant
}

// NewTenantManager constructs a tenant registry seeded with an active default tenant.
func NewTenantManager() *TenantManager {
	tm := &TenantManager{
		tenants:  make(map[string]*Tenant),
		byPrefix: make(map[string]*Tenant),
	}

	def := &Tenant{
		ID:              "default",
		Name:            "Default Tenant",
		NamespacePrefix: "DEF",
		HMACSecret:      "",
		MaxLicenses:     0,
		WebhookURL:      "",
		IsActive:        true,
		CreatedAt:       time.Now().UTC(),
	}

	tm.tenants[def.ID] = def
	tm.byPrefix[def.NamespacePrefix] = def
	tm.defaultTenant = def

	return tm
}

// DefaultTenant returns the fallback tenant for non-namespaced requests.
func (tm *TenantManager) DefaultTenant() *Tenant {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.defaultTenant
}

// RegisterTenant validates and stores a new tenant namespace.
func (tm *TenantManager) RegisterTenant(t *Tenant) (*Tenant, error) {
	if t == nil {
		return nil, ErrInvalidTenantID
	}

	id := strings.TrimSpace(t.ID)
	if id == "" {
		return nil, ErrInvalidTenantID
	}

	prefix := strings.ToUpper(strings.TrimSpace(t.NamespacePrefix))
	if !prefixRegex.MatchString(prefix) {
		return nil, ErrInvalidPrefix
	}

	name := strings.TrimSpace(t.Name)
	if name == "" {
		name = id
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.tenants[id]; exists {
		return nil, ErrTenantAlreadyExist
	}
	if _, exists := tm.byPrefix[prefix]; exists {
		return nil, ErrTenantAlreadyExist
	}

	created := &Tenant{
		ID:              id,
		Name:            name,
		NamespacePrefix: prefix,
		HMACSecret:      strings.TrimSpace(t.HMACSecret),
		MaxLicenses:     t.MaxLicenses,
		WebhookURL:      strings.TrimSpace(t.WebhookURL),
		IsActive:        t.IsActive,
		CreatedAt:       time.Now().UTC(),
	}

	tm.tenants[id] = created
	tm.byPrefix[prefix] = created
	return created, nil
}

// GetTenant retrieves a tenant by unique ID.
func (tm *TenantManager) GetTenant(id string) (*Tenant, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	t, found := tm.tenants[strings.TrimSpace(id)]
	return t, found
}

// GetTenantByPrefix retrieves a tenant by namespace prefix.
func (tm *TenantManager) GetTenantByPrefix(prefix string) (*Tenant, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	t, found := tm.byPrefix[strings.ToUpper(strings.TrimSpace(prefix))]
	return t, found
}

// ListTenants returns all registered tenants.
func (tm *TenantManager) ListTenants() []*Tenant {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	list := make([]*Tenant, 0, len(tm.tenants))
	for _, t := range tm.tenants {
		list = append(list, t)
	}
	return list
}

// FormatLicenseKey generates a prefixed key following the convention: PREFIX-LIC-XXXX-YYYY.
func (tm *TenantManager) FormatLicenseKey(prefix string) string {
	cleanPrefix := strings.ToUpper(strings.TrimSpace(prefix))
	if cleanPrefix == "" || !prefixRegex.MatchString(cleanPrefix) {
		cleanPrefix = "DEF"
	}

	b := make([]byte, 4)
	_, _ = rand.Read(b)
	hexStr := strings.ToUpper(hex.EncodeToString(b))

	return fmt.Sprintf("%s-LIC-%s-%s", cleanPrefix, hexStr[0:4], hexStr[4:8])
}

// ParseLicenseKey extracts the namespace prefix if the key adheres to standard namespacing.
func ParseLicenseKey(key string) (prefix string, isNamespaced bool) {
	cleanKey := strings.ToUpper(strings.TrimSpace(key))
	parts := strings.Split(cleanKey, "-")
	if len(parts) >= 3 && parts[1] == "LIC" {
		if prefixRegex.MatchString(parts[0]) {
			return parts[0], true
		}
	}
	return "", false
}

// ResolveTenantByKey resolves the tenant from a license key's namespace prefix.
func (tm *TenantManager) ResolveTenantByKey(key string) *Tenant {
	if prefix, ok := ParseLicenseKey(key); ok {
		if t, found := tm.GetTenantByPrefix(prefix); found && t.IsActive {
			return t
		}
	}
	return tm.DefaultTenant()
}

// ResolveFromRequest inspects HTTP headers and query parameters to determine the tenant context.
func (tm *TenantManager) ResolveFromRequest(r *http.Request) *Tenant {
	if r == nil {
		return tm.DefaultTenant()
	}

	// 1. Check X-Tenant-ID header
	if headerVal := strings.TrimSpace(r.Header.Get("X-Tenant-ID")); headerVal != "" {
		if t, found := tm.GetTenant(headerVal); found && t.IsActive {
			return t
		}
		if t, found := tm.GetTenantByPrefix(headerVal); found && t.IsActive {
			return t
		}
	}

	// 2. Check query parameter 'tenant' or 'tenant_id'
	q := r.URL.Query()
	paramVal := strings.TrimSpace(q.Get("tenant"))
	if paramVal == "" {
		paramVal = strings.TrimSpace(q.Get("tenant_id"))
	}

	if paramVal != "" {
		if t, found := tm.GetTenant(paramVal); found && t.IsActive {
			return t
		}
		if t, found := tm.GetTenantByPrefix(paramVal); found && t.IsActive {
			return t
		}
	}

	return tm.DefaultTenant()
}
