package tenant

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestTenantManagerRegistrationAndLookup(t *testing.T) {
	tm := NewTenantManager()

	def := tm.DefaultTenant()
	if def == nil || def.ID != "default" {
		t.Fatalf("expected default tenant with id 'default', got %+v", def)
	}

	tenant1 := &Tenant{
		ID:              "tenant-acme",
		Name:            "Acme Corp",
		NamespacePrefix: "ACME",
		HMACSecret:      "acme-secret-key-123",
		MaxLicenses:     100,
		WebhookURL:      "https://acme.example.com/webhooks",
		IsActive:        true,
	}

	created, err := tm.RegisterTenant(tenant1)
	if err != nil {
		t.Fatalf("unexpected error registering tenant: %v", err)
	}
	if created.NamespacePrefix != "ACME" {
		t.Errorf("expected prefix ACME, got %s", created.NamespacePrefix)
	}

	// Lookup by ID
	found, ok := tm.GetTenant("tenant-acme")
	if !ok || found.Name != "Acme Corp" {
		t.Errorf("failed to lookup tenant by ID: got %+v, ok=%v", found, ok)
	}

	// Lookup by Prefix
	foundPrefix, ok := tm.GetTenantByPrefix("acme")
	if !ok || foundPrefix.ID != "tenant-acme" {
		t.Errorf("failed to lookup tenant by prefix: got %+v, ok=%v", foundPrefix, ok)
	}

	// Duplicate registration rejection
	_, err = tm.RegisterTenant(tenant1)
	if err != ErrTenantAlreadyExist {
		t.Errorf("expected ErrTenantAlreadyExist for duplicate ID, got %v", err)
	}

	// Duplicate prefix rejection
	tenantDuplicatePrefix := &Tenant{
		ID:              "tenant-acme-2",
		NamespacePrefix: "ACME",
	}
	_, err = tm.RegisterTenant(tenantDuplicatePrefix)
	if err != ErrTenantAlreadyExist {
		t.Errorf("expected ErrTenantAlreadyExist for duplicate prefix, got %v", err)
	}

	// Invalid prefix rejection
	invalidPrefixTenant := &Tenant{
		ID:              "tenant-bad",
		NamespacePrefix: "INVALID_LONG_PREFIX",
	}
	_, err = tm.RegisterTenant(invalidPrefixTenant)
	if err != ErrInvalidPrefix {
		t.Errorf("expected ErrInvalidPrefix, got %v", err)
	}
}

func TestLicenseKeyFormattingAndResolution(t *testing.T) {
	tm := NewTenantManager()
	_, _ = tm.RegisterTenant(&Tenant{
		ID:              "tenant-beta",
		Name:            "Beta Labs",
		NamespacePrefix: "BETA",
		IsActive:        true,
	})

	key := tm.FormatLicenseKey("BETA")
	if len(key) == 0 {
		t.Fatalf("expected formatted key, got empty string")
	}

	prefix, isNamespaced := ParseLicenseKey(key)
	if !isNamespaced || prefix != "BETA" {
		t.Errorf("expected prefix BETA, isNamespaced=true, got prefix=%s, ok=%v", prefix, isNamespaced)
	}

	resolved := tm.ResolveTenantByKey(key)
	if resolved == nil || resolved.ID != "tenant-beta" {
		t.Errorf("expected resolved tenant 'tenant-beta', got %+v", resolved)
	}

	// Unregistered prefix should resolve to default tenant
	unregKey := "UNKNOWN-LIC-1111-2222"
	resolvedDef := tm.ResolveTenantByKey(unregKey)
	if resolvedDef == nil || resolvedDef.ID != "default" {
		t.Errorf("expected fallback to default tenant, got %+v", resolvedDef)
	}
}

func TestResolveFromRequest(t *testing.T) {
	tm := NewTenantManager()
	_, _ = tm.RegisterTenant(&Tenant{
		ID:              "tenant-gamma",
		Name:            "Gamma Inc",
		NamespacePrefix: "GAM",
		IsActive:        true,
	})

	// 1. Resolve via X-Tenant-ID Header
	reqHeader := httptest.NewRequest(http.MethodGet, "/api/licenses", nil)
	reqHeader.Header.Set("X-Tenant-ID", "tenant-gamma")
	res1 := tm.ResolveFromRequest(reqHeader)
	if res1.ID != "tenant-gamma" {
		t.Errorf("expected tenant-gamma via header, got %s", res1.ID)
	}

	// 2. Resolve via prefix in X-Tenant-ID Header
	reqHeaderPrefix := httptest.NewRequest(http.MethodGet, "/api/licenses", nil)
	reqHeaderPrefix.Header.Set("X-Tenant-ID", "GAM")
	res2 := tm.ResolveFromRequest(reqHeaderPrefix)
	if res2.ID != "tenant-gamma" {
		t.Errorf("expected tenant-gamma via prefix in header, got %s", res2.ID)
	}

	// 3. Resolve via query param 'tenant'
	reqQuery := httptest.NewRequest(http.MethodGet, "/api/licenses?tenant=tenant-gamma", nil)
	res3 := tm.ResolveFromRequest(reqQuery)
	if res3.ID != "tenant-gamma" {
		t.Errorf("expected tenant-gamma via query param, got %s", res3.ID)
	}

	// 4. Fallback to default tenant when missing
	reqEmpty := httptest.NewRequest(http.MethodGet, "/api/licenses", nil)
	resDef := tm.ResolveFromRequest(reqEmpty)
	if resDef.ID != "default" {
		t.Errorf("expected default tenant for empty request, got %s", resDef.ID)
	}
}

func TestTenantManagerConcurrency(t *testing.T) {
	tm := NewTenantManager()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			id := "tenant-" + string(rune('A'+idx))
			pref := string(rune('A' + idx)) + "X"
			_, _ = tm.RegisterTenant(&Tenant{
				ID:              id,
				NamespacePrefix: pref,
				IsActive:        true,
			})
			_ = tm.ListTenants()
			_ = tm.ResolveTenantByKey(pref + "-LIC-1234-5678")
		}()
	}

	wg.Wait()
	list := tm.ListTenants()
	if len(list) < 2 {
		t.Errorf("expected multiple tenants registered concurrently, got %d", len(list))
	}
}
