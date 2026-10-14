package replication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/auth"
	"github.com/kLauncher1/sheet-license-broker/internal/db"
	"github.com/kLauncher1/sheet-license-broker/internal/gas"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
)

func TestMergeLicensesCollisionFree(t *testing.T) {
	now := time.Now()
	later := now.Add(48 * time.Hour)

	primary := []license.License{
		{
			LicenseKey: "LIC-001",
			BoundHWID:  "",
			ExpiresAt:  now,
			Status:     "active",
			MaxDevices: 1,
		},
		{
			LicenseKey: "LIC-002",
			BoundHWID:  "HWID-ORIGINAL",
			Status:     "active",
		},
		{
			LicenseKey: "LIC-003",
			Status:     "revoked", // Revoked on primary
		},
	}

	standby := []license.License{
		{
			LicenseKey: "LIC-001",
			BoundHWID:  "HWID-BOUND-ON-STANDBY",
			ExpiresAt:  later,
			Status:     "active",
			MaxDevices: 2,
		},
		{
			LicenseKey: "LIC-002",
			Status:     "revoked", // Revoked on standby
		},
		{
			LicenseKey: "LIC-004", // New key on standby
			BoundHWID:  "HWID-NEW",
			ExpiresAt:  later,
			Status:     "active",
		},
	}

	merged, conflicts := MergeLicenses(primary, standby)

	if len(merged) != 4 {
		t.Fatalf("expected 4 merged licenses, got %d", len(merged))
	}
	if conflicts < 2 {
		t.Errorf("expected at least 2 resolved conflicts, got %d", conflicts)
	}

	lookup := make(map[string]license.License)
	for _, l := range merged {
		lookup[l.LicenseKey] = l
	}

	// Invariant 1: Bound HWID wins over unbound
	if lookup["LIC-001"].BoundHWID != "HWID-BOUND-ON-STANDBY" {
		t.Errorf("expected LIC-001 to adopt bound HWID, got %s", lookup["LIC-001"].BoundHWID)
	}
	if !lookup["LIC-001"].ExpiresAt.Equal(later) {
		t.Errorf("expected LIC-001 to adopt later expiration date")
	}

	// Invariant 2: Revocation on EITHER sheet wins
	if lookup["LIC-002"].Status != "revoked" {
		t.Errorf("expected LIC-002 to be revoked due to standby revocation")
	}
	if lookup["LIC-003"].Status != "revoked" {
		t.Errorf("expected LIC-003 to remain revoked")
	}

	// Invariant 3: New key present
	if lookup["LIC-004"].BoundHWID != "HWID-NEW" {
		t.Errorf("expected LIC-004 from standby to be included")
	}
}

func TestMergeBlacklistUnion(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-1 * time.Hour)

	primary := []license.BlacklistEntry{
		{Type: "device", Target: "HWID-A", Reason: "Tamper attempt", CreatedAt: now},
		{Type: "license", Target: "LIC-B", Reason: "Manual revoke", CreatedAt: now},
	}
	standby := []license.BlacklistEntry{
		{Type: "device", Target: "hwid-a", Reason: "Tamper attempt detailed log", CreatedAt: earlier},
		{Type: "device", Target: "HWID-C", Reason: "Brute force ban", CreatedAt: now},
	}

	merged, conflicts := MergeBlacklist(primary, standby)
	if len(merged) != 3 {
		t.Fatalf("expected 3 union-merged blacklist entries, got %d", len(merged))
	}
	if conflicts != 1 {
		t.Errorf("expected 1 conflict resolution for detailed reason, got %d", conflicts)
	}

	foundC := false
	for _, e := range merged {
		if e.Target == "HWID-C" {
			foundC = true
		}
	}
	if !foundC {
		t.Errorf("expected HWID-C in merged blacklist")
	}
}

func TestMergeUsersAndKV(t *testing.T) {
	t1 := time.Now().Add(-10 * time.Minute)
	t2 := time.Now()

	pUsers := []auth.User{{Username: "admin", PasswordHash: "h1", CreatedAt: t1}}
	sUsers := []auth.User{
		{Username: "admin", PasswordHash: "h2", CreatedAt: t2},
		{Username: "operator", PasswordHash: "h3", CreatedAt: t1},
	}

	mergedUsers, uConflicts := MergeUsers(pUsers, sUsers)
	if len(mergedUsers) != 2 {
		t.Fatalf("expected 2 users, got %d", len(mergedUsers))
	}
	if uConflicts != 1 {
		t.Errorf("expected 1 user conflict, got %d", uConflicts)
	}

	pDocs := []db.Document{{Collection: "settings", DocID: "theme", Payload: "dark", UpdatedAt: t1}}
	sDocs := []db.Document{
		{Collection: "settings", DocID: "theme", Payload: "emerald", UpdatedAt: t2},
		{Collection: "settings", DocID: "banner", Payload: "welcome", UpdatedAt: t1},
	}

	mergedDocs, dConflicts := MergeKV(pDocs, sDocs)
	if len(mergedDocs) != 2 {
		t.Fatalf("expected 2 docs, got %d", len(mergedDocs))
	}
	if dConflicts != 1 {
		t.Errorf("expected 1 doc conflict, got %d", dConflicts)
	}
}

func TestHAManagerFailoverAndRoleSwitch(t *testing.T) {
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","action":"ping"}`))
	}))
	defer primaryServer.Close()

	standbyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","action":"ping"}`))
	}))
	defer standbyServer.Close()

	pClient, _ := gas.NewClient(gas.ClientConfig{WebAppURL: primaryServer.URL})
	sClient, _ := gas.NewClient(gas.ClientConfig{WebAppURL: standbyServer.URL})

	mgr := NewHAManager(HAConfig{
		PrimaryClient: pClient,
		StandbyClient: sClient,
		AutoFailover:  true,
	})

	if mgr.ActiveClient().WebAppURL() != primaryServer.URL {
		t.Errorf("expected primary as active client")
	}

	st := mgr.CheckHealth(context.Background())
	if !st.Primary.Healthy || !st.Standby.Healthy {
		t.Errorf("expected both healthy, got primary=%v, standby=%v", st.Primary.Healthy, st.Standby.Healthy)
	}

	// Force failover to standby
	err := mgr.ForceFailover(RoleStandby)
	if err != nil {
		t.Fatalf("force failover failed: %v", err)
	}
	if mgr.ActiveClient().WebAppURL() != standbyServer.URL {
		t.Errorf("expected standby as active client after switch")
	}
	if mgr.StandbyClient().WebAppURL() != primaryServer.URL {
		t.Errorf("expected primary as standby client after switch")
	}

	// Switch back
	_ = mgr.ForceFailover(RolePrimary)
	if mgr.ActiveClient().WebAppURL() != primaryServer.URL {
		t.Errorf("expected primary as active client after switch back")
	}
}
