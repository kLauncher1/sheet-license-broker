package replication

import (
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/auth"
	"github.com/kLauncher1/sheet-license-broker/internal/db"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
)

// ReconciliationReport summarizes the results of a collision-free bidirectional dataset merge.
type ReconciliationReport struct {
	Timestamp         time.Time `json:"timestamp"`
	PrimaryLicenses   int       `json:"primary_licenses"`
	StandbyLicenses   int       `json:"standby_licenses"`
	MergedLicenses    int       `json:"merged_licenses"`
	PrimaryBlacklist  int       `json:"primary_blacklist"`
	StandbyBlacklist  int       `json:"standby_blacklist"`
	MergedBlacklist   int       `json:"merged_blacklist"`
	PrimaryUsers      int       `json:"primary_users"`
	StandbyUsers      int       `json:"standby_users"`
	MergedUsers       int       `json:"merged_users"`
	PrimaryDocs       int       `json:"primary_docs"`
	StandbyDocs       int       `json:"standby_docs"`
	MergedDocs        int       `json:"merged_docs"`
	ConflictsResolved int       `json:"conflicts_resolved"`
	SyncedToPrimary   bool      `json:"synced_to_primary"`
	SyncedToStandby   bool      `json:"synced_to_standby"`
}

// MergeLicenses performs a deterministic, collision-free merge between primary and standby license sets.
// Security invariant: Revocations always win. Bound HWIDs win over unbound HWIDs. Later expiration wins.
func MergeLicenses(primary, standby []license.License) ([]license.License, int) {
	mergedMap := make(map[string]license.License)
	conflicts := 0

	for _, lic := range primary {
		key := strings.ToUpper(strings.TrimSpace(lic.LicenseKey))
		if key != "" {
			mergedMap[key] = lic
		}
	}

	for _, sLic := range standby {
		key := strings.ToUpper(strings.TrimSpace(sLic.LicenseKey))
		if key == "" {
			continue
		}

		pLic, exists := mergedMap[key]
		if !exists {
			mergedMap[key] = sLic
			continue
		}

		// Conflict detected - resolve deterministically
		resolved := pLic
		conflictFound := false

		// 1. Revocation rule (Revocation ALWAYS takes precedence)
		if strings.ToLower(sLic.Status) == "revoked" && strings.ToLower(pLic.Status) != "revoked" {
			resolved.Status = "revoked"
			conflictFound = true
		}

		// 2. HWID Device binding (Bound wins over unbound)
		if resolved.BoundHWID == "" && sLic.BoundHWID != "" {
			resolved.BoundHWID = sLic.BoundHWID
			conflictFound = true
		}

		// 3. Expiry date (Extended validity wins unless revoked)
		if sLic.ExpiresAt.After(resolved.ExpiresAt) {
			resolved.ExpiresAt = sLic.ExpiresAt
			conflictFound = true
		}

		// 4. Max devices
		if sLic.MaxDevices > resolved.MaxDevices {
			resolved.MaxDevices = sLic.MaxDevices
			conflictFound = true
		}

		if conflictFound {
			conflicts++
		}
		mergedMap[key] = resolved
	}

	res := make([]license.License, 0, len(mergedMap))
	for _, lic := range mergedMap {
		res = append(res, lic)
	}
	return res, conflicts
}

// MergeBlacklist performs a union merge on device bans and revoked license entries.
// Security invariant: A ban in either sheet remains banned.
func MergeBlacklist(primary, standby []license.BlacklistEntry) ([]license.BlacklistEntry, int) {
	mergedMap := make(map[string]license.BlacklistEntry)
	conflicts := 0

	for _, entry := range primary {
		key := strings.ToUpper(strings.TrimSpace(entry.Target))
		if key != "" {
			mergedMap[key] = entry
		}
	}

	for _, sEntry := range standby {
		key := strings.ToUpper(strings.TrimSpace(sEntry.Target))
		if key == "" {
			continue
		}

		pEntry, exists := mergedMap[key]
		if !exists {
			mergedMap[key] = sEntry
			continue
		}

		// If entry exists in both, keep the earliest ban timestamp or richer reason
		resolved := pEntry
		if sEntry.CreatedAt.Before(pEntry.CreatedAt) && !sEntry.CreatedAt.IsZero() {
			resolved.CreatedAt = sEntry.CreatedAt
		}
		if len(sEntry.Reason) > len(pEntry.Reason) {
			resolved.Reason = sEntry.Reason
			conflicts++
		}
		mergedMap[key] = resolved
	}

	res := make([]license.BlacklistEntry, 0, len(mergedMap))
	for _, e := range mergedMap {
		res = append(res, e)
	}
	return res, conflicts
}

// MergeUsers merges user account databases. Later created user records win.
func MergeUsers(primary, standby []auth.User) ([]auth.User, int) {
	mergedMap := make(map[string]auth.User)
	conflicts := 0

	for _, u := range primary {
		uname := strings.ToLower(strings.TrimSpace(u.Username))
		if uname != "" {
			mergedMap[uname] = u
		}
	}

	for _, sUser := range standby {
		uname := strings.ToLower(strings.TrimSpace(sUser.Username))
		if uname == "" {
			continue
		}

		pUser, exists := mergedMap[uname]
		if !exists {
			mergedMap[uname] = sUser
			continue
		}

		// Conflict: keep the one with the later timestamp, or primary by default
		if sUser.CreatedAt.After(pUser.CreatedAt) {
			mergedMap[uname] = sUser
			conflicts++
		}
	}

	res := make([]auth.User, 0, len(mergedMap))
	for _, u := range mergedMap {
		res = append(res, u)
	}
	return res, conflicts
}

// MergeKV merges document key-value stores with Last-Write-Wins (LWW) based on timestamp.
func MergeKV(primary, standby []db.Document) ([]db.Document, int) {
	mergedMap := make(map[string]db.Document)
	conflicts := 0

	for _, doc := range primary {
		key := doc.Collection + ":" + doc.DocID
		mergedMap[key] = doc
	}

	for _, sDoc := range standby {
		key := sDoc.Collection + ":" + sDoc.DocID
		pDoc, exists := mergedMap[key]
		if !exists {
			mergedMap[key] = sDoc
			continue
		}

		if sDoc.UpdatedAt.After(pDoc.UpdatedAt) {
			mergedMap[key] = sDoc
			conflicts++
		}
	}

	res := make([]db.Document, 0, len(mergedMap))
	for _, d := range mergedMap {
		res = append(res, d)
	}
	return res, conflicts
}
