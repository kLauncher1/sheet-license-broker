package license

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// License represents an entitlement row in Google Sheets.
type License struct {
	LicenseKey string    `json:"license_key"`
	BoundHWID  string    `json:"bound_hwid"`
	MaxDevices int       `json:"max_devices"`
	Status     string    `json:"status"`
	Tier       string    `json:"tier"`
	Features   []string  `json:"features,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// Manager orchestrates license issuance, device-locking checks, and revocations.
type Manager struct {
	mu        sync.RWMutex
	licenses  map[string]*License
	blacklist *BlacklistManager
}

// NewManager initializes the license manager.
func NewManager() *Manager {
	return &Manager{
		licenses:  make(map[string]*License),
		blacklist: NewBlacklistManager(),
	}
}

// Blacklist returns the attached blacklist manager.
func (m *Manager) Blacklist() *BlacklistManager {
	return m.blacklist
}

// GenerateKey produces formatted license strings (e.g., KEY-A1B2-C3D4-E5F6).
func GenerateKey() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	hexStr := strings.ToUpper(hex.EncodeToString(b))
	return fmt.Sprintf("KEY-%s-%s-%s", hexStr[0:4], hexStr[4:8], hexStr[8:12])
}

// CreateLicense registers a new license key with expiration and default pro tier.
func (m *Manager) CreateLicense(daysValid, maxDevices int) *License {
	return m.CreateLicenseWithTier(daysValid, maxDevices, "pro", nil)
}

// CreateLicenseWithTier registers a new license key with custom tier and feature tags.
func (m *Manager) CreateLicenseWithTier(daysValid, maxDevices int, tier string, features []string) *License {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := GenerateKey()
	now := time.Now().UTC()
	if tier == "" {
		tier = "pro"
	}
	lic := &License{
		LicenseKey: key,
		BoundHWID:  "",
		MaxDevices: maxDevices,
		Status:     "ACTIVE",
		Tier:       strings.ToLower(strings.TrimSpace(tier)),
		Features:   features,
		ExpiresAt:  now.Add(time.Duration(daysValid) * 24 * time.Hour),
		CreatedAt:  now,
	}

	m.licenses[key] = lic
	return lic
}

// PutLicense registers or updates an existing license record.
func (m *Manager) PutLicense(lic *License) {
	if lic == nil || lic.LicenseKey == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.licenses[strings.ToUpper(strings.TrimSpace(lic.LicenseKey))] = lic
}

// RevokeLicense marks a license as REVOKED and registers it in the blacklist.
func (m *Manager) RevokeLicense(key, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	lic, exists := m.licenses[normKey]
	if exists {
		lic.Status = "REVOKED"
	}

	m.blacklist.Add(BlacklistTypeLicense, normKey, reason)
	return nil
}

// VerifyAndBind checks validity and locks the license to the machine's HWID.
func (m *Manager) VerifyAndBind(key, hwid string) (*License, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normKey := strings.ToUpper(strings.TrimSpace(key))
	normHWID := strings.TrimSpace(hwid)

	// Check blacklist first
	if err := m.blacklist.Check(normKey, normHWID); err != nil {
		return nil, err
	}

	lic, exists := m.licenses[normKey]
	if !exists {
		return nil, errors.New("license key not found")
	}

	if lic.Status != "ACTIVE" {
		return nil, fmt.Errorf("license status is %s", lic.Status)
	}

	if time.Now().UTC().After(lic.ExpiresAt) {
		lic.Status = "EXPIRED"
		return nil, errors.New("license has expired")
	}

	// First-time hardware lock
	if lic.BoundHWID == "" && normHWID != "" {
		lic.BoundHWID = normHWID
		return lic, nil
	}

	// Device mismatch verification
	if lic.BoundHWID != "" && normHWID != "" && lic.BoundHWID != normHWID {
		return nil, errors.New("hardware mismatch: license is bound to another machine")
	}

	return lic, nil
}

// ListLicenses returns all licenses.
func (m *Manager) ListLicenses() []License {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]License, 0, len(m.licenses))
	for _, l := range m.licenses {
		res = append(res, *l)
	}
	return res
}
