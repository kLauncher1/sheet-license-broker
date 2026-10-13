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
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// Manager orchestrates license issuance and device-locking checks.
type Manager struct {
	mu       sync.RWMutex
	licenses map[string]*License
}

// NewManager initializes the license manager.
func NewManager() *Manager {
	return &Manager{
		licenses: make(map[string]*License),
	}
}

// GenerateKey produces formatted license strings (e.g., KEY-A1B2-C3D4-E5F6).
func GenerateKey() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	hexStr := strings.ToUpper(hex.EncodeToString(b))
	return fmt.Sprintf("KEY-%s-%s-%s", hexStr[0:4], hexStr[4:8], hexStr[8:12])
}

// CreateLicense registers a new license key with expiration.
func (m *Manager) CreateLicense(daysValid, maxDevices int) *License {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := GenerateKey()
	now := time.Now().UTC()
	lic := &License{
		LicenseKey: key,
		BoundHWID:  "",
		MaxDevices: maxDevices,
		Status:     "ACTIVE",
		ExpiresAt:  now.Add(time.Duration(daysValid) * 24 * time.Hour),
		CreatedAt:  now,
	}

	m.licenses[key] = lic
	return lic
}

// VerifyAndBind checks validity and locks the license to the machine's HWID.
func (m *Manager) VerifyAndBind(key, hwid string) (*License, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lic, exists := m.licenses[key]
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
	if lic.BoundHWID == "" && hwid != "" {
		lic.BoundHWID = hwid
		return lic, nil
	}

	// Device mismatch verification
	if lic.BoundHWID != "" && hwid != "" && lic.BoundHWID != hwid {
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
