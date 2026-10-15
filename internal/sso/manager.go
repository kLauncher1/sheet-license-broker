package sso

import (
	"context"
	"time"
)

// Manager orchestrates Identity Providers, SCIM user directory, and RBAC token issuance.
type Manager struct {
	idps      *IdPRegistry
	directory *SCIMDirectory
	tokens    *TokenManager
}

// NewManager constructs an enterprise SSO and SCIM directory coordinator.
func NewManager(secretKey []byte, onProvision ProvisionHook, onDeprovision DeprovisionHook) *Manager {
	return &Manager{
		idps:      NewIdPRegistry(),
		directory: NewSCIMDirectory(onProvision, onDeprovision),
		tokens:    NewTokenManager(secretKey, 1*time.Hour),
	}
}

// IdPs returns the Identity Provider configuration registry.
func (m *Manager) IdPs() *IdPRegistry {
	return m.idps
}

// Directory returns the SCIM 2.0 user directory.
func (m *Manager) Directory() *SCIMDirectory {
	return m.directory
}

// Tokens returns the ephemeral session token manager.
func (m *Manager) Tokens() *TokenManager {
	return m.tokens
}

// Status returns a telemetry summary of SSO federation and SCIM directory status.
func (m *Manager) Status() SSOStatusSummary {
	active, deprov, seats := m.directory.Stats()
	return SSOStatusSummary{
		TotalIdPs:             m.idps.Count(),
		ActiveDirectoryUsers:  active,
		DeprovisionedUsers:    deprov,
		AllocatedLicenseSeats: seats,
		SupportedProtocols:    []string{"SAML 2.0", "OIDC 1.0", "SCIM 2.0"},
	}
}

// LoginWithSAML processes incoming SAML 2.0 assertion and returns an ephemeral session token.
func (m *Manager) LoginWithSAML(ctx context.Context, xmlData []byte, expectedAudience, tenantID string) (*SessionTokenClaims, string, error) {
	assert, err := ParseSAMLResponse(xmlData, expectedAudience)
	if err != nil {
		return nil, "", err
	}

	role := RoleUser
	if assert.Role != "" {
		role = assert.Role
	}

	claims := SessionTokenClaims{
		UserID:   assert.Subject,
		Email:    assert.Email,
		TenantID: tenantID,
		Role:     role,
		Scopes:   GetScopesForRole(role),
	}

	token, err := m.tokens.MintSessionToken(claims)
	if err != nil {
		return nil, "", err
	}

	return &claims, token, nil
}

// LoginWithOIDC processes incoming OIDC ID token claims and returns an ephemeral session token.
func (m *Manager) LoginWithOIDC(ctx context.Context, claimsJSON []byte, expectedIss, expectedAud, tenantID string) (*SessionTokenClaims, string, error) {
	oidc, err := ValidateOIDCClaims(claimsJSON, expectedIss, expectedAud)
	if err != nil {
		return nil, "", err
	}

	role := RoleUser
	if len(oidc.Roles) > 0 {
		role = oidc.Roles[0]
	}

	if oidc.TenantID != "" && (tenantID == "" || tenantID == "default") {
		tenantID = oidc.TenantID
	}

	claims := SessionTokenClaims{
		UserID:   oidc.Sub,
		Email:    oidc.Email,
		TenantID: tenantID,
		Role:     role,
		Scopes:   GetScopesForRole(role),
	}

	token, err := m.tokens.MintSessionToken(claims)
	if err != nil {
		return nil, "", err
	}

	return &claims, token, nil
}
