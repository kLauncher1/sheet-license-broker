package proxy

import (
	"context"
	"fmt"

	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/sso"
)

func (p *Proxy) initSSO() {
	secret := []byte("sheet-license-broker-sso-secret-key-32b")
	p.ssoManager = sso.NewManager(
		secret,
		// onProvision hook: auto-assign license seat
		func(ctx context.Context, user *sso.SCIMUser) error {
			if user.LicenseKey == "" && user.Active {
				lic, err := p.CreateTenantLicense(ctx, user.TenantID, 365, 1)
				if err == nil && lic != nil {
					user.LicenseKey = lic.LicenseKey
				}
			}
			if p.auditCollector != nil {
				p.auditCollector.Record(audit.AuditRecord{
					EventType: "SCIM_USER_PROVISIONED",
					Severity:  "INFO",
					TenantID:  user.TenantID,
					ActorIP:   "127.0.0.1",
					Details:   fmt.Sprintf("user=%s license=%s active=%v", user.UserName, user.LicenseKey, user.Active),
				})
			}
			return nil
		},
		// onDeprovision hook: auto-revoke license seat & push kill-switch
		func(ctx context.Context, user *sso.SCIMUser, reason string) error {
			if user.LicenseKey != "" {
				_ = p.RevokeLicense(ctx, user.LicenseKey, fmt.Sprintf("SCIM deprovisioned: %s", reason))
			}
			if p.auditCollector != nil {
				p.auditCollector.Record(audit.AuditRecord{
					EventType: "SCIM_USER_DEPROVISIONED",
					Severity:  "WARNING",
					TenantID:  user.TenantID,
					ActorIP:   "127.0.0.1",
					Details:   fmt.Sprintf("user=%s license=%s reason=%s", user.UserName, user.LicenseKey, reason),
				})
			}
			return nil
		},
	)
}

// SSOManager returns the SSO & SCIM directory manager.
func (p *Proxy) SSOManager() *sso.Manager {
	return p.ssoManager
}

// ProcessSAMLACS verifies SAML assertion and returns session claims and token.
func (p *Proxy) ProcessSAMLACS(ctx context.Context, xmlData []byte, expectedAud, tenantID string) (*sso.SessionTokenClaims, string, error) {
	if p.ssoManager == nil {
		return nil, "", fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.LoginWithSAML(ctx, xmlData, expectedAud, tenantID)
}

// ProcessOIDCCallback processes OIDC claims and returns session claims and token.
func (p *Proxy) ProcessOIDCCallback(ctx context.Context, claimsJSON []byte, expectedIss, expectedAud, tenantID string) (*sso.SessionTokenClaims, string, error) {
	if p.ssoManager == nil {
		return nil, "", fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.LoginWithOIDC(ctx, claimsJSON, expectedIss, expectedAud, tenantID)
}

// SCIMCreateUser provisions a new user via SCIM 2.0.
func (p *Proxy) SCIMCreateUser(ctx context.Context, u sso.SCIMUser) (*sso.SCIMUser, error) {
	if p.ssoManager == nil {
		return nil, fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.Directory().CreateUser(ctx, u)
}

// SCIMGetUser retrieves a user from SCIM directory.
func (p *Proxy) SCIMGetUser(id string) (*sso.SCIMUser, bool) {
	if p.ssoManager == nil {
		return nil, false
	}
	return p.ssoManager.Directory().GetUser(id)
}

// SCIMUpdateUser updates a SCIM user resource.
func (p *Proxy) SCIMUpdateUser(ctx context.Context, id string, u sso.SCIMUser) (*sso.SCIMUser, error) {
	if p.ssoManager == nil {
		return nil, fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.Directory().UpdateUser(ctx, id, u)
}

// SCIMDeprovisionUser deactivates a user and reclaims their license.
func (p *Proxy) SCIMDeprovisionUser(ctx context.Context, id, reason string) (*sso.SCIMUser, error) {
	if p.ssoManager == nil {
		return nil, fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.Directory().DeprovisionUser(ctx, id, reason)
}

// SCIMDeleteUser removes a user and reclaims their license.
func (p *Proxy) SCIMDeleteUser(ctx context.Context, id string) error {
	if p.ssoManager == nil {
		return fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.Directory().DeleteUser(ctx, id)
}

// SCIMListUsers lists directory users.
func (p *Proxy) SCIMListUsers(startIndex, count int, tenantID string) sso.SCIMListResponse {
	if p.ssoManager == nil {
		return sso.SCIMListResponse{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		}
	}
	return p.ssoManager.Directory().ListUsers(startIndex, count, tenantID)
}

// IssueSessionToken mints an ephemeral HMAC session token.
func (p *Proxy) IssueSessionToken(claims sso.SessionTokenClaims) (string, error) {
	if p.ssoManager == nil {
		return "", fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.Tokens().MintSessionToken(claims)
}

// IntrospectSessionToken verifies an ephemeral session token.
func (p *Proxy) IntrospectSessionToken(token string) (*sso.SessionTokenClaims, error) {
	if p.ssoManager == nil {
		return nil, fmt.Errorf("SSO manager not initialized")
	}
	return p.ssoManager.Tokens().VerifySessionToken(token)
}

// GetSSOStatus returns telemetry for SSO federation and SCIM.
func (p *Proxy) GetSSOStatus() sso.SSOStatusSummary {
	if p.ssoManager == nil {
		return sso.SSOStatusSummary{}
	}
	return p.ssoManager.Status()
}
