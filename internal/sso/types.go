package sso

import (
	"time"
)

// IdPType identifies the identity provider protocol.
type IdPType string

const (
	IdPTypeSAML2  IdPType = "saml2"
	IdPTypeOIDC   IdPType = "oidc"
	IdPTypeOAuth2 IdPType = "oauth2"
)

// IdPConfig stores identity provider federation parameters.
type IdPConfig struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Type        IdPType   `json:"type"`
	Issuer      string    `json:"issuer"`
	SSOEndpoint string    `json:"sso_endpoint"`
	EntityID    string    `json:"entity_id"`
	ClientID    string    `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	MetadataURL string    `json:"metadata_url,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SAMLAssertion represents parsed SAML 2.0 authentication statement.
type SAMLAssertion struct {
	ID           string            `json:"id"`
	Issuer       string            `json:"issuer"`
	Subject      string            `json:"subject"`
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	Role         string            `json:"role"`
	Audience     string            `json:"audience"`
	NotBefore    time.Time         `json:"not_before"`
	NotOnOrAfter time.Time         `json:"not_on_or_after"`
	Attributes   map[string]string `json:"attributes"`
}

// OIDCClaims represents decoded OpenID Connect identity claims.
type OIDCClaims struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Roles             []string `json:"roles"`
	TenantID          string   `json:"tenant_id"`
	Iss               string   `json:"iss"`
	Aud               string   `json:"aud"`
	Exp               int64    `json:"exp"`
	Iat               int64    `json:"iat"`
}

// SCIM 2.0 (RFC 7643 / RFC 7644) Models

// SCIMName represents structured person names in SCIM.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// SCIMEmail represents email addresses in SCIM.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMRole represents enterprise roles in SCIM.
type SCIMRole struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMMeta contains resource metadata per RFC 7643.
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// SCIMUser represents a SCIM 2.0 User resource.
type SCIMUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        SCIMName    `json:"name"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Roles       []SCIMRole  `json:"roles,omitempty"`
	Active      bool        `json:"active"`
	TenantID    string      `json:"tenantId,omitempty"`
	LicenseKey  string      `json:"licenseKey,omitempty"`
	Meta        SCIMMeta    `json:"meta"`
}

// SCIMListResponse represents a standard paginated collection response.
type SCIMListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []SCIMUser `json:"Resources"`
}

// SCIMError represents an RFC 7644 error response.
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

// RBAC & Ephemeral Session Tokens

// Standard Role definitions
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
	RoleUser     = "user"
)

// Standard Permission Scopes
const (
	ScopeLicenseRead   = "license:read"
	ScopeLicenseWrite  = "license:write"
	ScopeLicenseRevoke = "license:revoke"
	ScopeAuditRead     = "audit:read"
	ScopeTenantManage  = "tenant:manage"
	ScopeSSOManage     = "sso:manage"
	ScopeSCIMManage    = "scim:manage"
)

// SessionTokenClaims contains validated ephemeral session token claims.
type SessionTokenClaims struct {
	SessionID string   `json:"session_id"`
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	TenantID  string   `json:"tenant_id"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// SSOStatusSummary provides real-time telemetry on SSO federation and SCIM.
type SSOStatusSummary struct {
	TotalIdPs              int      `json:"total_idps"`
	ActiveDirectoryUsers   int      `json:"active_directory_users"`
	DeprovisionedUsers     int      `json:"deprovisioned_users"`
	AllocatedLicenseSeats  int      `json:"allocated_license_seats"`
	SupportedProtocols     []string `json:"supported_protocols"`
}
