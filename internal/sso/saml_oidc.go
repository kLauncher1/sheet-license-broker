package sso

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// IdPRegistry manages multi-tenant Identity Provider configurations.
type IdPRegistry struct {
	mu      sync.RWMutex
	configs map[string]*IdPConfig // key: id
}

// NewIdPRegistry creates a concurrent-safe IdP configuration registry.
func NewIdPRegistry() *IdPRegistry {
	return &IdPRegistry{
		configs: make(map[string]*IdPConfig),
	}
}

// Register adds or updates an Identity Provider configuration.
func (r *IdPRegistry) Register(cfg IdPConfig) (*IdPConfig, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if strings.TrimSpace(cfg.ID) == "" {
		return nil, errors.New("idp id is required")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		cfg.TenantID = "default"
	}
	now := time.Now().UTC()
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = now
	}
	cfg.UpdatedAt = now
	r.configs[cfg.ID] = &cfg
	return &cfg, nil
}

// Get retrieves an IdP configuration by ID.
func (r *IdPRegistry) Get(id string) (*IdPConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.configs[id]
	if !ok {
		return nil, false
	}
	cpy := *cfg
	return &cpy, true
}

// List returns all registered IdP configurations.
func (r *IdPRegistry) List(tenantID string) []IdPConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var res []IdPConfig
	for _, cfg := range r.configs {
		if tenantID == "" || cfg.TenantID == tenantID {
			res = append(res, *cfg)
		}
	}
	return res
}

// Count returns the total number of registered IdPs.
func (r *IdPRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.configs)
}

// BuildSPMetadataXML generates standard SAML 2.0 Service Provider metadata XML.
func BuildSPMetadataXML(entityID, acsURL string) string {
	if entityID == "" {
		entityID = "urn:sheet-license-broker:sp"
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`, entityID, acsURL)
}

// Minimal XML structs for SAML Response extraction
type rawSAMLResponse struct {
	XMLName    xml.Name          `xml:"Response"`
	Issuer     string            `xml:"Issuer"`
	Assertion  rawSAMLAssertion  `xml:"Assertion"`
}

type rawSAMLAssertion struct {
	ID                  string               `xml:"ID,attr"`
	Issuer              string               `xml:"Issuer"`
	Subject             rawSAMLSubject       `xml:"Subject"`
	Conditions          rawSAMLConditions    `xml:"Conditions"`
	AttributeStatements []rawSAMLAttrStmt    `xml:"AttributeStatement"`
}

type rawSAMLSubject struct {
	NameID string `xml:"NameID"`
}

type rawSAMLConditions struct {
	NotBefore           string                 `xml:"NotBefore,attr"`
	NotOnOrAfter        string                 `xml:"NotOnOrAfter,attr"`
	AudienceRestriction rawSAMLAudienceRestrict `xml:"AudienceRestriction"`
}

type rawSAMLAudienceRestrict struct {
	Audience string `xml:"Audience"`
}

type rawSAMLAttrStmt struct {
	Attributes []rawSAMLAttribute `xml:"Attribute"`
}

type rawSAMLAttribute struct {
	Name       string   `xml:"Name,attr"`
	Values     []string `xml:"AttributeValue"`
}

// ParseSAMLResponse decodes and extracts authentication statements from a SAML 2.0 Response.
func ParseSAMLResponse(payload []byte, expectedAudience string) (*SAMLAssertion, error) {
	data := payload
	// Attempt base64 decode if payload doesn't start with '<'
	trimmed := strings.TrimSpace(string(payload))
	if !strings.HasPrefix(trimmed, "<") {
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err == nil {
			data = decoded
		}
	}

	var resp rawSAMLResponse
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse SAML XML: %w", err)
	}

	assertion := resp.Assertion
	if assertion.ID == "" {
		assertion.ID = fmt.Sprintf("saml-assert-%d", time.Now().UnixNano())
	}

	res := &SAMLAssertion{
		ID:         assertion.ID,
		Issuer:     assertion.Issuer,
		Subject:    assertion.Subject.NameID,
		Audience:   assertion.Conditions.AudienceRestriction.Audience,
		Attributes: make(map[string]string),
	}
	if res.Issuer == "" {
		res.Issuer = resp.Issuer
	}

	// Validate Conditions: Audience
	if expectedAudience != "" && res.Audience != "" && res.Audience != expectedAudience {
		return nil, fmt.Errorf("audience mismatch: got %q, expected %q", res.Audience, expectedAudience)
	}

	// Validate Conditions: Timestamps
	now := time.Now().UTC()
	if assertion.Conditions.NotBefore != "" {
		if t, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore); err == nil {
			res.NotBefore = t
			if now.Before(t.Add(-1 * time.Minute)) { // 1 min clock drift
				return nil, errors.New("SAML assertion is not yet valid")
			}
		}
	}
	if assertion.Conditions.NotOnOrAfter != "" {
		if t, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter); err == nil {
			res.NotOnOrAfter = t
			if now.After(t.Add(1 * time.Minute)) {
				return nil, errors.New("SAML assertion has expired")
			}
		}
	}

	// Extract attributes
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				val := attr.Values[0]
				res.Attributes[attr.Name] = val
				nameLower := strings.ToLower(attr.Name)
				if strings.Contains(nameLower, "email") || nameLower == "mail" {
					res.Email = val
				} else if strings.Contains(nameLower, "role") || nameLower == "roles" {
					res.Role = val
				} else if strings.Contains(nameLower, "displayname") || strings.Contains(nameLower, "name") {
					res.Name = val
				}
			}
		}
	}

	if res.Email == "" && strings.Contains(res.Subject, "@") {
		res.Email = res.Subject
	}

	return res, nil
}

// ValidateOIDCClaims verifies standard OpenID Connect ID token claims.
func ValidateOIDCClaims(claimsJSON []byte, expectedIssuer, expectedAudience string) (*OIDCClaims, error) {
	var claims OIDCClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid OIDC claims JSON: %w", err)
	}

	if claims.Sub == "" {
		return nil, errors.New("missing sub claim in OIDC token")
	}

	now := time.Now().UTC().Unix()
	if claims.Exp > 0 && now > claims.Exp+60 {
		return nil, errors.New("OIDC token has expired")
	}

	if expectedIssuer != "" && claims.Iss != "" && claims.Iss != expectedIssuer {
		return nil, fmt.Errorf("OIDC issuer mismatch: got %q, expected %q", claims.Iss, expectedIssuer)
	}

	if expectedAudience != "" && claims.Aud != "" && claims.Aud != expectedAudience {
		return nil, fmt.Errorf("OIDC audience mismatch: got %q, expected %q", claims.Aud, expectedAudience)
	}

	if claims.TenantID == "" {
		claims.TenantID = "default"
	}

	return &claims, nil
}
