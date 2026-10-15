package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/sso"
)

func TestProxySSOAndSCIMWorkflow(t *testing.T) {
	ctx := context.Background()
	p, err := NewProxy(ProxyConfig{
		OfflineMode: true,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	if p.SSOManager() == nil {
		t.Fatal("expected ssoManager to be initialized")
	}

	// 1. SCIM User Provisioning: should auto-generate license seat
	scimUser, err := p.SCIMCreateUser(ctx, sso.SCIMUser{
		UserName:    "sam@enterprise.corp",
		DisplayName: "Sam Security",
		Active:      true,
		TenantID:    "corp",
		Roles:       []sso.SCIMRole{{Value: "operator", Primary: true}},
	})
	if err != nil {
		t.Fatalf("failed to create SCIM user via proxy: %v", err)
	}
	if scimUser.LicenseKey == "" {
		t.Errorf("expected auto-assigned license seat for provisioned SCIM user")
	}

	// Verify license exists in local license manager
	licRes, err := p.VerifyLicense(ctx, scimUser.LicenseKey, "")
	if err != nil || !licRes.Valid {
		t.Errorf("expected auto-assigned license to be valid: %v", err)
	}

	// 2. SCIM Get and List Users
	userRetrieved, ok := p.SCIMGetUser(scimUser.ID)
	if !ok || userRetrieved.UserName != "sam@enterprise.corp" {
		t.Errorf("failed to retrieve SCIM user via proxy: %+v", userRetrieved)
	}

	userList := p.SCIMListUsers(1, 10, "corp")
	if userList.TotalResults != 1 || len(userList.Resources) != 1 {
		t.Errorf("expected 1 user in list, got %+v", userList)
	}

	// 3. Ephemeral Session Token Minting and Introspection
	token, err := p.IssueSessionToken(sso.SessionTokenClaims{
		UserID:   scimUser.ID,
		Email:    scimUser.UserName,
		TenantID: scimUser.TenantID,
		Role:     sso.RoleOperator,
	})
	if err != nil {
		t.Fatalf("failed to issue session token: %v", err)
	}

	claims, err := p.IntrospectSessionToken(token)
	if err != nil {
		t.Fatalf("failed to introspect session token: %v", err)
	}
	if claims.Email != "sam@enterprise.corp" || claims.Role != sso.RoleOperator {
		t.Errorf("mismatched introspected claims: %+v", claims)
	}

	// 4. SCIM Deprovisioning: should automatically revoke the assigned license
	deprovisioned, err := p.SCIMDeprovisionUser(ctx, scimUser.ID, "employment terminated")
	if err != nil {
		t.Fatalf("failed to deprovision SCIM user: %v", err)
	}
	if deprovisioned.Active {
		t.Errorf("expected user to be inactive")
	}

	// Verify license has been revoked!
	licResAfter, _ := p.VerifyLicense(ctx, scimUser.LicenseKey, "")
	if licResAfter != nil && licResAfter.Valid {
		t.Errorf("expected license %s to be revoked after deprovisioning", scimUser.LicenseKey)
	}

	// 5. SSO Telemetry Status
	status := p.GetSSOStatus()
	if status.ActiveDirectoryUsers != 0 || status.DeprovisionedUsers != 1 {
		t.Errorf("unexpected SSO status: %+v", status)
	}
}

func TestProxyOIDCAndSAMLLogin(t *testing.T) {
	ctx := context.Background()
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	// Test OIDC callback via proxy
	now := time.Now().UTC().Unix()
	oidcClaims := sso.OIDCClaims{
		Sub:      "usr-oidc-1",
		Email:    "oidc-user@cloud.com",
		Roles:    []string{"admin"},
		TenantID: "default",
		Iss:      "https://idp.cloud.com",
		Aud:      "broker-client-id",
		Exp:      now + 1800,
		Iat:      now,
	}
	claimsBytes, _ := json.Marshal(oidcClaims)

	claims, token, err := p.ProcessOIDCCallback(ctx, claimsBytes, "https://idp.cloud.com", "broker-client-id", "default")
	if err != nil {
		t.Fatalf("failed to process OIDC callback: %v", err)
	}
	if claims.Email != "oidc-user@cloud.com" || !strings.HasPrefix(token, "sso.") {
		t.Errorf("unexpected OIDC claims or token: %+v, token=%s", claims, token)
	}

	// Test SAML ACS via proxy
	notBefore := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	notOnOrAfter := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	samlXML := fmt.Sprintf(`<?xml version="1.0"?>
<Response>
  <Assertion ID="saml-test-1">
    <Issuer>https://saml.idp.com</Issuer>
    <Subject><NameID>saml-user@corp.com</NameID></Subject>
    <Conditions NotBefore="%s" NotOnOrAfter="%s">
      <AudienceRestriction><Audience>urn:sheet-license-broker:sp</Audience></AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="role"><AttributeValue>operator</AttributeValue></Attribute>
    </AttributeStatement>
  </Assertion>
</Response>`, notBefore, notOnOrAfter)

	samlClaims, samlToken, err := p.ProcessSAMLACS(ctx, []byte(samlXML), "urn:sheet-license-broker:sp", "default")
	if err != nil {
		t.Fatalf("failed to process SAML ACS: %v", err)
	}
	if samlClaims.Email != "saml-user@corp.com" || !strings.HasPrefix(samlToken, "sso.") {
		t.Errorf("unexpected SAML claims or token: %+v", samlClaims)
	}
}
