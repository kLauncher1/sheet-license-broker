package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSPMetadataXMLGeneration(t *testing.T) {
	xmlStr := BuildSPMetadataXML("https://broker.example.com/sp", "https://broker.example.com/api/sso/saml/acs")
	if !strings.Contains(xmlStr, `entityID="https://broker.example.com/sp"`) {
		t.Fatalf("expected entityID in metadata XML, got: %s", xmlStr)
	}
	if !strings.Contains(xmlStr, `Location="https://broker.example.com/api/sso/saml/acs"`) {
		t.Fatalf("expected ACS location in metadata XML, got: %s", xmlStr)
	}
}

func TestSAMLResponseParsing(t *testing.T) {
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute).Format(time.RFC3339)
	notOnOrAfter := now.Add(5 * time.Minute).Format(time.RFC3339)

	validSAMLXML := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Assertion ID="assert-12345">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@enterprise.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>https://broker.example.com/sp</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>alice@enterprise.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>operator</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="displayName">
        <saml:AttributeValue>Alice Johnson</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`, notBefore, notOnOrAfter)

	// 1. Valid SAML Response
	assert, err := ParseSAMLResponse([]byte(validSAMLXML), "https://broker.example.com/sp")
	if err != nil {
		t.Fatalf("unexpected error parsing valid SAML: %v", err)
	}
	if assert.Subject != "alice@enterprise.com" {
		t.Errorf("expected subject alice@enterprise.com, got %q", assert.Subject)
	}
	if assert.Email != "alice@enterprise.com" {
		t.Errorf("expected email alice@enterprise.com, got %q", assert.Email)
	}
	if assert.Role != "operator" {
		t.Errorf("expected role operator, got %q", assert.Role)
	}
	if assert.Name != "Alice Johnson" {
		t.Errorf("expected name Alice Johnson, got %q", assert.Name)
	}

	// 2. Audience Mismatch
	_, err = ParseSAMLResponse([]byte(validSAMLXML), "https://wrong-audience.com")
	if err == nil || !strings.Contains(err.Error(), "audience mismatch") {
		t.Fatalf("expected audience mismatch error, got: %v", err)
	}

	// 3. Expired SAML Assertion
	expiredXML := fmt.Sprintf(`<?xml version="1.0"?>
<Response>
  <Assertion ID="assert-expired">
    <Subject><NameID>bob@enterprise.com</NameID></Subject>
    <Conditions NotBefore="%s" NotOnOrAfter="%s">
      <AudienceRestriction><Audience>https://broker.example.com/sp</Audience></AudienceRestriction>
    </Conditions>
  </Assertion>
</Response>`, now.Add(-10*time.Minute).Format(time.RFC3339), now.Add(-2*time.Minute).Format(time.RFC3339))

	_, err = ParseSAMLResponse([]byte(expiredXML), "https://broker.example.com/sp")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired assertion error, got: %v", err)
	}
}

func TestOIDCClaimsValidation(t *testing.T) {
	now := time.Now().UTC().Unix()
	validClaims := OIDCClaims{
		Sub:      "usr-9876",
		Email:    "charlie@enterprise.com",
		Roles:    []string{"admin"},
		TenantID: "tenant-acme",
		Iss:      "https://login.microsoftonline.com/common/v2.0",
		Aud:      "client-broker-app",
		Exp:      now + 3600,
		Iat:      now,
	}
	claimsBytes, _ := json.Marshal(validClaims)

	// 1. Valid OIDC
	validated, err := ValidateOIDCClaims(claimsBytes, "https://login.microsoftonline.com/common/v2.0", "client-broker-app")
	if err != nil {
		t.Fatalf("unexpected error validating OIDC claims: %v", err)
	}
	if validated.Sub != "usr-9876" || validated.Email != "charlie@enterprise.com" {
		t.Errorf("mismatched validated claims: %+v", validated)
	}

	// 2. Expired OIDC
	expiredClaims := validClaims
	expiredClaims.Exp = now - 120
	expBytes, _ := json.Marshal(expiredClaims)
	_, err = ValidateOIDCClaims(expBytes, "https://login.microsoftonline.com/common/v2.0", "client-broker-app")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired OIDC error, got: %v", err)
	}

	// 3. Mismatched Issuer
	_, err = ValidateOIDCClaims(claimsBytes, "https://accounts.google.com", "client-broker-app")
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("expected issuer mismatch error, got: %v", err)
	}
}

func TestSCIMUserLifecycleAndDeprovisionHook(t *testing.T) {
	ctx := context.Background()
	var provisionedEvents []string
	var deprovisionedEvents []string

	onProvision := func(ctx context.Context, u *SCIMUser) error {
		provisionedEvents = append(provisionedEvents, u.UserName)
		u.LicenseKey = fmt.Sprintf("LIC-%s", u.UserName)
		return nil
	}
	onDeprovision := func(ctx context.Context, u *SCIMUser, reason string) error {
		deprovisionedEvents = append(deprovisionedEvents, fmt.Sprintf("%s:%s", u.UserName, reason))
		return nil
	}

	dir := NewSCIMDirectory(onProvision, onDeprovision)

	// 1. Create User (Provisioning)
	user, err := dir.CreateUser(ctx, SCIMUser{
		UserName:    "dave@enterprise.com",
		DisplayName: "Dave Engineer",
		Active:      true,
		TenantID:    "acme",
		Roles:       []SCIMRole{{Value: "operator", Primary: true}},
	})
	if err != nil {
		t.Fatalf("failed to create SCIM user: %v", err)
	}
	if user.ID == "" || !user.Active {
		t.Errorf("unexpected user creation state: %+v", user)
	}
	if len(provisionedEvents) != 1 || provisionedEvents[0] != "dave@enterprise.com" {
		t.Errorf("expected provision hook invocation, got %v", provisionedEvents)
	}

	// 2. Conflict on duplicate userName
	_, err = dir.CreateUser(ctx, SCIMUser{
		UserName: "Dave@Enterprise.com", // Case-insensitive collision check
		Active:   true,
	})
	if err == nil {
		t.Fatal("expected collision error on duplicate username, got nil")
	}

	// 3. Read User
	byID, ok := dir.GetUser(user.ID)
	if !ok || byID.UserName != "dave@enterprise.com" {
		t.Errorf("failed to retrieve user by ID: %+v", byID)
	}
	byName, ok := dir.GetUserByUserName("dave@enterprise.com")
	if !ok || byName.ID != user.ID {
		t.Errorf("failed to retrieve user by username: %+v", byName)
	}

	// 4. Update User: Deactivate triggers deprovision hook
	user.Active = false
	updated, err := dir.UpdateUser(ctx, user.ID, *user)
	if err != nil {
		t.Fatalf("failed to update SCIM user: %v", err)
	}
	if updated.Active {
		t.Errorf("expected user to be inactive")
	}
	if len(deprovisionedEvents) != 1 || !strings.Contains(deprovisionedEvents[0], "dave@enterprise.com") {
		t.Errorf("expected deprovision hook invocation, got %v", deprovisionedEvents)
	}

	// 5. Delete User
	err = dir.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}
	if _, ok := dir.GetUser(user.ID); ok {
		t.Errorf("user should no longer exist after delete")
	}
}

func TestSCIMListAndServiceProviderConfig(t *testing.T) {
	ctx := context.Background()
	dir := NewSCIMDirectory(nil, nil)

	for i := 1; i <= 5; i++ {
		_, _ = dir.CreateUser(ctx, SCIMUser{
			UserName: fmt.Sprintf("user%d@example.com", i),
			Active:   true,
			TenantID: "default",
		})
	}

	list := dir.ListUsers(1, 3, "default")
	if list.TotalResults != 5 {
		t.Errorf("expected 5 total results, got %d", list.TotalResults)
	}
	if len(list.Resources) != 3 {
		t.Errorf("expected 3 paginated resources, got %d", len(list.Resources))
	}

	cfg := BuildServiceProviderConfig()
	if cfg["patch"].(map[string]bool)["supported"] != true {
		t.Errorf("expected patch support true")
	}
}

func TestRBACAndEphemeralSessionTokens(t *testing.T) {
	tm := NewTokenManager([]byte("super-secret-hmac-key-for-sso-tokens!"), 1*time.Hour)

	claims := SessionTokenClaims{
		UserID:   "usr-555",
		Email:    "lead@enterprise.com",
		TenantID: "tenant-1",
		Role:     RoleAdmin,
	}

	// 1. Mint Token
	token, err := tm.MintSessionToken(claims)
	if err != nil {
		t.Fatalf("failed to mint session token: %v", err)
	}
	if !strings.HasPrefix(token, "sso.") {
		t.Fatalf("token missing expected sso. prefix: %s", token)
	}

	// 2. Verify Valid Token
	verified, err := tm.VerifySessionToken(token)
	if err != nil {
		t.Fatalf("failed to verify valid session token: %v", err)
	}
	if verified.UserID != "usr-555" || verified.Role != RoleAdmin {
		t.Errorf("mismatched verified claims: %+v", verified)
	}

	// Check Scopes
	if !HasPermission(verified.Role, verified.Scopes, ScopeLicenseRevoke) {
		t.Errorf("admin should have license:revoke permission")
	}
	if !HasPermission(RoleUser, nil, ScopeLicenseRead) {
		t.Errorf("user should have license:read permission")
	}
	if HasPermission(RoleUser, nil, ScopeLicenseRevoke) {
		t.Errorf("standard user should NOT have license:revoke permission")
	}

	// 3. Tampered Token Rejection
	tampered := token[:len(token)-3] + "xyz"
	_, err = tm.VerifySessionToken(tampered)
	if err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("expected tampered token error, got: %v", err)
	}

	// 4. Expired Token Rejection
	expiredClaims := claims
	expiredClaims.ExpiresAt = time.Now().UTC().Unix() - 10
	expiredToken, _ := tm.MintSessionToken(expiredClaims)
	_, err = tm.VerifySessionToken(expiredToken)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired token error, got: %v", err)
	}
}

func TestSCIMConcurrentProvisioning(t *testing.T) {
	ctx := context.Background()
	dir := NewSCIMDirectory(nil, nil)

	var wg sync.WaitGroup
	workers := 25

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := dir.CreateUser(ctx, SCIMUser{
				UserName: fmt.Sprintf("worker%d@company.internal", idx),
				Active:   true,
				TenantID: "perf-test",
			})
			if err != nil {
				t.Errorf("worker %d failed to create user: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	active, _, seats := dir.Stats()
	if active != workers || seats != workers {
		t.Errorf("expected %d active users, got %d (seats: %d)", workers, active, seats)
	}
}
