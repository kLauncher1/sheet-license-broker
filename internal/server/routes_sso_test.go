package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/sso"
)

func setupTestAppServerForSSO(t *testing.T) (*AppServer, *http.ServeMux) {
	t.Helper()
	server, err := newAppServer()
	if err != nil {
		t.Fatalf("failed to create app server: %v", err)
	}

	apiMux := http.NewServeMux()
	mux := http.NewServeMux()

	server.registerSSORoutes(apiMux, mux)
	mux.Handle("/api/", apiMux)

	return server, mux
}

func TestRoutesSSOMetadata(t *testing.T) {
	_, mux := setupTestAppServerForSSO(t)

	req := httptest.NewRequest(http.MethodGet, "/api/sso/saml/metadata?entity_id=urn:test:sp", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `entityID="urn:test:sp"`) {
		t.Errorf("expected entityID in metadata XML response: %s", body)
	}
	if w.Header().Get("Content-Type") != "application/xml; charset=utf-8" {
		t.Errorf("expected application/xml content type, got: %s", w.Header().Get("Content-Type"))
	}
}

func TestRoutesSAMLACSAndOIDCCallback(t *testing.T) {
	_, mux := setupTestAppServerForSSO(t)

	// 1. SAML ACS
	notBefore := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	notOnOrAfter := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	samlXML := fmt.Sprintf(`<?xml version="1.0"?>
<Response>
  <Assertion ID="acs-test-1">
    <Subject><NameID>saml-user@corp.internal</NameID></Subject>
    <Conditions NotBefore="%s" NotOnOrAfter="%s">
      <AudienceRestriction><Audience>urn:sheet-license-broker:sp</Audience></AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="role"><AttributeValue>operator</AttributeValue></Attribute>
    </AttributeStatement>
  </Assertion>
</Response>`, notBefore, notOnOrAfter)

	acsReq := httptest.NewRequest(http.MethodPost, "/api/sso/saml/acs", strings.NewReader(samlXML))
	acsReq.Header.Set("Content-Type", "application/xml")
	wACS := httptest.NewRecorder()
	mux.ServeHTTP(wACS, acsReq)

	if wACS.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on SAML ACS, got %d: %s", wACS.Code, wACS.Body.String())
	}
	var acsResp struct {
		Authenticated bool                    `json:"authenticated"`
		Token         string                  `json:"token"`
		Claims        *sso.SessionTokenClaims `json:"claims"`
	}
	_ = json.NewDecoder(wACS.Body).Decode(&acsResp)
	if !acsResp.Authenticated || !strings.HasPrefix(acsResp.Token, "sso.") {
		t.Errorf("expected valid authenticated response with token, got %+v", acsResp)
	}

	// 2. OIDC Callback
	now := time.Now().UTC().Unix()
	oidcClaims := sso.OIDCClaims{
		Sub:      "usr-oidc-99",
		Email:    "engineer@corp.internal",
		Roles:    []string{"admin"},
		Iss:      "https://idp.corp.internal",
		Aud:      "broker-client-id",
		Exp:      now + 3600,
		Iat:      now,
	}
	claimsBytes, _ := json.Marshal(oidcClaims)
	oidcReq := httptest.NewRequest(http.MethodPost, "/api/sso/oidc/callback", bytes.NewReader(claimsBytes))
	oidcReq.Header.Set("Content-Type", "application/json")
	wOIDC := httptest.NewRecorder()
	mux.ServeHTTP(wOIDC, oidcReq)

	if wOIDC.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on OIDC callback, got %d: %s", wOIDC.Code, wOIDC.Body.String())
	}
}

func TestRoutesSSOTokenMintAndIntrospect(t *testing.T) {
	_, mux := setupTestAppServerForSSO(t)

	// 1. Mint Token
	mintReqBody, _ := json.Marshal(sso.SessionTokenClaims{
		UserID: "operator-101",
		Email:  "op@broker.dev",
		Role:   sso.RoleOperator,
	})
	mintReq := httptest.NewRequest(http.MethodPost, "/api/sso/token/mint", bytes.NewReader(mintReqBody))
	mintReq.Header.Set("Content-Type", "application/json")
	wMint := httptest.NewRecorder()
	mux.ServeHTTP(wMint, mintReq)

	if wMint.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on token mint, got %d: %s", wMint.Code, wMint.Body.String())
	}
	var mintResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(wMint.Body).Decode(&mintResp)

	// 2. Introspect Token with Allowed Scope
	introReqBody, _ := json.Marshal(map[string]string{
		"token":          mintResp.Token,
		"required_scope": sso.ScopeLicenseRead,
	})
	introReq := httptest.NewRequest(http.MethodPost, "/api/sso/token/introspect", bytes.NewReader(introReqBody))
	introReq.Header.Set("Content-Type", "application/json")
	wIntro := httptest.NewRecorder()
	mux.ServeHTTP(wIntro, introReq)

	if wIntro.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on introspect, got %d: %s", wIntro.Code, wIntro.Body.String())
	}
	var introResp struct {
		Active     bool                    `json:"active"`
		Authorized bool                    `json:"authorized"`
		Claims     *sso.SessionTokenClaims `json:"claims"`
	}
	_ = json.NewDecoder(wIntro.Body).Decode(&introResp)
	if !introResp.Active || !introResp.Authorized || introResp.Claims.Email != "op@broker.dev" {
		t.Errorf("unexpected introspect result: %+v", introResp)
	}

	// 3. Introspect with Unauthorized Scope for Operator (e.g. sso:manage)
	unauthReqBody, _ := json.Marshal(map[string]string{
		"token":          mintResp.Token,
		"required_scope": sso.ScopeSSOManage,
	})
	unauthReq := httptest.NewRequest(http.MethodPost, "/api/sso/token/introspect", bytes.NewReader(unauthReqBody))
	unauthReq.Header.Set("Content-Type", "application/json")
	wUnauth := httptest.NewRecorder()
	mux.ServeHTTP(wUnauth, unauthReq)

	var unauthResp struct {
		Active     bool `json:"active"`
		Authorized bool `json:"authorized"`
	}
	_ = json.NewDecoder(wUnauth.Body).Decode(&unauthResp)
	if !unauthResp.Active || unauthResp.Authorized {
		t.Errorf("operator should NOT be authorized for sso:manage: %+v", unauthResp)
	}
}

func TestRoutesSCIMUserEndpoints(t *testing.T) {
	_, mux := setupTestAppServerForSSO(t)

	// 1. ServiceProviderConfig
	cfgReq := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	wCfg := httptest.NewRecorder()
	mux.ServeHTTP(wCfg, cfgReq)
	if wCfg.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on SCIM ServiceProviderConfig, got %d", wCfg.Code)
	}

	// 2. Create SCIM User
	userBody, _ := json.Marshal(sso.SCIMUser{
		UserName:    "scim-test@company.corp",
		DisplayName: "SCIM Tester",
		Active:      true,
		Roles:       []sso.SCIMRole{{Value: "operator", Primary: true}},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(userBody))
	createReq.Header.Set("Content-Type", "application/scim+json")
	wCreate := httptest.NewRecorder()
	mux.ServeHTTP(wCreate, createReq)

	if wCreate.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on SCIM user create, got %d: %s", wCreate.Code, wCreate.Body.String())
	}
	var created sso.SCIMUser
	_ = json.NewDecoder(wCreate.Body).Decode(&created)
	if created.ID == "" || created.LicenseKey == "" {
		t.Errorf("expected generated ID and auto-assigned license: %+v", created)
	}

	// 3. Get SCIM User
	getReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/scim/v2/Users/%s", created.ID), nil)
	wGet := httptest.NewRecorder()
	mux.ServeHTTP(wGet, getReq)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get user, got %d", wGet.Code)
	}

	// 4. List SCIM Users
	listReq := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=1&count=10", nil)
	wList := httptest.NewRecorder()
	mux.ServeHTTP(wList, listReq)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on list users, got %d", wList.Code)
	}

	// 5. Delete SCIM User
	delReq := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/scim/v2/Users/%s", created.ID), nil)
	wDel := httptest.NewRecorder()
	mux.ServeHTTP(wDel, delReq)
	if wDel.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content on delete user, got %d", wDel.Code)
	}

	// 6. Verify Deletion
	getAfterDel := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/scim/v2/Users/%s", created.ID), nil)
	wAfterDel := httptest.NewRecorder()
	mux.ServeHTTP(wAfterDel, getAfterDel)
	if wAfterDel.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found after deletion, got %d", wAfterDel.Code)
	}
}

func TestRoutesSSOStatusAndIdP(t *testing.T) {
	_, mux := setupTestAppServerForSSO(t)

	// 1. Register IdP
	idpBody, _ := json.Marshal(sso.IdPConfig{
		ID:          "idp-okta-1",
		TenantID:    "corp",
		Name:        "Corporate Okta",
		Type:        sso.IdPTypeSAML2,
		EntityID:    "https://okta.corp.com",
		SSOEndpoint: "https://okta.corp.com/app/sso",
		Enabled:     true,
	})
	regReq := httptest.NewRequest(http.MethodPost, "/api/sso/idp", bytes.NewReader(idpBody))
	regReq.Header.Set("Content-Type", "application/json")
	wReg := httptest.NewRecorder()
	mux.ServeHTTP(wReg, regReq)

	if wReg.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on IdP register, got %d: %s", wReg.Code, wReg.Body.String())
	}

	// 2. List IdPs
	listReq := httptest.NewRequest(http.MethodGet, "/api/sso/idp", nil)
	wList := httptest.NewRecorder()
	mux.ServeHTTP(wList, listReq)

	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on IdP list, got %d", wList.Code)
	}

	// 3. SSO Status
	statReq := httptest.NewRequest(http.MethodGet, "/api/sso/status", nil)
	wStat := httptest.NewRecorder()
	mux.ServeHTTP(wStat, statReq)

	if wStat.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on SSO status, got %d", wStat.Code)
	}
	var stat sso.SSOStatusSummary
	_ = json.NewDecoder(wStat.Body).Decode(&stat)
	if stat.TotalIdPs < 1 {
		t.Errorf("expected at least 1 IdP in status summary, got %+v", stat)
	}
}
