package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/sso"
)

// handleSSOMetadata serves standard SAML 2.0 Service Provider metadata XML.
func (s *Server) handleSSOMetadata(w http.ResponseWriter, r *http.Request) {
	entityID := r.URL.Query().Get("entity_id")
	if entityID == "" {
		entityID = "urn:sheet-license-broker:sp"
	}
	proto := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		proto = "https"
	}
	acsURL := r.URL.Query().Get("acs_url")
	if acsURL == "" {
		acsURL = proto + "://" + r.Host + "/api/sso/saml/acs"
	}
	xmlData := sso.BuildSPMetadataXML(entityID, acsURL)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xmlData))
}

// handleSAMLACS processes SAML 2.0 Assertion Consumer Service responses.
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rawXML []byte
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		_ = r.ParseForm()
		samlResp := r.FormValue("SAMLResponse")
		if samlResp == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing SAMLResponse form field"})
			return
		}
		rawXML = []byte(samlResp)
	} else {
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty request body"})
			return
		}
		var req struct {
			SAMLResponse string `json:"saml_response"`
		}
		if err := json.Unmarshal(body, &req); err == nil && req.SAMLResponse != "" {
			rawXML = []byte(req.SAMLResponse)
		} else {
			rawXML = body
		}
	}

	tenantID := s.proxy.TenantManager().ResolveFromRequest(r).ID
	claims, token, err := s.proxy.ProcessSAMLACS(r.Context(), rawXML, "", tenantID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"token":         token,
		"claims":        claims,
	})
}

// handleOIDCCallback validates OIDC claims and issues an ephemeral session token.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty OIDC request payload"})
		return
	}

	tenantID := s.proxy.TenantManager().ResolveFromRequest(r).ID
	claims, token, err := s.proxy.ProcessOIDCCallback(r.Context(), body, "", "", tenantID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"token":         token,
		"claims":        claims,
	})
}

// handleSSOIdP handles registration and listing of Identity Providers.
func (s *Server) handleSSOIdP(w http.ResponseWriter, r *http.Request) {
	tenantID := s.proxy.TenantManager().ResolveFromRequest(r).ID
	switch r.Method {
	case http.MethodGet:
		idps := s.proxy.SSOManager().IdPs().List(tenantID)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"idps":  idps,
			"count": len(idps),
		})
	case http.MethodPost:
		var cfg sso.IdPConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
			return
		}
		if cfg.TenantID == "" {
			cfg.TenantID = tenantID
		}
		registered, err := s.proxy.SSOManager().IdPs().Register(cfg)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, registered)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSSOTokenMint mints ephemeral session tokens with custom claims.
func (s *Server) handleSSOTokenMint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var claims sso.SessionTokenClaims
	if err := json.NewDecoder(r.Body).Decode(&claims); err != nil || claims.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id is required in token claims"})
		return
	}
	if claims.TenantID == "" {
		claims.TenantID = s.proxy.TenantManager().ResolveFromRequest(r).ID
	}
	token, err := s.proxy.IssueSessionToken(claims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":  token,
		"claims": claims,
	})
}

// handleSSOTokenIntrospect validates and checks scopes for a session token.
func (s *Server) handleSSOTokenIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token         string `json:"token"`
		RequiredScope string `json:"required_scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	claims, err := s.proxy.IntrospectSessionToken(req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"active": false,
			"error":  err.Error(),
		})
		return
	}

	authorized := true
	if req.RequiredScope != "" {
		authorized = sso.HasPermission(claims.Role, claims.Scopes, req.RequiredScope)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active":     true,
		"authorized": authorized,
		"claims":     claims,
	})
}

// handleSSOStatus delivers telemetry on SSO federation and SCIM directory status.
func (s *Server) handleSSOStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.proxy.GetSSOStatus())
}

// SCIM 2.0 Endpoints (RFC 7644)

// handleSCIMServiceProviderConfig delivers RFC 7643 provider configuration.
func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json; charset=utf-8")
	writeJSON(w, http.StatusOK, sso.BuildServiceProviderConfig())
}

// handleSCIMUsers handles listing and creating SCIM user resources.
func (s *Server) handleSCIMUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json; charset=utf-8")
	tenantID := s.proxy.TenantManager().ResolveFromRequest(r).ID

	switch r.Method {
	case http.MethodGet:
		startIndex := 1
		if sIdx := r.URL.Query().Get("startIndex"); sIdx != "" {
			if parsed, err := strconv.Atoi(sIdx); err == nil && parsed > 0 {
				startIndex = parsed
			}
		}
		count := 100
		if c := r.URL.Query().Get("count"); c != "" {
			if parsed, err := strconv.Atoi(c); err == nil && parsed > 0 {
				count = parsed
			}
		}
		list := s.proxy.SCIMListUsers(startIndex, count, tenantID)
		writeJSON(w, http.StatusOK, list)

	case http.MethodPost:
		var u sso.SCIMUser
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, sso.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  "Invalid SCIM JSON payload",
				Status:  "400",
			})
			return
		}
		if u.TenantID == "" {
			u.TenantID = tenantID
		}
		created, err := s.proxy.SCIMCreateUser(r.Context(), u)
		if err != nil {
			status := "400"
			if strings.Contains(err.Error(), "already exists") {
				status = "409"
			}
			code, _ := strconv.Atoi(status)
			writeJSON(w, code, sso.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  err.Error(),
				Status:  status,
			})
			return
		}
		writeJSON(w, http.StatusCreated, created)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSCIMUserItem handles operations on specific SCIM user items (/scim/v2/Users/{id}).
func (s *Server) handleSCIMUserItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json; charset=utf-8")
	userID := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
	if userID == "" || strings.Contains(userID, "/") {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		u, ok := s.proxy.SCIMGetUser(userID)
		if !ok {
			writeJSON(w, http.StatusNotFound, sso.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  "User not found",
				Status:  "404",
			})
			return
		}
		writeJSON(w, http.StatusOK, u)

	case http.MethodPut, http.MethodPatch:
		var u sso.SCIMUser
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			writeJSON(w, http.StatusBadRequest, sso.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  "Invalid SCIM update payload",
				Status:  "400",
			})
			return
		}
		updated, err := s.proxy.SCIMUpdateUser(r.Context(), userID, u)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, sso.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  err.Error(),
				Status:  "400",
			})
			return
		}
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if err := s.proxy.SCIMDeleteUser(r.Context(), userID); err != nil {
			writeJSON(w, http.StatusNotFound, sso.SCIMError{
				Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				Detail:  err.Error(),
				Status:  "404",
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// registerSSORoutes mounts SSO and SCIM 2.0 endpoints.
func (s *Server) registerSSORoutes(apiMux *http.ServeMux, rootMux *http.ServeMux) {
	// SAML 2.0 & OIDC
	apiMux.HandleFunc("/api/sso/saml/metadata", s.handleSSOMetadata)
	apiMux.HandleFunc("/api/sso/saml/acs", s.handleSAMLACS)
	apiMux.HandleFunc("/api/sso/oidc/callback", s.handleOIDCCallback)
	apiMux.HandleFunc("/api/sso/idp", s.handleSSOIdP)
	apiMux.HandleFunc("/api/sso/token/mint", s.handleSSOTokenMint)
	apiMux.HandleFunc("/api/sso/token/introspect", s.handleSSOTokenIntrospect)
	apiMux.HandleFunc("/api/sso/status", s.handleSSOStatus)

	// SCIM 2.0 (RFC 7644) mounted at root /scim/v2/
	rootMux.HandleFunc("/scim/v2/ServiceProviderConfig", s.handleSCIMServiceProviderConfig)
	rootMux.HandleFunc("/scim/v2/Users", s.handleSCIMUsers)
	rootMux.HandleFunc("/scim/v2/Users/", s.handleSCIMUserItem)
}
