package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/license"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// Server orchestrates the serverless Google Sheets proxy, security guard, and web console.
type Server struct {
	proxy *proxy.Proxy
	guard *security.Guard
}

// AppServer is an alias for Server.
type AppServer = Server

// NewServer creates a new API Server instance.
func NewServer(px *proxy.Proxy, guard *security.Guard) *Server {
	return &Server{
		proxy: px,
		guard: guard,
	}
}

// NewAppServer initializes a Server with environment configurations.
func NewAppServer() (*Server, error) {
	cacheTTL := 10 * time.Minute
	if ttlSec := os.Getenv("CACHE_TTL_SECONDS"); ttlSec != "" {
		if s, err := strconv.Atoi(ttlSec); err == nil && s > 0 {
			cacheTTL = time.Duration(s) * time.Second
		}
	}

	px, err := proxy.NewProxy(proxy.ProxyConfig{
		WebAppURL:        strings.TrimSpace(os.Getenv("GAS_WEBAPP_URL")),
		OfflineMode:      os.Getenv("OFFLINE_MODE") == "1" || strings.ToLower(os.Getenv("OFFLINE_MODE")) == "true",
		CacheTTL:         cacheTTL,
		GlobalWebhookURL: strings.TrimSpace(os.Getenv("GLOBAL_WEBHOOK_URL")),
		GlobalSecret:     strings.TrimSpace(os.Getenv("GLOBAL_WEBHOOK_SECRET")),
		StandbyWebAppURL: strings.TrimSpace(os.Getenv("GAS_STANDBY_WEBAPP_URL")),
		AutoFailover:     os.Getenv("HA_AUTO_FAILOVER") == "1" || strings.ToLower(os.Getenv("HA_AUTO_FAILOVER")) == "true",
		SpoolPath:        strings.TrimSpace(os.Getenv("SPOOL_PATH")),
		SpoolSecret:      strings.TrimSpace(os.Getenv("SPOOL_SECRET")),
		DiscordAlertURL:  strings.TrimSpace(os.Getenv("DISCORD_ALERT_WEBHOOK_URL")),
		SlackAlertURL:    strings.TrimSpace(os.Getenv("SLACK_ALERT_WEBHOOK_URL")),
		NodeID:           strings.TrimSpace(os.Getenv("NODE_ID")),
		ClusterRegion:    strings.TrimSpace(os.Getenv("CLUSTER_REGION")),
		ClusterAddress:   strings.TrimSpace(os.Getenv("CLUSTER_ADDRESS")),
		ClusterPeers:     strings.Split(strings.TrimSpace(os.Getenv("CLUSTER_PEERS")), ","),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init proxy: %w", err)
	}
	hmacEnforce := os.Getenv("HMAC_ENFORCE") == "1" || strings.ToLower(os.Getenv("HMAC_ENFORCE")) == "true"
	secGuard := security.NewGuard([]byte(strings.TrimSpace(os.Getenv("HMAC_SECRET"))), 5*time.Minute, hmacEnforce)
	return &Server{proxy: px, guard: secGuard}, nil
}

// newAppServer is an internal package alias for test convenience.
func newAppServer() (*Server, error) {
	return NewAppServer()
}

// Proxy returns the underlying proxy instance.
func (s *Server) Proxy() *proxy.Proxy {
	return s.proxy
}

// Guard returns the security guard instance.
func (s *Server) Guard() *security.Guard {
	return s.guard
}

// Routes constructs the HTTP handler hierarchy including API endpoints, security middlewares, and web UI.
func (s *Server) Routes(subFS fs.FS) http.Handler {
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/health", s.handleHealth)
	apiMux.HandleFunc("/api/proxy/ping", s.handleProxyPing)
	apiMux.HandleFunc("/api/proxy/status", s.handleProxyStatus)
	apiMux.HandleFunc("/api/licenses", s.handleLicenses)
	apiMux.HandleFunc("/api/licenses/validate", s.handleValidateLicense)
	apiMux.HandleFunc("/api/licenses/revoke", s.handleRevokeLicense)
	apiMux.HandleFunc("/api/security/blacklist", s.handleBlacklist)
	apiMux.HandleFunc("/api/security/blacklist/remove", s.handleBlacklistRemove)
	apiMux.HandleFunc("/api/security/status", s.handleSecurityStatus)
	apiMux.HandleFunc("/api/users", s.handleUsers)
	apiMux.HandleFunc("/api/users/register", s.handleRegisterUser)
	apiMux.HandleFunc("/api/users/login", s.handleLoginUser)
	apiMux.HandleFunc("/api/docs", s.handleDocs)
	apiMux.HandleFunc("/api/tenants", s.handleTenants)
	apiMux.HandleFunc("/api/tenants/register", s.handleRegisterTenant)
	apiMux.HandleFunc("/api/backup/export", s.handleBackupExport)
	apiMux.HandleFunc("/api/backup/restore", s.handleBackupRestore)
	apiMux.HandleFunc("/api/webhooks/test", s.handleTestWebhook)

	mux := http.NewServeMux()
	mux.Handle("/api/", s.securityRateLimitMiddleware(s.guard.Middleware(apiMux)))

	// Wire subsystem routes
	s.registerHARoutes(apiMux, mux)
	s.registerFeatureRoutes(apiMux)
	s.registerAttestationRoutes(apiMux)
	s.registerSecurityRoutes(apiMux)
	s.registerConsensusRoutes(apiMux)
	s.registerStreamRoutes(apiMux, mux)
	s.registerZKPRoutes(apiMux)
	s.registerSSORoutes(apiMux, mux)
	s.registerPQCRoutes(apiMux)
	s.registerAnomalyRoutes(apiMux)

	if subFS != nil {
		fileServer := http.FileServer(http.FS(subFS))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/scim/") {
				http.NotFound(w, r)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"service":   "sheet-license-broker",
		"version":   "1.5.0",
		"proxy":     s.proxy.Status(),
		"consensus": s.proxy.ClusterStatus(),
		"zkp":       s.proxy.GetZKPStatus(),
		"sso":       s.proxy.GetSSOStatus(),
		"pqc":       s.proxy.GetPQCStatus(),
		"anomaly":   s.proxy.GetAnomalyStatus(),
		"security":  map[string]interface{}{"hmac_enforced": s.guard.IsEnforced(), "nonce_window": "5m"},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleProxyPing(w http.ResponseWriter, r *http.Request) {
	if res, err := s.proxy.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	} else {
		writeJSON(w, http.StatusOK, res)
	}
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.proxy.Status())
}

func (s *Server) handleLicenses(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.proxy.ListLicenses())
	case http.MethodPost:
		var req struct {
			TenantID   string `json:"tenant_id"`
			Days       int    `json:"days"`
			MaxDevices int    `json:"max_devices"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Days <= 0 {
			req.Days = 30
		}
		if req.MaxDevices <= 0 {
			req.MaxDevices = 1
		}

		targetTenant := req.TenantID
		if targetTenant == "" {
			targetTenant = s.proxy.TenantManager().ResolveFromRequest(r).ID
		}
		lic, err := s.proxy.CreateTenantLicense(r.Context(), targetTenant, req.Days, req.MaxDevices)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, lic)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleValidateLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		LicenseKey string `json:"license_key"`
		HWID       string `json:"hwid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	res, err := s.proxy.VerifyLicense(r.Context(), req.LicenseKey, req.HWID)
	if err != nil {
		s.proxy.NotifyLicenseEvent(webhook.EventTamperDetected, req.LicenseKey, req.HWID, err.Error())
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"valid": false, "error": err.Error(), "message": res.Message, "source": res.Source})
		return
	}

	s.proxy.NotifyLicenseEvent(webhook.EventLicenseVerified, req.LicenseKey, req.HWID, "Verified")
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.ListUsers())
}

func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}
	user, err := s.proxy.RegisterUser(r.Context(), req.Username, req.Password, req.Role)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleLoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}
	user, err := s.proxy.AuthenticateUser(r.Context(), req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"authenticated": true, "user": user})
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.proxy.ListDocuments())
	case http.MethodPost:
		var req struct {
			Collection string `json:"collection"`
			DocID      string `json:"doc_id"`
			Payload    string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
			return
		}
		doc, err := s.proxy.PutDocument(r.Context(), req.Collection, req.DocID, req.Payload)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, doc)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hmac_enforced": s.guard.IsEnforced(),
		"nonce_window":  "5m",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleRevokeLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		LicenseKey string `json:"license_key"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.LicenseKey) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key is required"})
		return
	}
	if req.Reason == "" {
		req.Reason = "Revoked via administrative console"
	}
	if err := s.proxy.RevokeLicense(r.Context(), req.LicenseKey, req.Reason); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "revoked": true, "license_key": req.LicenseKey, "reason": req.Reason})
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		entries, err := s.proxy.ListBlacklist(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, entries)
	case http.MethodPost:
		var req struct {
			Type   string `json:"type"`
			Target string `json:"target"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Target) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target identifier is required"})
			return
		}
		if req.Type == "" {
			req.Type = license.BlacklistTypeDevice
		}
		if req.Reason == "" {
			req.Reason = "Blacklisted via administrative console"
		}

		if req.Type == license.BlacklistTypeLicense {
			_ = s.proxy.RevokeLicense(r.Context(), req.Target, req.Reason)
		} else {
			_ = s.proxy.BlacklistDevice(r.Context(), req.Target, req.Reason)
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{"status": "success", "type": req.Type, "target": req.Target, "reason": req.Reason})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlacklistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Type   string `json:"type"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Target) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type and target are required"})
		return
	}
	if req.Type == "" {
		req.Type = license.BlacklistTypeDevice
	}
	_ = s.proxy.RemoveBlacklist(r.Context(), req.Type, req.Target)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Target removed from blacklist"})
}

// writeJSON writes a JSON response with status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
