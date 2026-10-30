package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
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

//go:embed web/dist/*
var embeddedDist embed.FS

// AppServer orchestrates the serverless Google Sheets proxy, security guard, and web console.
type AppServer struct {
	proxy *proxy.Proxy
	guard *security.Guard
}

func newAppServer() (*AppServer, error) {
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
		StripeWebhookSecret:       strings.TrimSpace(os.Getenv("STRIPE_WEBHOOK_SECRET")),
		LemonSqueezyWebhookSecret: strings.TrimSpace(os.Getenv("LEMONSQUEEZY_WEBHOOK_SECRET")),
		PaddleWebhookSecret:       strings.TrimSpace(os.Getenv("PADDLE_WEBHOOK_SECRET")),
		MLKEMQuantumEnforced:      os.Getenv("PQC_QUANTUM_ENFORCE") == "1" || strings.ToLower(os.Getenv("PQC_QUANTUM_ENFORCE")) == "true",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init proxy: %w", err)
	}
	hmacEnforce := os.Getenv("HMAC_ENFORCE") == "1" || strings.ToLower(os.Getenv("HMAC_ENFORCE")) == "true"
	secGuard := security.NewGuard([]byte(strings.TrimSpace(os.Getenv("HMAC_SECRET"))), 5*time.Minute, hmacEnforce)
	return &AppServer{proxy: px, guard: secGuard}, nil
}

func main() {
	server, err := newAppServer()
	if err != nil {
		log.Fatalf("[Init Error] %v", err)
	}
	defer server.proxy.Close()

	ctx := context.Background()
	if !server.proxy.IsRemoteEnabled() {
		demoLic, _ := server.proxy.CreateLicense(ctx, 30, 1)
		log.Printf("[Init] Pre-seeded demo license key: %s (Local Standalone Mode)", demoLic.LicenseKey)
	} else {
		log.Printf("[Init] Remote Google Apps Script Web App active: %s", server.proxy.WebAppURL())
	}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/health", server.handleHealth)
	apiMux.HandleFunc("/api/proxy/ping", server.handleProxyPing)
	apiMux.HandleFunc("/api/proxy/status", server.handleProxyStatus)
	apiMux.HandleFunc("/api/licenses", server.handleLicenses)
	apiMux.HandleFunc("/api/licenses/validate", server.handleValidateLicense)
	apiMux.HandleFunc("/api/licenses/revoke", server.handleRevokeLicense)
	apiMux.HandleFunc("/api/security/blacklist", server.handleBlacklist)
	apiMux.HandleFunc("/api/security/blacklist/remove", server.handleBlacklistRemove)
	apiMux.HandleFunc("/api/security/status", server.handleSecurityStatus)
	apiMux.HandleFunc("/api/users", server.handleUsers)
	apiMux.HandleFunc("/api/users/register", server.handleRegisterUser)
	apiMux.HandleFunc("/api/users/login", server.handleLoginUser)
	apiMux.HandleFunc("/api/docs", server.handleDocs)
	apiMux.HandleFunc("/api/tenants", server.handleTenants)
	apiMux.HandleFunc("/api/tenants/register", server.handleRegisterTenant)
	apiMux.HandleFunc("/api/backup/export", server.handleBackupExport)
	apiMux.HandleFunc("/api/backup/restore", server.handleBackupRestore)
	apiMux.HandleFunc("/api/webhooks/test", server.handleTestWebhook)

	mux := http.NewServeMux()
	mux.Handle("/api/", server.securityRateLimitMiddleware(server.guard.Middleware(apiMux)))

	// Wire subsystem routes
	server.registerHARoutes(apiMux, mux)
	server.registerFeatureRoutes(apiMux)
	server.registerAttestationRoutes(apiMux)
	server.registerSecurityRoutes(apiMux)
	server.registerConsensusRoutes(apiMux)
	server.registerStreamRoutes(apiMux, mux)
	server.registerZKPRoutes(apiMux)
	server.registerSSORoutes(apiMux, mux)
	server.registerPQCRoutes(apiMux)
	server.registerAnomalyRoutes(apiMux)
	server.registerEnclaveRoutes(apiMux)
	server.registerAnycastRoutes(apiMux)
	server.registerMarketplaceRoutes(apiMux, mux)
	server.registerAirgapRoutes(apiMux)
	server.registerZeroTrustRoutes(apiMux)
	server.registerHealingRoutes(apiMux)
	server.registerHSMRoutes(apiMux)
	server.registerMLKEMRoutes(apiMux)

	subFS, err := fs.Sub(embeddedDist, "web/dist")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(subFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/scim/") {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "9082"
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("  Sheet-License-Broker Server active on http://%s (v2.3.0)", addr)

	s := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server exited unexpectedly: %v", err)
	}
}

func (s *AppServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "healthy",
		"service":     "sheet-license-broker",
		"version":     "2.3.0",
		"proxy":       s.proxy.Status(),
		"consensus":   s.proxy.ClusterStatus(),
		"zkp":         s.proxy.GetZKPStatus(),
		"sso":         s.proxy.GetSSOStatus(),
		"pqc":         s.proxy.GetPQCStatus(),
		"anomaly":     s.proxy.GetAnomalyStatus(),
		"enclave":     s.proxy.GetEnclaveTelemetry(),
		"anycast":     s.proxy.GetAnycastStatus(),
		"marketplace": s.proxy.GetMarketplaceStatus(),
		"airgap":      s.proxy.GetAirgapStatus(),
		"zerotrust":   s.proxy.GetZeroTrustStatus(),
		"healing":     s.proxy.GetHealingStatus(),
		"hsm":         s.proxy.GetHSMStatus(),
		"mlkem":       s.proxy.GetMLKEMStatus(),
		"security":    map[string]interface{}{"hmac_enforced": s.guard.IsEnforced(), "nonce_window": "5m"},
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *AppServer) handleProxyPing(w http.ResponseWriter, r *http.Request) {
	if res, err := s.proxy.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	} else {
		writeJSON(w, http.StatusOK, res)
	}
}

func (s *AppServer) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.proxy.Status())
}

func (s *AppServer) handleLicenses(w http.ResponseWriter, r *http.Request) {
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
		if req.Days <= 0 { req.Days = 30 }
		if req.MaxDevices <= 0 { req.MaxDevices = 1 }

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

func (s *AppServer) handleValidateLicense(w http.ResponseWriter, r *http.Request) {
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

func (s *AppServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.ListUsers())
}

func (s *AppServer) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`; Password string `json:"password"`; Role string `json:"role"`
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

func (s *AppServer) handleLoginUser(w http.ResponseWriter, r *http.Request) {
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

func (s *AppServer) handleDocs(w http.ResponseWriter, r *http.Request) {
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

func (s *AppServer) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hmac_enforced": s.guard.IsEnforced(),
		"nonce_window":  "5m",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *AppServer) handleRevokeLicense(w http.ResponseWriter, r *http.Request) {
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
	if req.Reason == "" { req.Reason = "Revoked via administrative console" }
	if err := s.proxy.RevokeLicense(r.Context(), req.LicenseKey, req.Reason); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "revoked": true, "license_key": req.LicenseKey, "reason": req.Reason})
}

func (s *AppServer) handleBlacklist(w http.ResponseWriter, r *http.Request) {
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
		if req.Type == "" { req.Type = license.BlacklistTypeDevice }
		if req.Reason == "" { req.Reason = "Blacklisted via administrative console" }

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

func (s *AppServer) handleBlacklistRemove(w http.ResponseWriter, r *http.Request) {
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
	if req.Type == "" { req.Type = license.BlacklistTypeDevice }
	_ = s.proxy.RemoveBlacklist(r.Context(), req.Type, req.Target)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Target removed from blacklist"})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
