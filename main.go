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

	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
)

//go:embed web/dist/*
var embeddedDist embed.FS

// AppServer orchestrates the serverless Google Sheets proxy and web console.
type AppServer struct {
	proxy *proxy.Proxy
}

func newAppServer() (*AppServer, error) {
	webAppURL := strings.TrimSpace(os.Getenv("GAS_WEBAPP_URL"))
	offlineMode := os.Getenv("OFFLINE_MODE") == "1" || strings.ToLower(os.Getenv("OFFLINE_MODE")) == "true"

	cacheTTL := 10 * time.Minute
	if ttlSec := os.Getenv("CACHE_TTL_SECONDS"); ttlSec != "" {
		if s, err := strconv.Atoi(ttlSec); err == nil && s > 0 {
			cacheTTL = time.Duration(s) * time.Second
		}
	}

	px, err := proxy.NewProxy(proxy.ProxyConfig{
		WebAppURL:   webAppURL,
		OfflineMode: offlineMode,
		CacheTTL:    cacheTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init proxy: %w", err)
	}

	return &AppServer{proxy: px}, nil
}

func main() {
	server, err := newAppServer()
	if err != nil {
		log.Fatalf("[Init Error] %v", err)
	}

	ctx := context.Background()

	// Seed demo license for initial UI dashboard inspection if standalone
	if !server.proxy.IsRemoteEnabled() {
		demoLic, _ := server.proxy.CreateLicense(ctx, 30, 1)
		log.Printf("[Init] Pre-seeded demo license key: %s (Local Standalone Mode)", demoLic.LicenseKey)
	} else {
		log.Printf("[Init] Remote Google Apps Script Web App active: %s", server.proxy.WebAppURL())
	}

	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/health", server.handleHealth)
	mux.HandleFunc("/api/proxy/ping", server.handleProxyPing)
	mux.HandleFunc("/api/proxy/status", server.handleProxyStatus)
	mux.HandleFunc("/api/licenses", server.handleLicenses)
	mux.HandleFunc("/api/licenses/validate", server.handleValidateLicense)
	mux.HandleFunc("/api/users", server.handleUsers)
	mux.HandleFunc("/api/users/register", server.handleRegisterUser)
	mux.HandleFunc("/api/users/login", server.handleLoginUser)
	mux.HandleFunc("/api/docs", server.handleDocs)

	// Embedded Static Asset Server
	subFS, err := fs.Sub(embeddedDist, "web/dist")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(subFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
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
	log.Printf("=====================================================")
	log.Printf("  Sheet-License-Broker Server active on http://%s", addr)
	log.Printf("  Mode: %v (Remote: %v)", server.proxy.Status()["mode"], server.proxy.IsRemoteEnabled())
	log.Printf("=====================================================")

	s := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server exited unexpectedly: %v", err)
	}
}

func (s *AppServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := s.proxy.Status()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"service":   "sheet-license-broker",
		"version":   "0.2.0",
		"proxy":     status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *AppServer) handleProxyPing(w http.ResponseWriter, r *http.Request) {
	res, err := s.proxy.Ping(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *AppServer) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.proxy.Status())
}

func (s *AppServer) handleLicenses(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		lics := s.proxy.ListLicenses()
		writeJSON(w, http.StatusOK, lics)
	case http.MethodPost:
		var req struct {
			Days       int `json:"days"`
			MaxDevices int `json:"max_devices"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req.Days = 30
			req.MaxDevices = 1
		}
		if req.Days <= 0 {
			req.Days = 30
		}
		if req.MaxDevices <= 0 {
			req.MaxDevices = 1
		}
		lic, err := s.proxy.CreateLicense(r.Context(), req.Days, req.MaxDevices)
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
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"valid":   false,
			"error":   err.Error(),
			"message": res.Message,
			"source":  res.Source,
		})
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *AppServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	users := s.proxy.ListUsers()
	writeJSON(w, http.StatusOK, users)
}

func (s *AppServer) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"user":          user,
	})
}

func (s *AppServer) handleDocs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		docs := s.proxy.ListDocuments()
		writeJSON(w, http.StatusOK, docs)
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

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
