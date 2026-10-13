package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/auth"
	"github.com/kLauncher1/sheet-license-broker/internal/db"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
)

//go:embed web/dist/*
var embeddedDist embed.FS

// AppServer orchestrates in-memory mock engine and Google Sheets API gateway.
type AppServer struct {
	authMgr    *auth.Manager
	licenseMgr *license.Manager
	storage    *db.Storage
}

func newAppServer() *AppServer {
	return &AppServer{
		authMgr:    auth.NewManager(),
		licenseMgr: license.NewManager(),
		storage:    db.NewStorage(),
	}
}

func main() {
	server := newAppServer()

	// Seed demo license for initial UI dashboard inspection
	demoLic := server.licenseMgr.CreateLicense(30, 1)
	log.Printf("[Init] Pre-seeded demo license key: %s", demoLic.LicenseKey)

	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/health", server.handleHealth)
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
		// Serve embedded files or fallback to index.html
		fileServer.ServeHTTP(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "9082"
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("=====================================================")
	log.Printf("  Sheet-License-Broker Server active on http://%s", addr)
	log.Printf("  Serving Google Sheets serverless auth & license engine")
	log.Printf("=====================================================")

	s := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server exited unexpectedly: %v", err)
	}
}

func (s *AppServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"service":   "sheet-license-broker",
		"version":   "0.1.0",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *AppServer) handleLicenses(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		lics := s.licenseMgr.ListLicenses()
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
		lic := s.licenseMgr.CreateLicense(req.Days, req.MaxDevices)
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

	lic, err := s.licenseMgr.VerifyAndBind(req.LicenseKey, req.HWID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":      true,
		"license":    lic,
		"expires_at": lic.ExpiresAt,
	})
}

func (s *AppServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	users := s.authMgr.ListUsers()
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

	user, err := s.authMgr.RegisterUser(req.Username, req.Password, req.Role)
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

	user, err := s.authMgr.Authenticate(req.Username, req.Password)
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
		docs := s.storage.ListAll()
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
		doc := s.storage.Put(req.Collection, req.DocID, req.Payload)
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
