package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/stream"
)

// handleStreamWS upgrades incoming HTTP requests to real-time WebSocket telemetry streams.
func (s *AppServer) handleStreamWS(w http.ResponseWriter, r *http.Request) {
	conn, err := stream.Upgrade(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("WebSocket upgrade failed: %v", err), http.StatusBadRequest)
		return
	}

	// Extract client identity from query parameters or headers
	q := r.URL.Query()
	licKey := strings.TrimSpace(q.Get("license_key"))
	if licKey == "" {
		licKey = strings.TrimSpace(r.Header.Get("X-License-Key"))
	}
	hwid := strings.TrimSpace(q.Get("hwid"))
	if hwid == "" {
		hwid = strings.TrimSpace(r.Header.Get("X-Hardware-ID"))
	}
	tenantID := strings.TrimSpace(q.Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}

	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	clientID := fmt.Sprintf("cl-%d-%s", time.Now().Unix(), hex.EncodeToString(randBytes))

	clientInfo := stream.ClientInfo{
		ID:         clientID,
		LicenseKey: licKey,
		HWID:       hwid,
		TenantID:   tenantID,
	}

	client := stream.NewClient(clientID, conn, s.proxy.StreamHub(), clientInfo)
	s.proxy.RegisterStreamClient(client)

	// Dispatch initial welcome envelope
	welcome, _ := stream.NewMessage(stream.EventConnected, map[string]interface{}{
		"client_id":   clientID,
		"server_time": time.Now().Unix(),
		"license_key": licKey,
		"hwid":        hwid,
		"tenant_id":   tenantID,
	})
	_ = client.SendJSON(welcome)

	// Start concurrent pumps
	go client.WritePump()
	client.ReadPump() // Blocks until connection closes
}

// handleStreamClients returns metadata for all currently connected client sessions.
func (s *AppServer) handleStreamClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clients := s.proxy.ActiveStreamClients()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"count":   len(clients),
		"clients": clients,
	})
}

// handleStreamKill executes an immediate remote kill-switch against targeted clients.
func (s *AppServer) handleStreamKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target    string `json:"target"`
		Reason    string `json:"reason"`
		Immediate bool   `json:"immediate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Target is required (license_key, hwid, client_id, or 'ALL')"})
		return
	}
	if req.Reason == "" {
		req.Reason = "Administrative remote termination directive"
	}

	signaled := s.proxy.PushKillSwitch(req.Target, req.Reason, req.Immediate)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":           "success",
		"target":           req.Target,
		"signaled_clients": signaled,
		"message":          fmt.Sprintf("Kill switch dispatched to %d client(s)", signaled),
	})
}

// handleStreamBroadcast broadcasts a notification or payload to all connected clients.
func (s *AppServer) handleStreamBroadcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Event   string                 `json:"event"`
		Payload map[string]interface{} `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if req.Event == "" {
		req.Event = "stream:notification"
	}

	sent := s.proxy.BroadcastStreamEvent(req.Event, req.Payload)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"event":  req.Event,
		"sent":   sent,
	})
}

// handleStreamTelemetry returns aggregate telemetry metrics across all active streams.
func (s *AppServer) handleStreamTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	telemetry := s.proxy.GetStreamTelemetry()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "success",
		"telemetry": telemetry,
	})
}

// registerStreamRoutes wires streaming and telemetry endpoints onto the API mux and root mux.
func (s *AppServer) registerStreamRoutes(apiMux *http.ServeMux, rootMux *http.ServeMux) {
	// WebSocket upgrade endpoint mounted directly (bypassing buffering middleware)
	rootMux.HandleFunc("/api/stream/ws", s.handleStreamWS)

	// REST stream telemetry and management endpoints
	apiMux.HandleFunc("/api/stream/clients", s.handleStreamClients)
	apiMux.HandleFunc("/api/stream/kill", s.handleStreamKill)
	apiMux.HandleFunc("/api/stream/broadcast", s.handleStreamBroadcast)
	apiMux.HandleFunc("/api/stream/telemetry", s.handleStreamTelemetry)
}
