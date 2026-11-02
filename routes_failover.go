package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/failover"
)

// registerFailoverRoutes registers REST API endpoints for autonomous multi-cloud failover & Geo-DNS health routing.
func (s *AppServer) registerFailoverRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/multicloud/status", s.handleMultiCloudStatus)
	apiMux.HandleFunc("/api/multicloud/providers", s.handleMultiCloudProviders)
	apiMux.HandleFunc("/api/multicloud/route", s.handleMultiCloudRoute)
	apiMux.HandleFunc("/api/multicloud/probe", s.handleMultiCloudProbe)
	apiMux.HandleFunc("/api/multicloud/sync/delta", s.handleMultiCloudSyncDelta)
	apiMux.HandleFunc("/api/multicloud/sync/pending", s.handleMultiCloudSyncPending)
	apiMux.HandleFunc("/api/multicloud/sync/acknowledge", s.handleMultiCloudSyncAck)
	apiMux.HandleFunc("/api/multicloud/failover/simulate", s.handleMultiCloudSimulateFailover)
}

func (s *AppServer) handleMultiCloudStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetMultiCloudStatus())
}

func (s *AppServer) handleMultiCloudProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	providers := s.proxy.MultiCloudManager().ListProviders()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
		"count":     len(providers),
	})
}

func (s *AppServer) handleMultiCloudRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientRegion string `json:"client_region"`
		ClientIP     string `json:"client_ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.ClientIP == "" {
		req.ClientIP = r.RemoteAddr
	}

	provider, token, err := s.proxy.RouteMultiCloud(req.ClientRegion, req.ClientIP)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"provider": provider,
		"token":    token,
	})
}

func (s *AppServer) handleMultiCloudProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req failover.HealthProbeResult
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json probe payload"})
		return
	}

	req.ProviderID = strings.TrimSpace(req.ProviderID)
	if req.ProviderID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id is required"})
		return
	}

	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}

	event, err := s.proxy.RecordMultiCloudProbe(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"failover_event": event,
	})
}

func (s *AppServer) handleMultiCloudSyncDelta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OriginProvider string          `json:"origin_provider"`
		Action         string          `json:"action"`
		Payload        json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json delta payload"})
		return
	}

	req.OriginProvider = strings.TrimSpace(req.OriginProvider)
	req.Action = strings.TrimSpace(req.Action)
	if req.OriginProvider == "" || req.Action == "" || len(req.Payload) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "origin_provider, action, and payload are required"})
		return
	}

	delta, err := s.proxy.SyncMultiCloudDelta(req.OriginProvider, req.Action, req.Payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"delta":   delta,
	})
}

func (s *AppServer) handleMultiCloudSyncPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providerID := strings.TrimSpace(r.URL.Query().Get("provider_id"))
	if providerID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id query parameter is required"})
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	pending := s.proxy.GetMultiCloudPendingSync(providerID, limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"provider_id": providerID,
		"pending":     pending,
		"count":       len(pending),
	})
}

func (s *AppServer) handleMultiCloudSyncAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ProviderID string                `json:"provider_id"`
		DeltaID    string                `json:"delta_id"`
		Voucher    *failover.SyncVoucher `json:"voucher"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json acknowledgement payload"})
		return
	}

	req.ProviderID = strings.TrimSpace(req.ProviderID)
	req.DeltaID = strings.TrimSpace(req.DeltaID)
	if req.ProviderID == "" || req.DeltaID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id and delta_id are required"})
		return
	}

	if err := s.proxy.AcknowledgeMultiCloudSync(req.ProviderID, req.DeltaID, req.Voucher); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "sync delta acknowledged and cleared from pending replay queue",
	})
}

func (s *AppServer) handleMultiCloudSimulateFailover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ProviderID string `json:"provider_id"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json simulate payload"})
		return
	}

	req.ProviderID = strings.TrimSpace(req.ProviderID)
	if req.ProviderID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id is required"})
		return
	}
	if req.Reason == "" {
		req.Reason = "Manual failover test drill"
	}

	event, err := s.proxy.SimulateMultiCloudOutage(req.ProviderID, req.Reason)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"failover_event": event,
	})
}
