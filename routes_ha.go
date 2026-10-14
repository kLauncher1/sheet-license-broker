package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/metrics"
	"github.com/kLauncher1/sheet-license-broker/internal/replication"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// handleHAStatus returns real-time high-availability and spool telemetry.
func (s *AppServer) handleHAStatus(w http.ResponseWriter, r *http.Request) {
	st := s.proxy.HAStatus(r.Context())
	writeJSON(w, http.StatusOK, st)
}

// handleHAReconcile triggers bidirectional collision-free reconciliation.
func (s *AppServer) handleHAReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	report, err := s.proxy.ReconcileDualSheets(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"report": report,
	})
}

// handleHASpoolDrain flushes pending offline disk events to the active sheet backend.
func (s *AppServer) handleHASpoolDrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flushed, err := s.proxy.DrainSpool(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"status":  "partial_drain",
			"flushed": flushed,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"flushed": flushed,
		"message": "All spooled events drained successfully",
	})
}

// handleHAFailover allows manual failover between primary and standby backends.
func (s *AppServer) handleHAFailover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetRole string `json:"target_role"` // "primary" or "standby"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	mgr := s.proxy.HAManager()
	if mgr == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "High Availability is not enabled"})
		return
	}

	target := replication.RolePrimary
	if strings.ToLower(strings.TrimSpace(req.TargetRole)) == "standby" {
		target = replication.RoleStandby
	}

	if err := mgr.ForceFailover(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"active_role": target,
		"message":     "Failover completed successfully",
	})
}

// handleAlertsTest sends a test incident alert to configured Slack/Discord channels.
func (s *AppServer) handleAlertsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type     string `json:"type"`
		Severity string `json:"severity"`
		Summary  string `json:"summary"`
		Details  string `json:"details"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.Type == "" {
		req.Type = "test_incident"
	}
	if req.Severity == "" {
		req.Severity = string(webhook.SeverityInfo)
	}
	if req.Summary == "" {
		req.Summary = "Test security incident alert from admin console"
	}

	alert := webhook.SecurityAlert{
		Type:      req.Type,
		Severity:  webhook.SecuritySeverity(req.Severity),
		Summary:   req.Summary,
		Details:   req.Details,
		IPAddress: r.RemoteAddr,
	}

	err := s.proxy.DispatchSecurityIncident(r.Context(), alert)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Incident alert dispatched to webhook channels",
	})
}

// registerHARoutes wires the HA, metrics, and reconciliation endpoints onto the mux.
func (s *AppServer) registerHARoutes(apiMux *http.ServeMux, rootMux *http.ServeMux) {
	// Guarded API endpoints
	apiMux.HandleFunc("/api/ha/status", s.handleHAStatus)
	apiMux.HandleFunc("/api/ha/reconcile", s.handleHAReconcile)
	apiMux.HandleFunc("/api/ha/spool/drain", s.handleHASpoolDrain)
	apiMux.HandleFunc("/api/ha/failover", s.handleHAFailover)
	apiMux.HandleFunc("/api/alerts/test", s.handleAlertsTest)

	// Prometheus Metrics endpoint (standard open scraping format)
	rootMux.Handle("/metrics", metrics.DefaultRegistry.Handler())
}
