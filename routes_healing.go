package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/healing"
)

// registerHealingRoutes mounts REST endpoints for autonomous healing and quota rebalancing.
func (s *AppServer) registerHealingRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/healing/status", s.handleHealingStatus)
	apiMux.HandleFunc("/api/healing/bucket/consume", s.handleHealingBucketConsume)
	apiMux.HandleFunc("/api/healing/tunnel/ticket", s.handleHealingTunnelTicket)
	apiMux.HandleFunc("/api/healing/tunnel/resume", s.handleHealingTunnelResume)
	apiMux.HandleFunc("/api/healing/quota/borrow", s.handleHealingQuotaBorrow)
	apiMux.HandleFunc("/api/healing/quota/return", s.handleHealingQuotaReturn)
	apiMux.HandleFunc("/api/healing/quota/recall", s.handleHealingQuotaRecall)
	apiMux.HandleFunc("/api/healing/quota/rebalance", s.handleHealingQuotaRebalance)
}

func (s *AppServer) handleHealingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetHealingStatus())
}

type bucketConsumeRequest struct {
	Tokens float64 `json:"tokens"`
}

func (s *AppServer) handleHealingBucketConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req bucketConsumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Tokens = 1.0 // default to 1 token if body is omitted
	}
	if req.Tokens <= 0 {
		req.Tokens = 1.0
	}

	allowed, stats := s.proxy.ConsumeHealingTokens(req.Tokens)
	status := http.StatusOK
	if !allowed {
		status = http.StatusTooManyRequests
	}

	writeJSON(w, status, map[string]interface{}{
		"allowed": allowed,
		"stats":   stats,
	})
}

type tunnelTicketRequest struct {
	SessionID  string `json:"session_id"`
	ClientID   string `json:"client_id"`
	HWID       string `json:"hwid"`
	TenantID   string `json:"tenant_id"`
	LastAckSeq int64  `json:"last_ack_seq"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

func (s *AppServer) handleHealingTunnelTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tunnelTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.ClientID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id is required"})
		return
	}
	if strings.TrimSpace(req.HWID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hwid is required"})
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = "default"
	}

	ttl := 3 * time.Minute
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	ticket := s.proxy.IssueHealingTicket(req.SessionID, req.ClientID, req.HWID, req.TenantID, req.LastAckSeq, ttl)
	if ticket == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to issue healing ticket"})
		return
	}

	writeJSON(w, http.StatusOK, ticket)
}

func (s *AppServer) handleHealingTunnelResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ticket healing.HealingTicket
	if err := json.NewDecoder(r.Body).Decode(&ticket); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	sess, deltas, err := s.proxy.ResumeHealingTunnel(&ticket)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "resumed",
		"session":       sess,
		"missed_events": deltas,
		"missed_count":  len(deltas),
	})
}

type quotaBorrowRequest struct {
	BorrowerTenant  string `json:"borrower_tenant"`
	LenderTenant    string `json:"lender_tenant"`
	Amount          int64  `json:"amount"`
	DurationMinutes int64  `json:"duration_minutes"`
}

func (s *AppServer) handleHealingQuotaBorrow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req quotaBorrowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.BorrowerTenant) == "" || strings.TrimSpace(req.LenderTenant) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "borrower_tenant and lender_tenant are required"})
		return
	}
	if req.Amount <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "amount must be positive"})
		return
	}

	duration := 15 * time.Minute
	if req.DurationMinutes > 0 {
		duration = time.Duration(req.DurationMinutes) * time.Minute
	}

	lease, err := s.proxy.BorrowHealingQuota(r.Context(), req.BorrowerTenant, req.LenderTenant, req.Amount, duration)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"lease":  lease,
	})
}

type leaseActionRequest struct {
	LeaseID string `json:"lease_id"`
	Reason  string `json:"reason,omitempty"`
}

func (s *AppServer) handleHealingQuotaReturn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req leaseActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.LeaseID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "lease_id is required"})
		return
	}

	if err := s.proxy.ReturnHealingQuota(r.Context(), req.LeaseID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "returned",
		"lease_id": req.LeaseID,
	})
}

func (s *AppServer) handleHealingQuotaRecall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req leaseActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.LeaseID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "lease_id is required"})
		return
	}

	if err := s.proxy.RecallHealingQuota(r.Context(), req.LeaseID, req.Reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "recalled",
		"lease_id": req.LeaseID,
	})
}

func (s *AppServer) handleHealingQuotaRebalance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	events := s.proxy.RebalanceHealingQuotas(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "rebalanced",
		"events": events,
	})
}
