package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/zerotrust"
)

// registerZeroTrustRoutes mounts REST endpoints for the Zero-Trust mesh and mTLS peer enforcement.
func (s *AppServer) registerZeroTrustRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/zerotrust/status", s.handleZeroTrustStatus)
	apiMux.HandleFunc("/api/zerotrust/peers", s.handleZeroTrustPeers)
	apiMux.HandleFunc("/api/zerotrust/peers/enroll", s.handleZeroTrustEnrollPeer)
	apiMux.HandleFunc("/api/zerotrust/peers/revoke", s.handleZeroTrustRevokePeer)
	apiMux.HandleFunc("/api/zerotrust/ca/rotate", s.handleZeroTrustRotateCA)
	apiMux.HandleFunc("/api/zerotrust/hsm/status", s.handleZeroTrustHSMStatus)
	apiMux.HandleFunc("/api/zerotrust/verify", s.handleZeroTrustVerifyPeer)
}

func (s *AppServer) handleZeroTrustStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetZeroTrustStatus())
}

func (s *AppServer) handleZeroTrustPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := s.proxy.ZeroTrustManager()
	if mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Zero-Trust manager unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"peers": mgr.ListPeers(),
	})
}

func (s *AppServer) handleZeroTrustEnrollPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req zerotrust.EnrollPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.NodeID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_id is required"})
		return
	}

	resp, err := s.proxy.EnrollZeroTrustPeer(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"enrollment":  resp,
	})
}

func (s *AppServer) handleZeroTrustRevokePeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req zerotrust.RevokePeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	if strings.TrimSpace(req.NodeID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_id is required"})
		return
	}

	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "Administrative revocation"
	}

	err := s.proxy.RevokeZeroTrustPeer(r.Context(), req)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, zerotrust.ErrPeerNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"node_id": req.NodeID,
		"revoked": true,
		"reason":  req.Reason,
	})
}

func (s *AppServer) handleZeroTrustRotateCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ValidityDays int `json:"validity_days"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}

	err := s.proxy.RotateZeroTrustCA(r.Context(), req.ValidityDays)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	status := s.proxy.GetZeroTrustStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "success",
		"message":           "Internal CA successfully rotated",
		"root_fingerprint":  status.CARootFingerprint,
		"ca_expires_at":     status.CAExpiresAt,
	})
}

func (s *AppServer) handleZeroTrustHSMStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	slots := s.proxy.GetZeroTrustHSMStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hsm_enabled": true,
		"slots_count": len(slots),
		"slots":       slots,
	})
}

func (s *AppServer) handleZeroTrustVerifyPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req zerotrust.PeerIdentity
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	valid, reason := s.proxy.VerifyZeroTrustPeer(r.Context(), &req)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   valid,
		"reason":  reason,
		"node_id": req.NodeID,
	})
}
