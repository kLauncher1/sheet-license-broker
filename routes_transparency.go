package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/transparency"
)

// registerTransparencyRoutes registers REST endpoints for the verifiable Merkle transparency log.
func (s *AppServer) registerTransparencyRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/transparency/status", s.handleTransparencyStatus)
	apiMux.HandleFunc("/api/transparency/append", s.handleTransparencyAppend)
	apiMux.HandleFunc("/api/transparency/sth", s.handleTransparencySTH)
	apiMux.HandleFunc("/api/transparency/entries", s.handleTransparencyEntries)
	apiMux.HandleFunc("/api/transparency/inclusion-proof", s.handleTransparencyInclusionProof)
	apiMux.HandleFunc("/api/transparency/inclusion-proof/verify", s.handleTransparencyVerifyInclusionProof)
	apiMux.HandleFunc("/api/transparency/consistency-proof", s.handleTransparencyConsistencyProof)
	apiMux.HandleFunc("/api/transparency/consistency-proof/verify", s.handleTransparencyVerifyConsistencyProof)
	apiMux.HandleFunc("/api/transparency/witness/cosign", s.handleTransparencyWitnessCosign)
	apiMux.HandleFunc("/api/transparency/witnesses", s.handleTransparencyWitnesses)
}

func (s *AppServer) handleTransparencyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetTransparencyStatus())
}

type transparencyAppendRequest struct {
	Action   string          `json:"action"`
	TenantID string          `json:"tenant_id"`
	Payload  json.RawMessage `json:"payload"`
}

func (s *AppServer) handleTransparencyAppend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req transparencyAppendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = "audit_event"
	}
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}

	entry, sth, err := s.proxy.AppendTransparencyAudit(action, tenantID, req.Payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status": "success",
		"entry":  entry,
		"sth":    sth,
	})
}

func (s *AppServer) handleTransparencySTH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sth := s.proxy.GetTransparencySTH()
	if sth == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no STH published yet"})
		return
	}

	writeJSON(w, http.StatusOK, sth)
}

func (s *AppServer) handleTransparencyEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := int64(0)
	if startStr := r.URL.Query().Get("start"); startStr != "" {
		if val, err := strconv.ParseInt(startStr, 10, 64); err == nil && val >= 0 {
			start = val
		}
	}

	count := int64(20)
	if countStr := r.URL.Query().Get("count"); countStr != "" {
		if val, err := strconv.ParseInt(countStr, 10, 64); err == nil && val > 0 {
			count = val
		}
	}

	entries, err := s.proxy.GetTransparencyEntries(start, count)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"start":   start,
		"count":   len(entries),
		"entries": entries,
	})
}

func (s *AppServer) handleTransparencyInclusionProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idxStr := r.URL.Query().Get("index")
	szStr := r.URL.Query().Get("tree_size")

	idx, err1 := strconv.ParseInt(idxStr, 10, 64)
	sz, err2 := strconv.ParseInt(szStr, 10, 64)
	if err1 != nil || err2 != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "index and tree_size integer parameters required"})
		return
	}

	proof, err := s.proxy.GetTransparencyInclusionProof(idx, sz)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, proof)
}

func (s *AppServer) handleTransparencyVerifyInclusionProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var proof transparency.InclusionProof
	if err := json.NewDecoder(r.Body).Decode(&proof); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid inclusion proof payload"})
		return
	}

	valid := s.proxy.VerifyTransparencyInclusionProof(&proof)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"verified":   valid,
		"leaf_index": proof.LeafIndex,
		"tree_size":  proof.TreeSize,
	})
}

func (s *AppServer) handleTransparencyConsistencyProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	firstStr := r.URL.Query().Get("first")
	secondStr := r.URL.Query().Get("second")

	first, err1 := strconv.ParseInt(firstStr, 10, 64)
	second, err2 := strconv.ParseInt(secondStr, 10, 64)
	if err1 != nil || err2 != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "first and second tree size parameters required"})
		return
	}

	proof, err := s.proxy.GetTransparencyConsistencyProof(first, second)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, proof)
}

func (s *AppServer) handleTransparencyVerifyConsistencyProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var proof transparency.ConsistencyProof
	if err := json.NewDecoder(r.Body).Decode(&proof); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid consistency proof payload"})
		return
	}

	valid := s.proxy.VerifyTransparencyConsistencyProof(&proof)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"verified":    valid,
		"first_size":  proof.FirstSize,
		"second_size": proof.SecondSize,
	})
}

type transparencyCosignRequest struct {
	WitnessID string `json:"witness_id"`
}

func (s *AppServer) handleTransparencyWitnessCosign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req transparencyCosignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	wID := strings.TrimSpace(req.WitnessID)
	if wID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "witness_id is required"})
		return
	}

	sig, err := s.proxy.WitnessCosignTransparency(wID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, sig)
}

func (s *AppServer) handleTransparencyWitnesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	witnesses := s.proxy.ListTransparencyWitnesses()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"witnesses": witnesses,
		"count":     len(witnesses),
	})
}
