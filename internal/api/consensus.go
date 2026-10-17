package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/consensus"
)

// handleConsensusStatus returns real-time Raft role, quorum health, and cluster topology.
func (s *Server) handleConsensusStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.ClusterStatus())
}

// handleConsensusPeers returns active peer nodes in the consensus mesh.
func (s *Server) handleConsensusPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"peers":  s.proxy.ClusterPeers(),
	})
}

// handleConsensusPeerJoin dynamically registers a new peer in the cluster.
func (s *Server) handleConsensusPeerJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID      string `json:"id"`
		Address string `json:"address"`
		Region  string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.Address = strings.TrimSpace(req.Address)
	if req.Address == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer address is required"})
		return
	}
	if req.ID == "" {
		req.ID = req.Address
	}
	if req.Region == "" {
		req.Region = "remote-region"
	}

	s.proxy.JoinCluster(consensus.PeerNode{
		ID:      req.ID,
		Address: req.Address,
		Region:  req.Region,
		Active:  true,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Peer joined consensus cluster successfully",
		"peer":    req,
	})
}

// handleConsensusRaftVote handles inbound Raft RequestVote RPCs.
func (s *Server) handleConsensusRaftVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req consensus.VoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid vote request"})
		return
	}

	resp := s.proxy.HandleRaftVote(req)
	writeJSON(w, http.StatusOK, resp)
}

// handleConsensusRaftAppend handles inbound Raft AppendEntries (heartbeat/replication) RPCs.
func (s *Server) handleConsensusRaftAppend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req consensus.AppendEntriesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid append request"})
		return
	}

	resp := s.proxy.HandleRaftAppend(req)
	writeJSON(w, http.StatusOK, resp)
}

// handleConsensusCRDTSync handles state-based CRDT anti-entropy sync requests.
func (s *Server) handleConsensusCRDTSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req consensus.CRDTSyncPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid crdt payload"})
		return
	}

	resp := s.proxy.HandleCRDTSync(req)
	writeJSON(w, http.StatusOK, resp)
}

// handleConsensusSyncTrigger initiates anti-entropy state synchronization with a peer.
func (s *Server) handleConsensusSyncTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PeerID string `json:"peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PeerID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer_id is required"})
		return
	}

	mutations, err := s.proxy.TriggerAntiEntropySync(r.Context(), req.PeerID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "success",
		"mutations": mutations,
		"message":   "Anti-entropy synchronization completed",
	})
}

// registerConsensusRoutes wires distributed consensus and quorum endpoints onto the API mux.
func (s *Server) registerConsensusRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/consensus/status", s.handleConsensusStatus)
	apiMux.HandleFunc("/api/consensus/peers", s.handleConsensusPeers)
	apiMux.HandleFunc("/api/consensus/peers/join", s.handleConsensusPeerJoin)
	apiMux.HandleFunc("/api/consensus/raft/vote", s.handleConsensusRaftVote)
	apiMux.HandleFunc("/api/consensus/raft/append", s.handleConsensusRaftAppend)
	apiMux.HandleFunc("/api/consensus/crdt/sync", s.handleConsensusCRDTSync)
	apiMux.HandleFunc("/api/consensus/sync/trigger", s.handleConsensusSyncTrigger)
}
