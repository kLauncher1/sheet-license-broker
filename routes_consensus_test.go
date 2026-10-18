package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/consensus"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func setupConsensusTestServer(t *testing.T) (*AppServer, *http.ServeMux) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		NodeID:         "test-server-node-1",
		ClusterRegion:  "us-east-1",
		ClusterAddress: "http://localhost:9082",
		OfflineMode:    true,
	})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	guard := security.NewGuard([]byte("test-secret"), 5*time.Minute, false)
	server := &AppServer{proxy: px, guard: guard}

	apiMux := http.NewServeMux()
	server.registerConsensusRoutes(apiMux)

	mux := http.NewServeMux()
	mux.Handle("/api/", apiMux)

	return server, mux
}

func TestRoutesConsensusStatusAndPeers(t *testing.T) {
	server, mux := setupConsensusTestServer(t)
	defer server.proxy.Close()

	// 1. GET /api/consensus/status
	req := httptest.NewRequest(http.MethodGet, "/api/consensus/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 on /api/consensus/status, got %d", w.Code)
	}

	var status consensus.ClusterStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to unmarshal status: %v", err)
	}
	if status.NodeID != "test-server-node-1" {
		t.Fatalf("expected NodeID 'test-server-node-1', got %s", status.NodeID)
	}
	if status.Region != "us-east-1" {
		t.Fatalf("expected Region 'us-east-1', got %s", status.Region)
	}

	// 2. POST /api/consensus/peers/join
	joinBody := []byte(`{"id":"peer-tokyo-1","address":"http://tokyo.broker:9082","region":"ap-northeast-1"}`)
	reqJoin := httptest.NewRequest(http.MethodPost, "/api/consensus/peers/join", bytes.NewReader(joinBody))
	reqJoin.Header.Set("Content-Type", "application/json")
	wJoin := httptest.NewRecorder()
	mux.ServeHTTP(wJoin, reqJoin)

	if wJoin.Code != http.StatusOK {
		t.Fatalf("expected status 200 on /api/consensus/peers/join, got %d", wJoin.Code)
	}

	// 3. GET /api/consensus/peers
	reqPeers := httptest.NewRequest(http.MethodGet, "/api/consensus/peers", nil)
	wPeers := httptest.NewRecorder()
	mux.ServeHTTP(wPeers, reqPeers)

	if wPeers.Code != http.StatusOK {
		t.Fatalf("expected status 200 on /api/consensus/peers, got %d", wPeers.Code)
	}

	var peersResp struct {
		Status string               `json:"status"`
		Peers  []consensus.PeerNode `json:"peers"`
	}
	if err := json.Unmarshal(wPeers.Body.Bytes(), &peersResp); err != nil {
		t.Fatalf("failed to unmarshal peers: %v", err)
	}
	if len(peersResp.Peers) != 1 || peersResp.Peers[0].ID != "peer-tokyo-1" {
		t.Fatalf("expected 1 peer 'peer-tokyo-1', got %+v", peersResp.Peers)
	}
}

func TestRoutesConsensusRaftRPCs(t *testing.T) {
	server, mux := setupConsensusTestServer(t)
	defer server.proxy.Close()

	// 1. POST /api/consensus/raft/vote
	voteReq := consensus.VoteRequest{
		Term:         5,
		CandidateID:  "candidate-london",
		LastLogIndex: 0,
		LastLogTerm:  0,
	}
	voteBytes, _ := json.Marshal(voteReq)
	reqVote := httptest.NewRequest(http.MethodPost, "/api/consensus/raft/vote", bytes.NewReader(voteBytes))
	reqVote.Header.Set("Content-Type", "application/json")
	wVote := httptest.NewRecorder()
	mux.ServeHTTP(wVote, reqVote)

	if wVote.Code != http.StatusOK {
		t.Fatalf("expected status 200 on /api/consensus/raft/vote, got %d", wVote.Code)
	}

	var voteResp consensus.VoteResponse
	if err := json.Unmarshal(wVote.Body.Bytes(), &voteResp); err != nil {
		t.Fatalf("failed to unmarshal vote response: %v", err)
	}
	if !voteResp.VoteGranted {
		t.Fatalf("expected vote to be granted for higher term 5")
	}

	// 2. POST /api/consensus/raft/append
	appendReq := consensus.AppendEntriesRequest{
		Term:         5,
		LeaderID:     "candidate-london",
		PrevLogIndex: 0,
		PrevLogTerm:  0,
		LeaderCommit: 0,
	}
	appendBytes, _ := json.Marshal(appendReq)
	reqAppend := httptest.NewRequest(http.MethodPost, "/api/consensus/raft/append", bytes.NewReader(appendBytes))
	reqAppend.Header.Set("Content-Type", "application/json")
	wAppend := httptest.NewRecorder()
	mux.ServeHTTP(wAppend, reqAppend)

	if wAppend.Code != http.StatusOK {
		t.Fatalf("expected status 200 on /api/consensus/raft/append, got %d", wAppend.Code)
	}

	var appendResp consensus.AppendEntriesResponse
	if err := json.Unmarshal(wAppend.Body.Bytes(), &appendResp); err != nil {
		t.Fatalf("failed to unmarshal append response: %v", err)
	}
	if !appendResp.Success {
		t.Fatalf("expected heartbeat append to succeed: %s", appendResp.Reason)
	}
}

func TestRoutesConsensusCRDTSync(t *testing.T) {
	server, mux := setupConsensusTestServer(t)
	defer server.proxy.Close()

	crdtReq := consensus.CRDTSyncPayload{
		NodeID:    "remote-peer-sydney",
		AddSet:    map[string]int64{"LIC-SYDNEY-100": time.Now().UnixNano()},
		Payloads:  map[string]string{"LIC-SYDNEY-100": `{"tier":"pro"}`},
		RemoveSet: make(map[string]int64),
		Counters:  map[string]int64{"P:total_ops": 10},
	}
	crdtBytes, _ := json.Marshal(crdtReq)

	req := httptest.NewRequest(http.MethodPost, "/api/consensus/crdt/sync", bytes.NewReader(crdtBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 on /api/consensus/crdt/sync, got %d", w.Code)
	}

	var resp consensus.CRDTSyncPayload
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal crdt response: %v", err)
	}
	if resp.NodeID != "test-server-node-1" {
		t.Fatalf("expected local node ID in sync response, got %s", resp.NodeID)
	}
}
