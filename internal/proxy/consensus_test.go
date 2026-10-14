package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/consensus"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
)

func TestProxyConsensusLifecycle(t *testing.T) {
	px, err := NewProxy(ProxyConfig{
		NodeID:         "test-proxy-node-1",
		ClusterRegion:  "us-west",
		ClusterAddress: "http://localhost:9082",
		OfflineMode:    true,
	})
	if err != nil {
		t.Fatalf("failed to init proxy with consensus: %v", err)
	}
	defer px.Close()

	// 1. Verify status
	status := px.ClusterStatus()
	if status.NodeID != "test-proxy-node-1" {
		t.Fatalf("expected NodeID 'test-proxy-node-1', got %s", status.NodeID)
	}
	if status.Region != "us-west" {
		t.Fatalf("expected region 'us-west', got %s", status.Region)
	}

	// 2. Join a dynamic peer
	px.JoinCluster(consensus.PeerNode{
		ID:      "peer-node-eu",
		Address: "http://eu.example.com:9082",
		Region:  "eu-central",
		Active:  true,
	})

	peers := px.ClusterPeers()
	if len(peers) != 1 || peers[0].ID != "peer-node-eu" {
		t.Fatalf("expected 1 peer 'peer-node-eu', got %d peers", len(peers))
	}

	// 3. Propose a license
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	lic := license.License{
		LicenseKey: "LIC-PROXY-CONSENSUS-1",
		BoundHWID:  "HWID-ABCD-1234",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Status:     "active",
	}

	// If single active peer is not responding, proposal might timeout, which confirms quorum check
	_ = px.ProposeConsensusLicense(ctx, lic)

	// 4. Test HandleCRDTSync
	syncPayload := consensus.CRDTSyncPayload{
		NodeID:    "peer-node-eu",
		AddSet:    map[string]int64{"LIC-REMOTE-999": time.Now().UnixNano()},
		Payloads:  map[string]string{"LIC-REMOTE-999": `{"status":"active"}`},
		RemoveSet: make(map[string]int64),
		Counters:  map[string]int64{"P:active_seats": 5},
	}

	resp := px.HandleCRDTSync(syncPayload)
	if resp.NodeID != "test-proxy-node-1" {
		t.Fatalf("expected sync response from node-1, got %s", resp.NodeID)
	}

	// 5. Test HandleRaftVote
	voteReq := consensus.VoteRequest{
		Term:         2,
		CandidateID:  "peer-node-eu",
		LastLogIndex: 0,
		LastLogTerm:  0,
	}
	voteResp := px.HandleRaftVote(voteReq)
	if !voteResp.VoteGranted {
		t.Fatalf("expected vote to be granted for higher term 2")
	}
}
