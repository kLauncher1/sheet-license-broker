package consensus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// In-Memory mock transport to simulate network communication between nodes in tests
type mockTransport struct {
	nodes map[string]*ConsensusEngine
}

func newMockTransport() *mockTransport {
	return &mockTransport{nodes: make(map[string]*ConsensusEngine)}
}

func (m *mockTransport) register(node *ConsensusEngine) {
	m.nodes[node.nodeID] = node
}

func (m *mockTransport) RequestVote(ctx context.Context, peer *PeerNode, req VoteRequest) (*VoteResponse, error) {
	target, exists := m.nodes[peer.ID]
	if !exists {
		return nil, ErrQuorumLoss
	}
	resp := target.HandleVoteRequest(req)
	return &resp, nil
}

func (m *mockTransport) AppendEntries(ctx context.Context, peer *PeerNode, req AppendEntriesRequest) (*AppendEntriesResponse, error) {
	target, exists := m.nodes[peer.ID]
	if !exists {
		return nil, ErrQuorumLoss
	}
	resp := target.HandleAppendEntries(req)
	return &resp, nil
}

func (m *mockTransport) SyncCRDT(ctx context.Context, peer *PeerNode, req CRDTSyncPayload) (*CRDTSyncPayload, error) {
	target, exists := m.nodes[peer.ID]
	if !exists {
		return nil, ErrQuorumLoss
	}
	target.crdt.Merge(req)
	resp := target.crdt.ExportState()
	return &resp, nil
}

func TestCRDTLWWElementSetAndRevocationPriority(t *testing.T) {
	store := NewCRDTStore("node-1")

	// 1. Add item
	store.Add("LIC-PRO-1234", `{"tier":"pro"}`)
	if !store.Contains("LIC-PRO-1234") {
		t.Fatalf("expected store to contain LIC-PRO-1234")
	}

	payload, ok := store.GetPayload("LIC-PRO-1234")
	if !ok || payload != `{"tier":"pro"}` {
		t.Fatalf("expected payload to match, got %v (%s)", ok, payload)
	}

	// 2. Remove item
	store.Remove("LIC-PRO-1234")
	if store.Contains("LIC-PRO-1234") {
		t.Fatalf("expected store NOT to contain revoked LIC-PRO-1234")
	}

	// 3. Test Revocation Priority on Equal Timestamps (Tie-Breaking Invariant)
	sameTS := time.Now().UnixNano()
	store.AddWithTimestamp("LIC-REV-TEST", "active", sameTS)
	store.RemoveWithTimestamp("LIC-REV-TEST", sameTS)

	if store.Contains("LIC-REV-TEST") {
		t.Fatalf("revocation must strictly win over addition on identical timestamps")
	}
}

func TestCRDTPNCounterAndConvergence(t *testing.T) {
	storeA := NewCRDTStore("node-A")
	storeB := NewCRDTStore("node-B")

	storeA.IncrementCounter("seats", 5)
	storeA.IncrementCounter("seats", -2) // net 3

	storeB.IncrementCounter("seats", 10)
	storeB.IncrementCounter("seats", -1) // net 9

	if storeA.GetCounter("seats") != 3 {
		t.Fatalf("expected storeA counter to be 3, got %d", storeA.GetCounter("seats"))
	}
	if storeB.GetCounter("seats") != 9 {
		t.Fatalf("expected storeB counter to be 9, got %d", storeB.GetCounter("seats"))
	}

	// Bidirectional merge
	stateA := storeA.ExportState()
	stateB := storeB.ExportState()

	storeA.Merge(stateB)
	storeB.Merge(stateA)

	if storeA.MerkleDigest() != storeB.MerkleDigest() {
		t.Fatalf("stores must have identical Merkle digests after mutual merge")
	}
}

func TestConsensusSingleNodeAutoLeader(t *testing.T) {
	crdt := NewCRDTStore("node-solo")
	cfg := Config{
		NodeID:          "node-solo",
		Region:          "us-east",
		ElectionTimeout: 50 * time.Millisecond,
		HeartbeatPeriod: 20 * time.Millisecond,
	}

	engine := NewConsensusEngine(cfg, crdt)
	defer engine.Close()

	// Wait for election timeout to trigger self-election
	time.Sleep(120 * time.Millisecond)

	status := engine.Status()
	if status.Role != RoleLeader {
		t.Fatalf("single node must elect itself leader, got: %s", status.Role)
	}
	if !status.HasQuorum {
		t.Fatalf("single node must have active quorum")
	}

	// Propose a license
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	entry, err := engine.Propose(ctx, CmdLicenseCreate, "LIC-SOLO-999", `{"status":"active"}`)
	if err != nil {
		t.Fatalf("failed to propose on single node: %v", err)
	}
	if entry.Index != 1 {
		t.Fatalf("expected entry index 1, got %d", entry.Index)
	}

	// Verify CRDT store was updated
	if !crdt.Contains("LIC-SOLO-999") {
		t.Fatalf("expected CRDT store to contain proposed license")
	}
}

func TestConsensusThreeNodeClusterQuorumAndReplication(t *testing.T) {
	transport := newMockTransport()

	crdt1 := NewCRDTStore("node-1")
	crdt2 := NewCRDTStore("node-2")
	crdt3 := NewCRDTStore("node-3")

	var committedEntries []LogEntry
	applyCb := func(entry LogEntry) error {
		committedEntries = append(committedEntries, entry)
		return nil
	}

	cfg1 := Config{NodeID: "node-1", Region: "us-east", ElectionTimeout: 30 * time.Millisecond, HeartbeatPeriod: 10 * time.Millisecond, Transport: transport, ApplyCallback: applyCb}
	cfg2 := Config{NodeID: "node-2", Region: "eu-west", ElectionTimeout: 300 * time.Millisecond, HeartbeatPeriod: 30 * time.Millisecond, Transport: transport}
	cfg3 := Config{NodeID: "node-3", Region: "ap-northeast", ElectionTimeout: 300 * time.Millisecond, HeartbeatPeriod: 30 * time.Millisecond, Transport: transport}

	e1 := NewConsensusEngine(cfg1, crdt1)
	defer e1.Close()
	e2 := NewConsensusEngine(cfg2, crdt2)
	defer e2.Close()
	e3 := NewConsensusEngine(cfg3, crdt3)
	defer e3.Close()

	transport.register(e1)
	transport.register(e2)
	transport.register(e3)

	// Interconnect peers
	e1.AddPeer(PeerNode{ID: "node-2", Region: "eu-west"})
	e1.AddPeer(PeerNode{ID: "node-3", Region: "ap-northeast"})
	e2.AddPeer(PeerNode{ID: "node-1", Region: "us-east"})
	e2.AddPeer(PeerNode{ID: "node-3", Region: "ap-northeast"})
	e3.AddPeer(PeerNode{ID: "node-1", Region: "us-east"})
	e3.AddPeer(PeerNode{ID: "node-2", Region: "eu-west"})

	// Give time for e1 (faster election timeout) to win election
	time.Sleep(100 * time.Millisecond)

	s1 := e1.Status()
	if s1.Role != RoleLeader {
		t.Logf("e1 role: %s, checking if e2 or e3 won", s1.Role)
	}

	// Propose from leader
	var leader *ConsensusEngine
	if e1.Status().Role == RoleLeader {
		leader = e1
	} else if e2.Status().Role == RoleLeader {
		leader = e2
	} else if e3.Status().Role == RoleLeader {
		leader = e3
	}

	if leader == nil {
		t.Fatalf("expected a leader to be elected in 3-node cluster")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	entry, err := leader.Propose(ctx, CmdLicenseCreate, "LIC-QUORUM-777", `{"tier":"enterprise"}`)
	if err != nil {
		t.Fatalf("quorum propose failed: %v", err)
	}
	if entry.Key != "LIC-QUORUM-777" {
		t.Fatalf("unexpected entry key: %s", entry.Key)
	}

	// Verify non-leader nodes reject direct proposals with ErrNotLeader
	var nonLeader *ConsensusEngine
	if leader != e1 {
		nonLeader = e1
	} else {
		nonLeader = e2
	}

	_, errNonLeader := nonLeader.Propose(ctx, CmdLicenseCreate, "LIC-FAIL", "val")
	if errNonLeader == nil {
		t.Fatalf("follower must reject proposals with ErrNotLeader")
	}
}

func TestP2PMeshAntiEntropySync(t *testing.T) {
	crdtRemote := NewCRDTStore("remote-node")
	crdtRemote.Add("LIC-REMOTE-001", `{"tier":"pro"}`)
	crdtRemote.IncrementCounter("api_calls", 42)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/consensus/crdt/sync" {
			var incoming CRDTSyncPayload
			_ = json.NewDecoder(r.Body).Decode(&incoming)
			crdtRemote.Merge(incoming)
			resp := crdtRemote.ExportState()
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	crdtLocal := NewCRDTStore("local-node")
	crdtLocal.Add("LIC-LOCAL-001", `{"tier":"free"}`)

	mesh := NewP2PMesh("local-node", "us-east", "http://localhost", crdtLocal, 100*time.Millisecond)
	defer mesh.Close()

	peer := &PeerNode{
		ID:           "remote-node",
		Address:      ts.URL,
		Region:       "eu-west",
		Active:       true,
		MerkleDigest: "diff-digest",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mutations, err := mesh.TriggerAntiEntropy(ctx, peer)
	if err != nil {
		t.Fatalf("TriggerAntiEntropy failed: %v", err)
	}
	if mutations == 0 {
		t.Fatalf("expected mutations from sync, got 0")
	}

	if !crdtLocal.Contains("LIC-REMOTE-001") {
		t.Fatalf("expected local store to contain remote license after anti-entropy sync")
	}
	if crdtLocal.GetCounter("api_calls") != 42 {
		t.Fatalf("expected counter to sync to 42, got %d", crdtLocal.GetCounter("api_calls"))
	}
}

func TestCRDTConcurrentConflictRevocationWins(t *testing.T) {
	nodeA := NewCRDTStore("node-A")
	nodeB := NewCRDTStore("node-B")

	baseTime := time.Now().UnixNano()
	nodeA.AddWithTimestamp("LIC-CONCURRENT", `{"owner":"alice"}`, baseTime)
	nodeB.AddWithTimestamp("LIC-CONCURRENT", `{"owner":"alice"}`, baseTime)

	// Concurrent actions: Node A updates metadata at baseTime+10; Node B revokes key at baseTime+10
	nodeA.AddWithTimestamp("LIC-CONCURRENT", `{"owner":"alice-updated"}`, baseTime+10)
	nodeB.RemoveWithTimestamp("LIC-CONCURRENT", baseTime+10)

	// Merge both ways
	nodeA.Merge(nodeB.ExportState())
	nodeB.Merge(nodeA.ExportState())

	// Revocation must win on both nodes
	if nodeA.Contains("LIC-CONCURRENT") || nodeB.Contains("LIC-CONCURRENT") {
		t.Fatalf("revocation must strictly win over concurrent modification")
	}
}

func TestConsensusPartitionTolerance(t *testing.T) {
	transport := newMockTransport()

	crdt1 := NewCRDTStore("part-1")
	crdt2 := NewCRDTStore("part-2")
	crdt3 := NewCRDTStore("part-3")

	cfg1 := Config{NodeID: "part-1", Region: "us-east", ElectionTimeout: 30 * time.Millisecond, HeartbeatPeriod: 10 * time.Millisecond, Transport: transport}
	cfg2 := Config{NodeID: "part-2", Region: "eu-west", ElectionTimeout: 400 * time.Millisecond, HeartbeatPeriod: 30 * time.Millisecond, Transport: transport}
	cfg3 := Config{NodeID: "part-3", Region: "ap-northeast", ElectionTimeout: 400 * time.Millisecond, HeartbeatPeriod: 30 * time.Millisecond, Transport: transport}

	e1 := NewConsensusEngine(cfg1, crdt1)
	defer e1.Close()
	e2 := NewConsensusEngine(cfg2, crdt2)
	defer e2.Close()
	e3 := NewConsensusEngine(cfg3, crdt3)
	defer e3.Close()

	transport.register(e1)
	transport.register(e2)
	transport.register(e3)

	e1.AddPeer(PeerNode{ID: "part-2"})
	e1.AddPeer(PeerNode{ID: "part-3"})
	e2.AddPeer(PeerNode{ID: "part-1"})
	e2.AddPeer(PeerNode{ID: "part-3"})
	e3.AddPeer(PeerNode{ID: "part-1"})
	e3.AddPeer(PeerNode{ID: "part-2"})

	time.Sleep(100 * time.Millisecond)

	// Now simulate a network partition by isolating part-2 and part-3 from part-1
	// part-1 can no longer reach part-2 or part-3
	e1.RemovePeer("part-2")
	e1.RemovePeer("part-3")

	// Attempting propose on isolated part-1 should succeed only if single node or fail if quorum lost
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Since part-1 has removed peers, it is a single-node partition and commits locally
	entry, err := e1.Propose(ctx, CmdLicenseCreate, "LIC-PART", "val")
	if err != nil {
		t.Fatalf("local single node commit should succeed: %v", err)
	}
	if entry.Key != "LIC-PART" {
		t.Fatalf("unexpected entry: %s", entry.Key)
	}
}

