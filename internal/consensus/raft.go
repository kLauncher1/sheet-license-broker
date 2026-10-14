package consensus

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNotLeader     = errors.New("node is not the cluster leader")
	ErrQuorumLoss    = errors.New("quorum consensus lost; partition detected")
	ErrProposalStale = errors.New("proposal superseded by higher term")
)

// ApplyCallback is invoked whenever a log entry is successfully committed by majority quorum.
type ApplyCallback func(entry LogEntry) error

// ConsensusEngine coordinates Raft-like quorum consensus and distributed state replication.
type ConsensusEngine struct {
	mu           sync.RWMutex
	nodeID       string
	region       string
	currentTerm  uint64
	votedFor     string
	role         NodeRole
	leaderID     string
	log          []LogEntry
	commitIndex  uint64
	lastApplied  uint64
	peers        map[string]*PeerNode
	crdt         *CRDTStore
	applyCb      ApplyCallback
	rpcTransport RPCTransport

	electionTimeout time.Duration
	heartbeatPeriod time.Duration
	lastHeartbeat   time.Time

	stopCh    chan struct{}
	proposeCh chan struct{}
}

// RPCTransport defines the network dispatch interface for consensus messages.
type RPCTransport interface {
	RequestVote(ctx context.Context, peer *PeerNode, req VoteRequest) (*VoteResponse, error)
	AppendEntries(ctx context.Context, peer *PeerNode, req AppendEntriesRequest) (*AppendEntriesResponse, error)
	SyncCRDT(ctx context.Context, peer *PeerNode, req CRDTSyncPayload) (*CRDTSyncPayload, error)
}

// Config configures a ConsensusEngine node.
type Config struct {
	NodeID          string
	Region          string
	ElectionTimeout time.Duration
	HeartbeatPeriod time.Duration
	Transport       RPCTransport
	ApplyCallback   ApplyCallback
}

// NewConsensusEngine creates and starts a distributed consensus engine.
func NewConsensusEngine(cfg Config, crdt *CRDTStore) *ConsensusEngine {
	if cfg.ElectionTimeout == 0 {
		cfg.ElectionTimeout = 300 * time.Millisecond
	}
	if cfg.HeartbeatPeriod == 0 {
		cfg.HeartbeatPeriod = 100 * time.Millisecond
	}
	if cfg.Region == "" {
		cfg.Region = "local-node"
	}

	engine := &ConsensusEngine{
		nodeID:          cfg.NodeID,
		region:          cfg.Region,
		role:            RoleFollower,
		log:             make([]LogEntry, 0),
		peers:           make(map[string]*PeerNode),
		crdt:            crdt,
		applyCb:         cfg.ApplyCallback,
		rpcTransport:    cfg.Transport,
		electionTimeout: cfg.ElectionTimeout,
		heartbeatPeriod: cfg.HeartbeatPeriod,
		lastHeartbeat:   time.Now(),
		stopCh:          make(chan struct{}),
		proposeCh:       make(chan struct{}, 64),
	}

	// Seed with dummy entry 0 to align 1-based indexing
	engine.log = append(engine.log, LogEntry{Index: 0, Term: 0})

	go engine.runLoop()
	return engine
}

// Close gracefully stops the consensus background loop.
func (e *ConsensusEngine) Close() {
	select {
	case <-e.stopCh:
		return
	default:
		close(e.stopCh)
	}
}

// AddPeer registers a new peer in the cluster topology.
func (e *ConsensusEngine) AddPeer(peer PeerNode) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if peer.ID == e.nodeID {
		return
	}
	peer.Active = true
	peer.LastSeen = time.Now()
	peer.NextIndex = uint64(len(e.log))
	peer.MatchIndex = 0
	e.peers[peer.ID] = &peer
}

// RemovePeer unregisters a peer node from the cluster.
func (e *ConsensusEngine) RemovePeer(peerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.peers, peerID)
}

// Status returns a point-in-time snapshot of the node's cluster telemetry.
func (e *ConsensusEngine) Status() ClusterStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	activePeers := 0
	var peerList []PeerNode
	for _, p := range e.peers {
		peerCopy := *p
		if time.Since(p.LastSeen) < 3*e.electionTimeout {
			peerCopy.Active = true
			activePeers++
		} else {
			peerCopy.Active = false
		}
		peerList = append(peerList, peerCopy)
	}

	totalNodes := len(e.peers) + 1
	quorumSize := (totalNodes / 2) + 1
	hasQuorum := (activePeers + 1) >= quorumSize

	digest := ""
	if e.crdt != nil {
		digest = e.crdt.MerkleDigest()
	}

	return ClusterStatus{
		NodeID:       e.nodeID,
		Region:       e.region,
		Role:         e.role,
		CurrentTerm:  e.currentTerm,
		LeaderID:     e.leaderID,
		CommitIndex:  e.commitIndex,
		LastLogIndex: uint64(len(e.log) - 1),
		PeerCount:    len(e.peers),
		ActivePeers:  activePeers,
		QuorumSize:   quorumSize,
		HasQuorum:    hasQuorum,
		MerkleDigest: digest,
		Peers:        peerList,
	}
}

// Propose appends an operation to the distributed log and awaits majority quorum commit.
func (e *ConsensusEngine) Propose(ctx context.Context, cmdType CommandType, key, value string) (*LogEntry, error) {
	e.mu.Lock()
	if e.role != RoleLeader {
		leader := e.leaderID
		e.mu.Unlock()
		return nil, fmt.Errorf("%w: current leader is '%s'", ErrNotLeader, leader)
	}

	totalNodes := len(e.peers) + 1
	quorumNeeded := (totalNodes / 2) + 1

	entry := LogEntry{
		Index:     uint64(len(e.log)),
		Term:      e.currentTerm,
		Type:      cmdType,
		Key:       key,
		Value:     value,
		Timestamp: time.Now().UnixNano(),
		NodeID:    e.nodeID,
	}
	entry.Hash = entry.ComputeHash()
	e.log = append(e.log, entry)
	targetIndex := entry.Index
	curTerm := e.currentTerm
	e.mu.Unlock()

	// If single node cluster, commit immediately
	if len(e.peers) == 0 {
		e.commitEntry(entry)
		return &entry, nil
	}

	// Trigger replication to peers
	e.broadcastAppendEntries()

	// Wait for majority consensus or context cancellation
	deadline := time.Now().Add(3 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.stopCh:
			return nil, errors.New("consensus engine stopped")
		case <-ticker.C:
			e.mu.RLock()
			if e.currentTerm > curTerm || e.role != RoleLeader {
				e.mu.RUnlock()
				return nil, ErrProposalStale
			}

			// Count replicas that have acknowledged targetIndex
			acks := 1 // self
			for _, peer := range e.peers {
				if peer.MatchIndex >= targetIndex {
					acks++
				}
			}
			committed := e.commitIndex >= targetIndex
			e.mu.RUnlock()

			if acks >= quorumNeeded || committed {
				if !committed {
					e.commitEntry(entry)
				}
				return &entry, nil
			}

			if time.Now().After(deadline) {
				return nil, fmt.Errorf("%w (acks: %d/%d)", ErrQuorumLoss, acks, quorumNeeded)
			}
		}
	}
}

func (e *ConsensusEngine) commitEntry(entry LogEntry) {
	e.mu.Lock()
	if entry.Index > e.commitIndex {
		e.commitIndex = entry.Index
	}
	e.mu.Unlock()

	// Apply to CRDT state store
	if e.crdt != nil {
		switch entry.Type {
		case CmdLicenseCreate:
			e.crdt.AddWithTimestamp(entry.Key, entry.Value, entry.Timestamp)
		case CmdLicenseRevoke, CmdDeviceBlacklist:
			e.crdt.RemoveWithTimestamp(entry.Key, entry.Timestamp)
		case CmdDeviceUnban:
			e.crdt.AddWithTimestamp(entry.Key, entry.Value, entry.Timestamp)
		}
	}

	if e.applyCb != nil {
		_ = e.applyCb(entry)
	}
}

// HandleVoteRequest processes incoming RequestVote RPCs.
func (e *ConsensusEngine) HandleVoteRequest(req VoteRequest) VoteResponse {
	e.mu.Lock()
	defer e.mu.Unlock()

	if req.Term > e.currentTerm {
		e.currentTerm = req.Term
		e.role = RoleFollower
		e.votedFor = ""
	}

	lastIndex := uint64(len(e.log) - 1)
	lastTerm := e.log[lastIndex].Term

	logUpToDate := req.LastLogTerm > lastTerm ||
		(req.LastLogTerm == lastTerm && req.LastLogIndex >= lastIndex)

	if req.Term == e.currentTerm && (e.votedFor == "" || e.votedFor == req.CandidateID) && logUpToDate {
		e.votedFor = req.CandidateID
		e.lastHeartbeat = time.Now()
		return VoteResponse{Term: e.currentTerm, VoteGranted: true}
	}

	return VoteResponse{
		Term:        e.currentTerm,
		VoteGranted: false,
		Reason:      "term outdated or log lagging",
	}
}

// HandleAppendEntries processes incoming AppendEntries RPCs.
func (e *ConsensusEngine) HandleAppendEntries(req AppendEntriesRequest) AppendEntriesResponse {
	e.mu.Lock()
	defer e.mu.Unlock()

	digest := ""
	if e.crdt != nil {
		digest = e.crdt.MerkleDigest()
	}

	if req.Term < e.currentTerm {
		return AppendEntriesResponse{
			Term:         e.currentTerm,
			Success:      false,
			MerkleDigest: digest,
			Reason:       "term outdated",
		}
	}

	if req.Term > e.currentTerm || e.role == RoleCandidate {
		e.currentTerm = req.Term
		e.role = RoleFollower
		e.votedFor = ""
	}

	e.leaderID = req.LeaderID
	e.lastHeartbeat = time.Now()

	// Log consistency verification
	if req.PrevLogIndex >= uint64(len(e.log)) || e.log[req.PrevLogIndex].Term != req.PrevLogTerm {
		return AppendEntriesResponse{
			Term:         e.currentTerm,
			Success:      false,
			MatchIndex:   uint64(len(e.log) - 1),
			MerkleDigest: digest,
			Reason:       "log index/term mismatch",
		}
	}

	// Append missing entries
	for i, entry := range req.Entries {
		idx := req.PrevLogIndex + 1 + uint64(i)
		if idx < uint64(len(e.log)) {
			if e.log[idx].Term != entry.Term {
				e.log = e.log[:idx]
				e.log = append(e.log, entry)
			}
		} else {
			e.log = append(e.log, entry)
		}
	}

	// Advance commit index and apply
	if req.LeaderCommit > e.commitIndex {
		lastNewIndex := req.PrevLogIndex + uint64(len(req.Entries))
		if req.LeaderCommit < lastNewIndex {
			e.commitIndex = req.LeaderCommit
		} else {
			e.commitIndex = lastNewIndex
		}

		for e.lastApplied < e.commitIndex {
			e.lastApplied++
			entryToApply := e.log[e.lastApplied]
			go e.commitEntry(entryToApply)
		}
	}

	matchIdx := uint64(len(e.log) - 1)
	return AppendEntriesResponse{
		Term:         e.currentTerm,
		Success:      true,
		MatchIndex:   matchIdx,
		MerkleDigest: digest,
	}
}

func (e *ConsensusEngine) broadcastAppendEntries() {
	e.mu.Lock()
	if e.role != RoleLeader {
		e.mu.Unlock()
		return
	}
	curTerm := e.currentTerm
	leaderID := e.nodeID
	commitIndex := e.commitIndex
	transport := e.rpcTransport
	peers := make([]*PeerNode, 0, len(e.peers))
	for _, p := range e.peers {
		peers = append(peers, p)
	}
	e.mu.Unlock()

	if transport == nil {
		return
	}

	digest := ""
	if e.crdt != nil {
		digest = e.crdt.MerkleDigest()
	}

	for _, p := range peers {
		peer := p
		go func() {
			e.mu.RLock()
			prevIndex := peer.NextIndex - 1
			if prevIndex >= uint64(len(e.log)) {
				prevIndex = uint64(len(e.log) - 1)
			}
			prevTerm := e.log[prevIndex].Term
			entries := make([]LogEntry, 0)
			if uint64(len(e.log)) > peer.NextIndex {
				entries = append(entries, e.log[peer.NextIndex:]...)
			}
			e.mu.RUnlock()

			req := AppendEntriesRequest{
				Term:         curTerm,
				LeaderID:     leaderID,
				PrevLogIndex: prevIndex,
				PrevLogTerm:  prevTerm,
				Entries:      entries,
				LeaderCommit: commitIndex,
				MerkleDigest: digest,
			}

			ctx, cancel := context.WithTimeout(context.Background(), e.heartbeatPeriod)
			defer cancel()

			res, err := transport.AppendEntries(ctx, peer, req)
			if err != nil || res == nil {
				return
			}

			e.mu.Lock()
			defer e.mu.Unlock()

			peer.LastSeen = time.Now()
			peer.MerkleDigest = res.MerkleDigest

			if res.Term > e.currentTerm {
				e.currentTerm = res.Term
				e.role = RoleFollower
				e.votedFor = ""
				return
			}

			if res.Success {
				peer.MatchIndex = res.MatchIndex
				peer.NextIndex = res.MatchIndex + 1

				totalNodes := len(e.peers) + 1
				quorumNeeded := (totalNodes / 2) + 1
				for N := res.MatchIndex; N > e.commitIndex; N-- {
					if N < uint64(len(e.log)) && e.log[N].Term == curTerm {
						matches := 1
						for _, p2 := range e.peers {
							if p2.MatchIndex >= N {
								matches++
							}
						}
						if matches >= quorumNeeded {
							e.commitIndex = N
							for e.lastApplied < e.commitIndex {
								e.lastApplied++
								entryToApply := e.log[e.lastApplied]
								go e.commitEntry(entryToApply)
							}
							break
						}
					}
				}
			} else if peer.NextIndex > 1 {
				peer.NextIndex--
			}
		}()
	}
}
