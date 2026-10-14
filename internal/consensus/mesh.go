package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// P2PMesh coordinates peer-to-peer heartbeat gossip, RPC network dispatch, and anti-entropy sync.
type P2PMesh struct {
	mu           sync.RWMutex
	nodeID       string
	region       string
	address      string
	httpClient   *http.Client
	crdtStore    *CRDTStore
	engine       *ConsensusEngine
	stopCh       chan struct{}
	gossipPeriod time.Duration
}

// NewP2PMesh initializes and starts a peer-to-peer heartbeat mesh coordinator.
func NewP2PMesh(nodeID, region, address string, crdt *CRDTStore, gossipPeriod time.Duration) *P2PMesh {
	if gossipPeriod == 0 {
		gossipPeriod = 500 * time.Millisecond
	}
	mesh := &P2PMesh{
		nodeID:       nodeID,
		region:       region,
		address:      address,
		crdtStore:    crdt,
		gossipPeriod: gossipPeriod,
		stopCh:       make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
	return mesh
}

// BindEngine attaches the consensus engine to the mesh for anti-entropy and heartbeat coordination.
func (m *P2PMesh) BindEngine(engine *ConsensusEngine) {
	m.mu.Lock()
	m.engine = engine
	m.mu.Unlock()

	go m.runGossipLoop()
}

// Close terminates the P2P background gossip worker.
func (m *P2PMesh) Close() {
	select {
	case <-m.stopCh:
		return
	default:
		close(m.stopCh)
	}
}

// RequestVote sends a Raft RequestVote RPC to a peer node via HTTP.
func (m *P2PMesh) RequestVote(ctx context.Context, peer *PeerNode, req VoteRequest) (*VoteResponse, error) {
	var resp VoteResponse
	err := m.postJSON(ctx, peer.Address, "/api/consensus/raft/vote", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// AppendEntries sends a Raft AppendEntries RPC to a peer node via HTTP.
func (m *P2PMesh) AppendEntries(ctx context.Context, peer *PeerNode, req AppendEntriesRequest) (*AppendEntriesResponse, error) {
	var resp AppendEntriesResponse
	start := time.Now()
	err := m.postJSON(ctx, peer.Address, "/api/consensus/raft/append", req, &resp)
	if err != nil {
		return nil, err
	}
	peer.LatencyMs = time.Since(start).Milliseconds()
	return &resp, nil
}

// SyncCRDT exchanges CRDT state with a peer node to achieve anti-entropy convergence.
func (m *P2PMesh) SyncCRDT(ctx context.Context, peer *PeerNode, req CRDTSyncPayload) (*CRDTSyncPayload, error) {
	var resp CRDTSyncPayload
	err := m.postJSON(ctx, peer.Address, "/api/consensus/crdt/sync", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *P2PMesh) postJSON(ctx context.Context, baseURL, path string, reqObj interface{}, respObj interface{}) error {
	bodyBytes, err := json.Marshal(reqObj)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	url := strings.TrimRight(baseURL, "/") + path
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Consensus-Node", m.nodeID)

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("mesh RPC error (%s): %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mesh RPC failed (%s) with status %d", path, resp.StatusCode)
	}

	if respObj != nil {
		if err := json.NewDecoder(resp.Body).Decode(respObj); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return nil
}

// TriggerAntiEntropy compares the local Merkle digest against a peer and performs bidirectional sync if diverged.
func (m *P2PMesh) TriggerAntiEntropy(ctx context.Context, peer *PeerNode) (mutations int, err error) {
	if m.crdtStore == nil {
		return 0, nil
	}

	localDigest := m.crdtStore.MerkleDigest()
	if peer.MerkleDigest != "" && peer.MerkleDigest == localDigest {
		return 0, nil // Perfectly synchronized
	}

	localPayload := m.crdtStore.ExportState()
	remotePayload, err := m.SyncCRDT(ctx, peer, localPayload)
	if err != nil {
		return 0, fmt.Errorf("anti-entropy sync with peer %s failed: %w", peer.ID, err)
	}

	if remotePayload != nil {
		mutations = m.crdtStore.Merge(*remotePayload)
		peer.MerkleDigest = m.crdtStore.MerkleDigest()
	}
	return mutations, nil
}

func (m *P2PMesh) runGossipLoop() {
	ticker := time.NewTicker(m.gossipPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.RLock()
			eng := m.engine
			m.mu.RUnlock()

			if eng == nil {
				continue
			}

			status := eng.Status()
			for _, p := range status.Peers {
				peerCopy := p
				if peerCopy.Active && peerCopy.MerkleDigest != "" && peerCopy.MerkleDigest != status.MerkleDigest {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_, _ = m.TriggerAntiEntropy(ctx, &peerCopy)
					cancel()
				}
			}
		}
	}
}
