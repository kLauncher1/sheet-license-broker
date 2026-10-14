package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// NodeRole represents the Raft consensus role of a broker instance.
type NodeRole string

const (
	RoleFollower  NodeRole = "follower"
	RoleCandidate NodeRole = "candidate"
	RoleLeader    NodeRole = "leader"
)

// CommandType denotes the state machine operation replicated across nodes.
type CommandType string

const (
	CmdLicenseCreate   CommandType = "LICENSE_CREATE"
	CmdLicenseRevoke   CommandType = "LICENSE_REVOKE"
	CmdDeviceBlacklist CommandType = "DEVICE_BLACKLIST"
	CmdDeviceUnban     CommandType = "DEVICE_UNBAN"
	CmdCRDTMerge       CommandType = "CRDT_MERGE"
	CmdConfigUpdate    CommandType = "CONFIG_UPDATE"
)

// LogEntry represents an immutable replicated write in the distributed log.
type LogEntry struct {
	Index     uint64      `json:"index"`
	Term      uint64      `json:"term"`
	Type      CommandType `json:"type"`
	Key       string      `json:"key"`
	Value     string      `json:"value"`
	Timestamp int64       `json:"timestamp"`
	NodeID    string      `json:"node_id"`
	Hash      string      `json:"hash"`
}

// ComputeHash calculates a deterministic SHA-256 integrity hash for the log entry.
func (e *LogEntry) ComputeHash() string {
	payload := fmt.Sprintf("%d:%d:%s:%s:%s:%d:%s",
		e.Index, e.Term, e.Type, e.Key, e.Value, e.Timestamp, e.NodeID)
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

// PeerNode captures metadata and health for a cluster member.
type PeerNode struct {
	ID           string    `json:"id"`
	Address      string    `json:"address"`
	Region       string    `json:"region"`
	Role         NodeRole  `json:"role"`
	LastSeen     time.Time `json:"last_seen"`
	Active       bool      `json:"active"`
	MatchIndex   uint64    `json:"match_index"`
	NextIndex    uint64    `json:"next_index"`
	LatencyMs    int64     `json:"latency_ms"`
	MerkleDigest string    `json:"merkle_digest"`
}

// VoteRequest is the Raft RequestVote RPC argument payload.
type VoteRequest struct {
	Term         uint64 `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex uint64 `json:"last_log_index"`
	LastLogTerm  uint64 `json:"last_log_term"`
}

// VoteResponse is the Raft RequestVote RPC return payload.
type VoteResponse struct {
	Term        uint64 `json:"term"`
	VoteGranted bool   `json:"vote_granted"`
	Reason      string `json:"reason,omitempty"`
}

// AppendEntriesRequest is the Raft AppendEntries (heartbeat / replication) RPC payload.
type AppendEntriesRequest struct {
	Term         uint64     `json:"term"`
	LeaderID     string     `json:"leader_id"`
	PrevLogIndex uint64     `json:"prev_log_index"`
	PrevLogTerm  uint64     `json:"prev_log_term"`
	Entries      []LogEntry `json:"entries,omitempty"`
	LeaderCommit uint64     `json:"leader_commit"`
	MerkleDigest string     `json:"merkle_digest,omitempty"`
}

// AppendEntriesResponse is the Raft AppendEntries RPC return payload.
type AppendEntriesResponse struct {
	Term         uint64 `json:"term"`
	Success      bool   `json:"success"`
	MatchIndex   uint64 `json:"match_index"`
	MerkleDigest string `json:"merkle_digest,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// ClusterStatus conveys real-time quorum and replication telemetry for the cluster.
type ClusterStatus struct {
	NodeID       string     `json:"node_id"`
	Region       string     `json:"region"`
	Role         NodeRole   `json:"role"`
	CurrentTerm  uint64     `json:"current_term"`
	LeaderID     string     `json:"leader_id"`
	CommitIndex  uint64     `json:"commit_index"`
	LastLogIndex uint64     `json:"last_log_index"`
	PeerCount    int        `json:"peer_count"`
	ActivePeers  int        `json:"active_peers"`
	QuorumSize   int        `json:"quorum_size"`
	HasQuorum    bool       `json:"has_quorum"`
	MerkleDigest string     `json:"merkle_digest"`
	Peers        []PeerNode `json:"peers"`
}

// CRDTSyncPayload carries state exchange bundles for anti-entropy sync.
type CRDTSyncPayload struct {
	NodeID       string            `json:"node_id"`
	MerkleDigest string            `json:"merkle_digest"`
	AddSet       map[string]int64  `json:"add_set"`
	RemoveSet    map[string]int64  `json:"remove_set"`
	Counters     map[string]int64  `json:"counters"`
	Payloads     map[string]string `json:"payloads,omitempty"`
}

// ToJSON serializes any consensus payload to JSON bytes.
func ToJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
