package transparency

import (
	"encoding/json"
	"errors"
)

var (
	// ErrEmptyTree is returned when an operation requires leaves but the tree is empty.
	ErrEmptyTree = errors.New("merkle tree is empty")
	// ErrInvalidLeafIndex is returned when the requested leaf index is outside tree bounds.
	ErrInvalidLeafIndex = errors.New("leaf index is out of bounds")
	// ErrInvalidTreeSize is returned when the tree size parameter is invalid.
	ErrInvalidTreeSize = errors.New("invalid tree size parameter")
	// ErrInvalidConsistencyRange is returned when first tree size is greater than second.
	ErrInvalidConsistencyRange = errors.New("first tree size cannot be greater than second tree size")
	// ErrSplitViewAttackDetected is returned when a witness detects divergent tree heads for the same size.
	ErrSplitViewAttackDetected = errors.New("split-view attack detected: conflicting tree heads observed")
	// ErrWitnessNotFound is returned when the witness ID is unregistered.
	ErrWitnessNotFound = errors.New("witness node is not registered")
	// ErrEntryNotFound is returned when the log entry cannot be located.
	ErrEntryNotFound = errors.New("transparency log entry not found")
)

// LogEntry represents an immutable, append-only record in the transparency log.
type LogEntry struct {
	Index        int64           `json:"index"`
	Timestamp    int64           `json:"timestamp"`
	Action       string          `json:"action"`
	TenantID     string          `json:"tenant_id"`
	Payload      json.RawMessage `json:"payload"`
	LeafHashHex  string          `json:"leaf_hash_hex"`
	Signature    string          `json:"signature,omitempty"`
}

// WitnessSignature represents a cryptographic co-signature from an independent witness node.
type WitnessSignature struct {
	WitnessID   string `json:"witness_id"`
	TreeSize    int64  `json:"tree_size"`
	RootHashHex string `json:"root_hash_hex"`
	Timestamp   int64  `json:"timestamp"`
	Signature   string `json:"signature"`
	Status      string `json:"status"` // "verified", "conflict"
}

// SignedTreeHead (STH) represents a cryptographically bound snapshot of the Merkle tree state.
type SignedTreeHead struct {
	TreeSize           int64              `json:"tree_size"`
	Timestamp          int64              `json:"timestamp"`
	RootHashHex        string             `json:"root_hash_hex"`
	LogID              string             `json:"log_id"`
	TreeHeadSignature  string             `json:"tree_head_signature"`
	WitnessSignatures  []WitnessSignature `json:"witness_signatures,omitempty"`
}

// InclusionProof provides an RFC 6962 audit path proving leaf membership in a given STH.
type InclusionProof struct {
	LeafIndex    int64    `json:"leaf_index"`
	TreeSize     int64    `json:"tree_size"`
	LeafHashHex  string   `json:"leaf_hash_hex"`
	RootHashHex  string   `json:"root_hash_hex"`
	AuditPathHex []string `json:"audit_path_hex"`
}

// ConsistencyProof provides RFC 6962 intermediate hashes proving append-only tree evolution.
type ConsistencyProof struct {
	FirstSize     int64    `json:"first_size"`
	SecondSize    int64    `json:"second_size"`
	FirstRootHex  string   `json:"first_root_hex"`
	SecondRootHex string   `json:"second_root_hex"`
	ProofHex      []string `json:"proof_hex"`
}

// TransparencyStatus encapsulates telemetry and operational health for the transparency log.
type TransparencyStatus struct {
	LogID           string          `json:"log_id"`
	TreeSize        int64           `json:"tree_size"`
	RootHashHex     string          `json:"root_hash_hex"`
	LatestSTH       *SignedTreeHead `json:"latest_sth"`
	ActiveWitnesses int             `json:"active_witnesses"`
	TotalEntries    int64           `json:"total_entries"`
	OperatingMode   string          `json:"operating_mode"` // "active", "read_only"
	ComplianceRFC   string          `json:"compliance_rfc"` // "RFC 6962"
}
