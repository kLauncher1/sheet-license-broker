package transparency

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// TransparencyTree manages thread-safe append-only storage and cryptographic tree head signing.
type TransparencyTree struct {
	mu         sync.RWMutex
	logID      string
	signingKey []byte
	entries    []*LogEntry
	leafHashes [][]byte
	latestSTH  *SignedTreeHead
}

// NewTransparencyTree instantiates an empty transparency tree for the specified log identity.
func NewTransparencyTree(logID string, signingKey []byte) *TransparencyTree {
	if len(signingKey) == 0 {
		signingKey = []byte("sheet-license-broker-transparency-signing-key")
	}
	t := &TransparencyTree{
		logID:      logID,
		signingKey: signingKey,
		entries:    make([]*LogEntry, 0),
		leafHashes: make([][]byte, 0),
	}
	emptyRoot := sha256.Sum256(nil)
	t.latestSTH = t.signTreeHeadLocked(0, emptyRoot, time.Now().UTC().UnixMilli())
	return t
}

// AppendEntry records a new audit event into the append-only ledger and issues an updated STH.
func (t *TransparencyTree) AppendEntry(action, tenantID string, payload []byte) (*LogEntry, *SignedTreeHead, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	idx := int64(len(t.entries))
	now := time.Now().UTC().UnixMilli()

	// Validate or wrap payload as valid JSON
	if !json.Valid(payload) {
		wrapped, _ := json.Marshal(map[string]string{"raw": string(payload)})
		payload = wrapped
	}

	leafHash := ComputeLeafHash(payload)
	leafHashHex := hex.EncodeToString(leafHash[:])

	// Calculate cryptographic signature for individual entry
	sig := t.signEntryLocked(idx, now, action, tenantID, leafHashHex)

	entry := &LogEntry{
		Index:       idx,
		Timestamp:   now,
		Action:      action,
		TenantID:    tenantID,
		Payload:     payload,
		LeafHashHex: leafHashHex,
		Signature:   sig,
	}

	t.entries = append(t.entries, entry)
	t.leafHashes = append(t.leafHashes, leafHash[:])

	root := BuildMerkleTreeRoot(t.leafHashes)
	t.latestSTH = t.signTreeHeadLocked(int64(len(t.entries)), root, now)

	return entry, t.latestSTH, nil
}

// Size returns the current number of leaves in the tree.
func (t *TransparencyTree) Size() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return int64(len(t.entries))
}

// LatestSTH returns the most recent Signed Tree Head snapshot.
func (t *TransparencyTree) LatestSTH() *SignedTreeHead {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.latestSTH
}

// UpdateSTHWitnessSignatures attaches witness co-signatures to the active STH.
func (t *TransparencyTree) UpdateSTHWitnessSignatures(sigs []WitnessSignature) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.latestSTH != nil {
		t.latestSTH.WitnessSignatures = sigs
	}
}

// GetEntry retrieves a single log entry by its 0-based index.
func (t *TransparencyTree) GetEntry(index int64) (*LogEntry, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if index < 0 || index >= int64(len(t.entries)) {
		return nil, ErrInvalidLeafIndex
	}
	return t.entries[index], nil
}

// GetEntries returns a range of log entries starting at start up to count records.
func (t *TransparencyTree) GetEntries(start, count int64) ([]*LogEntry, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := int64(len(t.entries))
	if start < 0 || start > n {
		return nil, ErrInvalidLeafIndex
	}
	if count <= 0 {
		return []*LogEntry{}, nil
	}
	end := start + count
	if end > n {
		end = n
	}
	result := make([]*LogEntry, end-start)
	copy(result, t.entries[start:end])
	return result, nil
}

// GenerateInclusionProof constructs an RFC 6962 audit path for leaf index in tree size.
func (t *TransparencyTree) GenerateInclusionProof(leafIndex, treeSize int64) (*InclusionProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := int64(len(t.entries))
	if treeSize <= 0 || treeSize > n {
		return nil, ErrInvalidTreeSize
	}
	if leafIndex < 0 || leafIndex >= treeSize {
		return nil, ErrInvalidLeafIndex
	}

	proofBytes, err := ComputeInclusionProof(t.leafHashes, leafIndex, treeSize)
	if err != nil {
		return nil, err
	}

	root := BuildMerkleTreeRoot(t.leafHashes[:treeSize])
	proofHex := make([]string, len(proofBytes))
	for i, b := range proofBytes {
		proofHex[i] = hex.EncodeToString(b)
	}

	return &InclusionProof{
		LeafIndex:    leafIndex,
		TreeSize:     treeSize,
		LeafHashHex:  hex.EncodeToString(t.leafHashes[leafIndex]),
		RootHashHex:  hex.EncodeToString(root[:]),
		AuditPathHex: proofHex,
	}, nil
}

// GenerateConsistencyProof constructs RFC 6962 consistency hashes between firstSize and secondSize.
func (t *TransparencyTree) GenerateConsistencyProof(firstSize, secondSize int64) (*ConsistencyProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := int64(len(t.entries))
	if firstSize <= 0 || secondSize <= 0 || secondSize > n {
		return nil, ErrInvalidTreeSize
	}
	if firstSize > secondSize {
		return nil, ErrInvalidConsistencyRange
	}

	proofBytes, err := ComputeConsistencyProof(t.leafHashes, firstSize, secondSize)
	if err != nil {
		return nil, err
	}

	root1 := BuildMerkleTreeRoot(t.leafHashes[:firstSize])
	root2 := BuildMerkleTreeRoot(t.leafHashes[:secondSize])

	proofHex := make([]string, len(proofBytes))
	for i, b := range proofBytes {
		proofHex[i] = hex.EncodeToString(b)
	}

	return &ConsistencyProof{
		FirstSize:     firstSize,
		SecondSize:    secondSize,
		FirstRootHex:  hex.EncodeToString(root1[:]),
		SecondRootHex: hex.EncodeToString(root2[:]),
		ProofHex:      proofHex,
	}, nil
}

func (t *TransparencyTree) signTreeHeadLocked(treeSize int64, rootHash [32]byte, timestamp int64) *SignedTreeHead {
	rootHex := hex.EncodeToString(rootHash[:])
	msg := fmt.Sprintf("STH:%s:%d:%d:%s", t.logID, treeSize, timestamp, rootHex)
	mac := hmac.New(sha256.New, t.signingKey)
	mac.Write([]byte(msg))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	return &SignedTreeHead{
		TreeSize:          treeSize,
		Timestamp:         timestamp,
		RootHashHex:       rootHex,
		LogID:             t.logID,
		TreeHeadSignature: sigHex,
		WitnessSignatures: make([]WitnessSignature, 0),
	}
}

func (t *TransparencyTree) signEntryLocked(index, timestamp int64, action, tenantID, leafHashHex string) string {
	msg := fmt.Sprintf("ENTRY:%d:%d:%s:%s:%s", index, timestamp, action, tenantID, leafHashHex)
	mac := hmac.New(sha256.New, t.signingKey)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
