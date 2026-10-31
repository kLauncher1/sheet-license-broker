package transparency

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// WitnessNode maintains independent verification state and cryptographic keying for a witness participant.
type WitnessNode struct {
	mu           sync.Mutex
	ID           string
	SecretKey    []byte
	LastTreeSize int64
	LastRootHex  string
	RegisteredAt int64
}

// WitnessPool coordinates multiple independent witness nodes to prevent split-view attacks.
type WitnessPool struct {
	mu        sync.RWMutex
	witnesses map[string]*WitnessNode
}

// NewWitnessPool constructs an empty multi-party witness registry.
func NewWitnessPool() *WitnessPool {
	return &WitnessPool{
		witnesses: make(map[string]*WitnessNode),
	}
}

// RegisterWitness adds or updates a trusted witness node in the pool.
func (wp *WitnessPool) RegisterWitness(id string, secretKey []byte) {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if len(secretKey) == 0 {
		secretKey = []byte(fmt.Sprintf("witness-secret-%s", id))
	}

	wp.witnesses[id] = &WitnessNode{
		ID:           id,
		SecretKey:    secretKey,
		RegisteredAt: time.Now().UTC().UnixMilli(),
	}
}

// ListWitnessIDs returns the identifiers of all registered witness participants.
func (wp *WitnessPool) ListWitnessIDs() []string {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	ids := make([]string, 0, len(wp.witnesses))
	for id := range wp.witnesses {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of active witness participants.
func (wp *WitnessPool) Count() int {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return len(wp.witnesses)
}

// CoSign evaluates an STH against the witness's previously verified tree head and signs if consistent.
func (wp *WitnessPool) CoSign(sth *SignedTreeHead, witnessID string, leaves [][]byte) (*WitnessSignature, error) {
	wp.mu.RLock()
	w, exists := wp.witnesses[witnessID]
	wp.mu.RUnlock()

	if !exists {
		return nil, ErrWitnessNotFound
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// 1. Detect Split-View Attack: Same tree size but divergent root hash
	if w.LastTreeSize > 0 && w.LastTreeSize == sth.TreeSize {
		if !stringsEqualConstantTime(w.LastRootHex, sth.RootHashHex) {
			return &WitnessSignature{
				WitnessID:   witnessID,
				TreeSize:    sth.TreeSize,
				RootHashHex: sth.RootHashHex,
				Timestamp:   time.Now().UTC().UnixMilli(),
				Status:      "conflict",
			}, ErrSplitViewAttackDetected
		}
	}

	// 2. Tree size must not roll back
	if w.LastTreeSize > 0 && sth.TreeSize < w.LastTreeSize {
		return nil, ErrSplitViewAttackDetected
	}

	// 3. If tree size advanced, verify append-only consistency proof
	if w.LastTreeSize > 0 && sth.TreeSize > w.LastTreeSize && len(leaves) >= int(sth.TreeSize) {
		prevRootBytes, err := hex.DecodeString(w.LastRootHex)
		if err != nil {
			return nil, err
		}
		newRootBytes, err := hex.DecodeString(sth.RootHashHex)
		if err != nil {
			return nil, err
		}

		proofBytes, err := ComputeConsistencyProof(leaves[:sth.TreeSize], w.LastTreeSize, sth.TreeSize)
		if err != nil {
			return nil, err
		}

		if !VerifyConsistencyProof(w.LastTreeSize, sth.TreeSize, prevRootBytes, newRootBytes, proofBytes) {
			return &WitnessSignature{
				WitnessID:   witnessID,
				TreeSize:    sth.TreeSize,
				RootHashHex: sth.RootHashHex,
				Timestamp:   time.Now().UTC().UnixMilli(),
				Status:      "conflict",
			}, ErrSplitViewAttackDetected
		}
	}

	// 4. Cryptographically sign the verified STH
	now := time.Now().UTC().UnixMilli()
	msg := fmt.Sprintf("WITNESS_STH:%s:%d:%d:%s", witnessID, sth.TreeSize, now, sth.RootHashHex)
	mac := hmac.New(sha256.New, w.SecretKey)
	mac.Write([]byte(msg))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	// 5. Update witness memory
	w.LastTreeSize = sth.TreeSize
	w.LastRootHex = sth.RootHashHex

	return &WitnessSignature{
		WitnessID:   witnessID,
		TreeSize:    sth.TreeSize,
		RootHashHex: sth.RootHashHex,
		Timestamp:   now,
		Signature:   sigHex,
		Status:      "verified",
	}, nil
}

// ValidateWitnessSignature cryptographically checks whether a witness co-signature matches expected payload.
func (wp *WitnessPool) ValidateWitnessSignature(sig *WitnessSignature) bool {
	if sig == nil || sig.WitnessID == "" || sig.Signature == "" {
		return false
	}

	wp.mu.RLock()
	w, exists := wp.witnesses[sig.WitnessID]
	wp.mu.RUnlock()

	if !exists {
		return false
	}

	msg := fmt.Sprintf("WITNESS_STH:%s:%d:%d:%s", sig.WitnessID, sig.TreeSize, sig.Timestamp, sig.RootHashHex)
	mac := hmac.New(sha256.New, w.SecretKey)
	mac.Write([]byte(msg))
	expected := mac.Sum(nil)

	actual, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func stringsEqualConstantTime(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
