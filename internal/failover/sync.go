package failover

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrDuplicateDelta  = errors.New("state delta has already been committed (idempotency guard)")
	ErrDeltaNotFound   = errors.New("specified sync delta was not found in ledger")
	ErrInvalidVoucher  = errors.New("sync voucher cryptographic signature is invalid")
	ErrInvalidPayload  = errors.New("delta mutation payload cannot be empty")
)

// SyncLedger coordinates zero-packet-loss state synchronization, vector clocks, and partition replay.
type SyncLedger struct {
	mu            sync.RWMutex
	secretKey     []byte
	sequence      uint64
	vectorClock   map[string]uint64
	deltas        []*SyncDelta
	pendingDeltas map[string][]*SyncDelta
	seenChecksums map[string]int64
	vouchers      map[string]*SyncVoucher
	maxDeltas     int
	knownPeers    []string
}

// NewSyncLedger instantiates the state synchronization engine.
func NewSyncLedger(secretKey []byte, knownPeers []string) *SyncLedger {
	if len(secretKey) == 0 {
		secretKey = []byte("default-sheet-license-broker-multicloud-sync-key-32b")
	}
	vc := make(map[string]uint64)
	for _, p := range knownPeers {
		vc[p] = 0
	}
	return &SyncLedger{
		secretKey:     secretKey,
		sequence:      0,
		vectorClock:   vc,
		deltas:        make([]*SyncDelta, 0, 500),
		pendingDeltas: make(map[string][]*SyncDelta),
		seenChecksums: make(map[string]int64),
		vouchers:      make(map[string]*SyncVoucher),
		maxDeltas:     500,
		knownPeers:    knownPeers,
	}
}

// RecordDelta appends an atomic state mutation, updates vector clocks, and enqueues deltas for peer clouds.
func (sl *SyncLedger) RecordDelta(originProvider string, action string, payload []byte) (*SyncDelta, error) {
	if len(payload) == 0 {
		return nil, ErrInvalidPayload
	}

	h := sha256.Sum256(payload)
	checksum := hex.EncodeToString(h[:])

	sl.mu.Lock()
	defer sl.mu.Unlock()

	now := time.Now().UTC().Unix()

	// Idempotency / deduplication check within 1-hour window
	if seenTime, exists := sl.seenChecksums[checksum]; exists {
		if now-seenTime < 3600 {
			for _, d := range sl.deltas {
				if d.Checksum == checksum {
					return d, nil
				}
			}
		}
	}
	sl.seenChecksums[checksum] = now

	sl.sequence++
	sl.vectorClock[originProvider]++

	// Copy current vector clock snapshot
	clockSnapshot := make(map[string]uint64, len(sl.vectorClock))
	for k, v := range sl.vectorClock {
		clockSnapshot[k] = v
	}

	deltaID := fmt.Sprintf("delta-%d-%s", now, sl.generateRandomID(8))
	delta := &SyncDelta{
		DeltaID:        deltaID,
		OriginProvider: originProvider,
		SequenceNumber: sl.sequence,
		VectorClock:    clockSnapshot,
		Action:         action,
		Payload:        json.RawMessage(payload),
		Timestamp:      now,
		Checksum:       checksum,
	}

	// Enforce memory bounding
	if len(sl.deltas) >= sl.maxDeltas {
		sl.deltas = sl.deltas[1:]
	}
	sl.deltas = append(sl.deltas, delta)

	// Enqueue for all peer cloud providers
	for _, peer := range sl.knownPeers {
		if peer != originProvider {
			sl.pendingDeltas[peer] = append(sl.pendingDeltas[peer], delta)
		}
	}

	return delta, nil
}

// GetPendingDeltas retrieves pending uncommitted deltas for a partitioned or recovering cloud provider.
func (sl *SyncLedger) GetPendingDeltas(providerID string, limit int) []*SyncDelta {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	queued := sl.pendingDeltas[providerID]
	if len(queued) == 0 {
		return []*SyncDelta{}
	}
	if limit <= 0 || limit > len(queued) {
		limit = len(queued)
	}
	out := make([]*SyncDelta, limit)
	copy(out, queued[:limit])
	return out
}

// CreateVoucher generates a cryptographically signed receipt acknowledging delta replication.
func (sl *SyncLedger) CreateVoucher(deltaID string, seq uint64, sourceProvider, targetProvider string) (*SyncVoucher, error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	now := time.Now().UTC().Unix()
	voucherID := fmt.Sprintf("vch-%d-%s", now, sl.generateRandomID(8))
	sig := sl.computeVoucherSignature(voucherID, deltaID, seq, sourceProvider, targetProvider, now)

	voucher := &SyncVoucher{
		VoucherID:      voucherID,
		DeltaID:        deltaID,
		SequenceNumber: seq,
		SourceProvider: sourceProvider,
		TargetProvider: targetProvider,
		Signature:      sig,
		ReplicatedAt:   now,
	}
	sl.vouchers[voucherID] = voucher
	return voucher, nil
}

// AcknowledgeSync clears a delta from a provider's pending replay queue once confirmed by voucher.
func (sl *SyncLedger) AcknowledgeSync(providerID string, deltaID string, voucher *SyncVoucher) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if voucher != nil {
		expectedSig := sl.computeVoucherSignature(voucher.VoucherID, voucher.DeltaID, voucher.SequenceNumber, voucher.SourceProvider, voucher.TargetProvider, voucher.ReplicatedAt)
		if subtle.ConstantTimeCompare([]byte(voucher.Signature), []byte(expectedSig)) != 1 {
			return ErrInvalidVoucher
		}
	}

	queued := sl.pendingDeltas[providerID]
	filtered := make([]*SyncDelta, 0, len(queued))
	found := false
	for _, d := range queued {
		if d.DeltaID == deltaID {
			found = true
			continue
		}
		filtered = append(filtered, d)
	}
	sl.pendingDeltas[providerID] = filtered

	if !found {
		return ErrDeltaNotFound
	}
	return nil
}

// SummaryStats returns metrics regarding delta throughput and synchronization backlog.
func (sl *SyncLedger) SummaryStats() (totalSynced int64, pendingCount int, vectorClock map[string]uint64) {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	totalSynced = int64(len(sl.deltas))
	for _, queue := range sl.pendingDeltas {
		pendingCount += len(queue)
	}

	vcCopy := make(map[string]uint64, len(sl.vectorClock))
	for k, v := range sl.vectorClock {
		vcCopy[k] = v
	}
	return totalSynced, pendingCount, vcCopy
}

// computeVoucherSignature calculates HMAC-SHA256 for cross-cloud replication vouchers.
func (sl *SyncLedger) computeVoucherSignature(vchID, deltaID string, seq uint64, src, tgt string, ts int64) string {
	payload := fmt.Sprintf("%s:%s:%d:%s:%s:%d", vchID, deltaID, seq, src, tgt, ts)
	mac := hmac.New(sha256.New, sl.secretKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateRandomID generates a secure random hex identifier.
func (sl *SyncLedger) generateRandomID(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
