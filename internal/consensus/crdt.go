package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// CRDTStore manages state-based Conflict-free Replicated Data Types (CRDTs).
// It implements an LWW-Element-Set (Last-Write-Wins) with revocation priority,
// along with PN-Counters and deterministic Merkle tree digests.
type CRDTStore struct {
	mu        sync.RWMutex
	nodeID    string
	addSet    map[string]int64  // Element -> timestamp (unix nano)
	removeSet map[string]int64  // Element -> timestamp (unix nano)
	payloads  map[string]string // Element -> latest JSON/string payload
	pCounters map[string]int64  // Key -> Positive counter
	nCounters map[string]int64  // Key -> Negative counter
	updatedAt time.Time
}

// NewCRDTStore initializes an empty CRDT storage engine.
func NewCRDTStore(nodeID string) *CRDTStore {
	return &CRDTStore{
		nodeID:    nodeID,
		addSet:    make(map[string]int64),
		removeSet: make(map[string]int64),
		payloads:  make(map[string]string),
		pCounters: make(map[string]int64),
		nCounters: make(map[string]int64),
		updatedAt: time.Now(),
	}
}

// Add inserts or updates an element in the LWW-Element-Set.
func (c *CRDTStore) Add(elem, payload string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ts := time.Now().UnixNano()
	c.addSet[elem] = ts
	if payload != "" {
		c.payloads[elem] = payload
	}
	c.updatedAt = time.Now()
}

// AddWithTimestamp inserts an element with an explicit timestamp.
func (c *CRDTStore) AddWithTimestamp(elem, payload string, ts int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cur, ok := c.addSet[elem]; !ok || ts > cur {
		c.addSet[elem] = ts
		if payload != "" {
			c.payloads[elem] = payload
		}
		c.updatedAt = time.Now()
	}
}

// Remove marks an element as removed in the LWW-Element-Set.
func (c *CRDTStore) Remove(elem string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ts := time.Now().UnixNano()
	c.removeSet[elem] = ts
	c.updatedAt = time.Now()
}

// RemoveWithTimestamp marks an element as removed with an explicit timestamp.
func (c *CRDTStore) RemoveWithTimestamp(elem string, ts int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cur, ok := c.removeSet[elem]; !ok || ts > cur {
		c.removeSet[elem] = ts
		c.updatedAt = time.Now()
	}
}

// Contains checks if an element is active.
// Invariant: If an element is present in both AddSet and RemoveSet,
// RemoveSet wins on timestamp ties (RemoveTime >= AddTime) to prevent resurrection of revocations.
func (c *CRDTStore) Contains(elem string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	addTime, hasAdd := c.addSet[elem]
	if !hasAdd {
		return false
	}

	remTime, hasRem := c.removeSet[elem]
	if !hasRem {
		return true
	}

	// Tie-breaking: Removals strictly win on equal timestamps.
	return addTime > remTime
}

// GetPayload retrieves the stored payload of an active element.
func (c *CRDTStore) GetPayload(elem string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.containsLocked(elem) {
		return "", false
	}
	p, ok := c.payloads[elem]
	return p, ok
}

func (c *CRDTStore) containsLocked(elem string) bool {
	addTime, hasAdd := c.addSet[elem]
	if !hasAdd {
		return false
	}
	remTime, hasRem := c.removeSet[elem]
	if !hasRem {
		return true
	}
	return addTime > remTime
}

// ListActive returns all currently active elements in the LWW-Element-Set.
func (c *CRDTStore) ListActive() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var active []string
	for elem := range c.addSet {
		if c.containsLocked(elem) {
			active = append(active, elem)
		}
	}
	sort.Strings(active)
	return active
}

// IncrementCounter bumps a positive counter for usage or seat tracking.
func (c *CRDTStore) IncrementCounter(key string, delta int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if delta > 0 {
		c.pCounters[key] += delta
	} else if delta < 0 {
		c.nCounters[key] += (-delta)
	}
	c.updatedAt = time.Now()
}

// GetCounter returns the current net value of a PN-Counter (P - N).
func (c *CRDTStore) GetCounter(key string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.pCounters[key] - c.nCounters[key]
}

// ExportState extracts a full snapshot payload for peer replication.
func (c *CRDTStore) ExportState() CRDTSyncPayload {
	c.mu.RLock()
	defer c.mu.RUnlock()

	adds := make(map[string]int64, len(c.addSet))
	for k, v := range c.addSet {
		adds[k] = v
	}

	rems := make(map[string]int64, len(c.removeSet))
	for k, v := range c.removeSet {
		rems[k] = v
	}

	counters := make(map[string]int64)
	for k, v := range c.pCounters {
		counters["P:"+k] = v
	}
	for k, v := range c.nCounters {
		counters["N:"+k] = v
	}

	payloads := make(map[string]string, len(c.payloads))
	for k, v := range c.payloads {
		payloads[k] = v
	}

	return CRDTSyncPayload{
		NodeID:       c.nodeID,
		MerkleDigest: c.computeDigestLocked(),
		AddSet:       adds,
		RemoveSet:    rems,
		Counters:     counters,
		Payloads:     payloads,
	}
}

// Merge incorporates external CRDT state and guarantees mathematical convergence.
func (c *CRDTStore) Merge(remote CRDTSyncPayload) (mutations int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Merge AddSet (Keep max timestamp)
	for k, remTs := range remote.AddSet {
		if curTs, exists := c.addSet[k]; !exists || remTs > curTs {
			c.addSet[k] = remTs
			mutations++
		}
	}

	// 2. Merge RemoveSet (Keep max timestamp)
	for k, remTs := range remote.RemoveSet {
		if curTs, exists := c.removeSet[k]; !exists || remTs > curTs {
			c.removeSet[k] = remTs
			mutations++
		}
	}

	// 3. Merge Payloads
	for k, p := range remote.Payloads {
		if p != "" {
			c.payloads[k] = p
		}
	}

	// 4. Merge PN-Counters (Max-growth merge)
	for k, val := range remote.Counters {
		if strings.HasPrefix(k, "P:") {
			key := strings.TrimPrefix(k, "P:")
			if val > c.pCounters[key] {
				c.pCounters[key] = val
				mutations++
			}
		} else if strings.HasPrefix(k, "N:") {
			key := strings.TrimPrefix(k, "N:")
			if val > c.nCounters[key] {
				c.nCounters[key] = val
				mutations++
			}
		}
	}

	if mutations > 0 {
		c.updatedAt = time.Now()
	}
	return mutations
}

// MerkleDigest returns a deterministic digest of the CRDT state for O(1) comparison.
func (c *CRDTStore) MerkleDigest() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.computeDigestLocked()
}

func (c *CRDTStore) computeDigestLocked() string {
	// Construct sorted list of canonical entries
	var lines []string

	var addKeys []string
	for k := range c.addSet {
		addKeys = append(addKeys, k)
	}
	sort.Strings(addKeys)
	for _, k := range addKeys {
		lines = append(lines, fmt.Sprintf("A:%s:%d", k, c.addSet[k]))
	}

	var remKeys []string
	for k := range c.removeSet {
		remKeys = append(remKeys, k)
	}
	sort.Strings(remKeys)
	for _, k := range remKeys {
		lines = append(lines, fmt.Sprintf("R:%s:%d", k, c.removeSet[k]))
	}

	var pKeys []string
	for k := range c.pCounters {
		pKeys = append(pKeys, k)
	}
	sort.Strings(pKeys)
	for _, k := range pKeys {
		lines = append(lines, fmt.Sprintf("P:%s:%d", k, c.pCounters[k]))
	}

	var nKeys []string
	for k := range c.nCounters {
		nKeys = append(nKeys, k)
	}
	sort.Strings(nKeys)
	for _, k := range nKeys {
		lines = append(lines, fmt.Sprintf("N:%s:%d", k, c.nCounters[k]))
	}

	raw := strings.Join(lines, "\n")
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
