package anycast

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PartitionMitigator manages geographic network partitions, emergency leases, and auto-healing.
type PartitionMitigator struct {
	mu                  sync.RWMutex
	localRegion         string
	secretKey           []byte
	localLeaseDuration  time.Duration
	failureThreshold    int
	failureCounts       map[string]int
	partitionStates     map[string]*PartitionState
	reconciliationQueue map[string][]string
}

// NewPartitionMitigator initializes a partition mitigator for the designated local region.
func NewPartitionMitigator(localRegion string, secretKey []byte, leaseDuration time.Duration) *PartitionMitigator {
	if localRegion == "" {
		localRegion = "global"
	}
	if len(secretKey) == 0 {
		secretKey = []byte("partition-emergency-mitigation-key")
	}
	if leaseDuration <= 0 {
		leaseDuration = 2 * time.Hour
	}
	return &PartitionMitigator{
		localRegion:         localRegion,
		secretKey:           secretKey,
		localLeaseDuration:  leaseDuration,
		failureThreshold:    3,
		failureCounts:       make(map[string]int),
		partitionStates:     make(map[string]*PartitionState),
		reconciliationQueue: make(map[string][]string),
	}
}

// RecordHeartbeat tracks connectivity to a region or central authority, detecting partitions and triggers healing.
func (pm *PartitionMitigator) RecordHeartbeat(remoteRegion string, success bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	state, exists := pm.partitionStates[remoteRegion]
	if !exists {
		state = &PartitionState{
			RegionID:           remoteRegion,
			Status:             PartitionNormal,
			LocalLeaseDuration: pm.localLeaseDuration,
			RecoverySyncStatus: "in_sync",
			LastProbeTime:      time.Now().UTC(),
		}
		pm.partitionStates[remoteRegion] = state
	}

	now := time.Now().UTC()
	state.LastProbeTime = now

	if success {
		pm.failureCounts[remoteRegion] = 0
		if state.Status == PartitionPartitioned {
			state.Status = PartitionHealing
			state.RecoverySyncStatus = "pending_replay"
		} else if state.Status == PartitionHealing {
			// Auto-healed once reconciled or queue is empty
			if len(pm.reconciliationQueue[remoteRegion]) == 0 {
				state.Status = PartitionNormal
				state.IsolatedSince = nil
				state.RecoverySyncStatus = "reconciled"
			}
		}
		return
	}

	// Failure branch
	pm.failureCounts[remoteRegion]++
	if pm.failureCounts[remoteRegion] >= pm.failureThreshold && state.Status == PartitionNormal {
		state.Status = PartitionPartitioned
		isolatedAt := now
		state.IsolatedSince = &isolatedAt
		state.RecoverySyncStatus = "pending_replay"
	}
}

// IsPartitioned checks if the specified region is currently partitioned/isolated.
func (pm *PartitionMitigator) IsPartitioned(region string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	state, ok := pm.partitionStates[region]
	if !ok {
		return false
	}
	return state.Status == PartitionPartitioned || state.Status == PartitionHealing
}

// IssueEmergencyLease grants an HMAC-signed local lease extension during network partition.
func (pm *PartitionMitigator) IssueEmergencyLease(licenseKey, clientHWID, targetRegion string) (*EmergencyLeaseToken, error) {
	if licenseKey == "" || clientHWID == "" {
		return nil, errors.New("licenseKey and clientHWID are required")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if targetRegion == "" {
		targetRegion = pm.localRegion
	}

	now := time.Now().UTC()
	expiry := now.Add(pm.localLeaseDuration)

	// Create payload for signature
	payload := fmt.Sprintf("%s:%s:%s:%d:%d", targetRegion, licenseKey, clientHWID, now.Unix(), expiry.Unix())
	mac := hmac.New(sha256.New, pm.secretKey)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	token := &EmergencyLeaseToken{
		RegionID:    targetRegion,
		LicenseKey:  licenseKey,
		ClientHWID:  clientHWID,
		LeaseExpiry: expiry,
		IssuedAt:    now,
		Signature:   sig,
	}

	// Record operation to reconciliation queue for eventual sync
	opDesc := fmt.Sprintf("EMERGENCY_LEASE:%s:%s:%d", licenseKey, clientHWID, expiry.Unix())
	pm.reconciliationQueue[targetRegion] = append(pm.reconciliationQueue[targetRegion], opDesc)

	return token, nil
}

// VerifyEmergencyLease validates an emergency lease token signature and unexpired validity.
func (pm *PartitionMitigator) VerifyEmergencyLease(token *EmergencyLeaseToken) (bool, error) {
	if token == nil {
		return false, errors.New("nil emergency lease token")
	}

	payload := fmt.Sprintf("%s:%s:%s:%d:%d",
		token.RegionID, token.LicenseKey, token.ClientHWID, token.IssuedAt.Unix(), token.LeaseExpiry.Unix())

	pm.mu.RLock()
	mac := hmac.New(sha256.New, pm.secretKey)
	pm.mu.RUnlock()

	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(token.Signature), []byte(expectedSig)) {
		return false, errors.New("invalid emergency lease signature")
	}

	if time.Now().UTC().After(token.LeaseExpiry) {
		return false, errors.New("emergency lease expired")
	}

	return true, nil
}

// QueueReconciliation enqueues a state mutation to be synchronized once the partition heals.
func (pm *PartitionMitigator) QueueReconciliation(regionID, operation string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.reconciliationQueue[regionID] = append(pm.reconciliationQueue[regionID], operation)
}

// ReconcilePartition flushes pending partitioned operations and transitions region to normal.
func (pm *PartitionMitigator) ReconcilePartition(regionID string) (int, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	ops := pm.reconciliationQueue[regionID]
	count := len(ops)
	pm.reconciliationQueue[regionID] = nil

	if state, ok := pm.partitionStates[regionID]; ok {
		state.Status = PartitionNormal
		state.IsolatedSince = nil
		state.RecoverySyncStatus = "reconciled"
	}

	return count, nil
}

// GetPartitionState returns a snapshot of partition health for a region.
func (pm *PartitionMitigator) GetPartitionState(regionID string) PartitionState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if state, ok := pm.partitionStates[regionID]; ok {
		return *state
	}

	return PartitionState{
		RegionID:           regionID,
		Status:             PartitionNormal,
		LocalLeaseDuration: pm.localLeaseDuration,
		RecoverySyncStatus: "in_sync",
		LastProbeTime:      time.Now().UTC(),
	}
}

// ListPartitionStates returns all monitored partition states.
func (pm *PartitionMitigator) ListPartitionStates() []PartitionState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	states := make([]PartitionState, 0, len(pm.partitionStates))
	for _, s := range pm.partitionStates {
		states = append(states, *s)
	}
	return states
}

// LocalRegion returns the configured local region for this node.
func (pm *PartitionMitigator) LocalRegion() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.localRegion
}

// IsLocalPartitioned checks if the local region is in a partitioned state.
func (pm *PartitionMitigator) IsLocalPartitioned() bool {
	return pm.IsPartitioned(pm.LocalRegion())
}

// SetPartitioned explicitly marks a region as partitioned or normal (useful for simulation & testing).
func (pm *PartitionMitigator) SetPartitioned(region string, partitioned bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if region == "" {
		region = pm.localRegion
	}

	state, exists := pm.partitionStates[region]
	if !exists {
		state = &PartitionState{
			RegionID:           region,
			Status:             PartitionNormal,
			LocalLeaseDuration: pm.localLeaseDuration,
			RecoverySyncStatus: "in_sync",
			LastProbeTime:      time.Now().UTC(),
		}
		pm.partitionStates[region] = state
	}

	if partitioned {
		state.Status = PartitionPartitioned
		now := time.Now().UTC()
		state.IsolatedSince = &now
		state.RecoverySyncStatus = "pending_replay"
	} else {
		state.Status = PartitionNormal
		state.IsolatedSince = nil
		state.RecoverySyncStatus = "reconciled"
		pm.failureCounts[region] = 0
	}
}

