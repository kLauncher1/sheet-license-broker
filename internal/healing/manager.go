package healing

import (
	"sync"
	"time"
)

// ManagerConfig holds operational parameters for the HealingManager.
type ManagerConfig struct {
	BucketConfig          TokenBucketConfig `json:"bucket_config"`
	HealingSecret         string            `json:"healing_secret"`
	DefaultGrace          time.Duration     `json:"default_grace"`
	AutoRebalanceInterval time.Duration     `json:"auto_rebalance_interval"`
}

// HealingManager serves as the unified facade orchestrator coordinating
// adaptive rate scaling, resilient reconnect tunnels, and distributed tenant quotas.
type HealingManager struct {
	bucket    *AutoScalingBucket
	tunnels   *TunnelManager
	quotas    *DistributedQuotaPool
	ticker    *time.Ticker
	stopChan  chan struct{}
	closeOnce sync.Once
}

// NewManager creates and starts a HealingManager instance.
func NewManager(cfg ManagerConfig) *HealingManager {
	if cfg.AutoRebalanceInterval <= 0 {
		cfg.AutoRebalanceInterval = 1 * time.Minute
	}

	mgr := &HealingManager{
		bucket:   NewAutoScalingBucket(cfg.BucketConfig),
		tunnels:  NewTunnelManager(cfg.HealingSecret, cfg.DefaultGrace),
		quotas:   NewDistributedQuotaPool(),
		ticker:   time.NewTicker(cfg.AutoRebalanceInterval),
		stopChan: make(chan struct{}),
	}

	go mgr.backgroundLoop()

	return mgr
}

// backgroundLoop runs periodic maintenance tasks (tunnel sweeping, quota rebalancing).
func (m *HealingManager) backgroundLoop() {
	for {
		select {
		case <-m.ticker.C:
			m.tunnels.SweepExpiredTunnels()
			m.quotas.RebalanceQuotas()
		case <-m.stopChan:
			return
		}
	}
}

// Close gracefully stops background tasks.
func (m *HealingManager) Close() {
	m.closeOnce.Do(func() {
		m.ticker.Stop()
		close(m.stopChan)
	})
}

// ConsumeTokens checks and consumes capacity from the auto-scaling rate bucket.
func (m *HealingManager) ConsumeTokens(tokens float64) (bool, TokenBucketStats) {
	return m.bucket.TryConsume(tokens)
}

// RecordLoad submits traffic and error observations to steer bucket adaptation.
func (m *HealingManager) RecordLoad(reqs int, errs int) {
	m.bucket.RecordTelemetry(reqs, errs)
}

// BucketStats retrieves real-time statistics from the adaptive token bucket.
func (m *HealingManager) BucketStats() TokenBucketStats {
	return m.bucket.Stats()
}

// IssueHealingTicket creates a signed reconnect ticket for a client.
func (m *HealingManager) IssueHealingTicket(sessionID, clientID, hwid, tenantID string, lastAckSeq int64, ttl time.Duration) *HealingTicket {
	return m.tunnels.IssueTicket(sessionID, clientID, hwid, tenantID, lastAckSeq, ttl)
}

// ResumeHealingTunnel validates a healing ticket and delivers missed state deltas.
func (m *HealingManager) ResumeHealingTunnel(ticket *HealingTicket) (*HealingSession, []DeltaEvent, error) {
	return m.tunnels.ResumeTunnel(ticket)
}

// RecordClientDisconnect marks a client connection as disconnected, initiating grace.
func (m *HealingManager) RecordClientDisconnect(clientID string) *HealingSession {
	return m.tunnels.RecordDisconnect(clientID)
}

// PublishDeltaEvent records an event for clients to catch up during reconnects.
func (m *HealingManager) PublishDeltaEvent(tenantID, clientID, eventType, payload string) DeltaEvent {
	return m.tunnels.RecordDeltaEvent(tenantID, clientID, eventType, payload)
}

// SetTenantQuota initializes or updates quota allocations for a tenant.
func (m *HealingManager) SetTenantQuota(tenantID string, quota int64) {
	m.quotas.SetTenantQuota(tenantID, quota)
}

// ConsumeTenantQuota deducts usage from a tenant's available pool.
func (m *HealingManager) ConsumeTenantQuota(tenantID string, amount int64) bool {
	return m.quotas.ConsumeQuota(tenantID, amount)
}

// BorrowQuota creates a temporary quota borrowing lease between tenants.
func (m *HealingManager) BorrowQuota(borrower, lender string, amount int64, duration time.Duration) (*QuotaLease, error) {
	return m.quotas.BorrowQuota(borrower, lender, amount, duration)
}

// ReturnQuota voluntarily completes a quota lease ahead of schedule.
func (m *HealingManager) ReturnQuota(leaseID string) error {
	return m.quotas.ReturnQuota(leaseID)
}

// RecallQuota revokes an active lease when lender experiences high load.
func (m *HealingManager) RecallQuota(leaseID, reason string) error {
	return m.quotas.RecallQuota(leaseID, reason)
}

// RebalanceQuotas triggers an explicit rebalance check across all quota pools.
func (m *HealingManager) RebalanceQuotas() []QuotaRebalanceEvent {
	return m.quotas.RebalanceQuotas()
}

// Status synthesizes a complete operational snapshot of the healing subsystem.
func (m *HealingManager) Status() HealingStatus {
	sessions := m.tunnels.ListSessions()
	activeTunnels := 0
	suspendedTunnels := 0
	for _, s := range sessions {
		if s.State == TunnelStateConnected || s.State == TunnelStateResumed {
			activeTunnels++
		} else if s.State == TunnelStateDisconnected {
			suspendedTunnels++
		}
	}

	leases := m.quotas.ListLeases()
	var activeLeases []QuotaLease
	for _, l := range leases {
		if l.Status == LeaseActive {
			activeLeases = append(activeLeases, l)
		}
	}

	return HealingStatus{
		Bucket:            m.bucket.Stats(),
		ActiveTunnels:     activeTunnels,
		SuspendedTunnels:  suspendedTunnels,
		TotalMissedEvents: int64(len(m.tunnels.deltaBuffer)),
		QuotaPools:        m.quotas.ListPools(),
		ActiveLeases:      activeLeases,
		RecentRebalances:  m.quotas.RecentEvents(),
	}
}
