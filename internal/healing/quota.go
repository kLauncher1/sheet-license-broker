package healing

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var (
	ErrTenantNotFound       = errors.New("tenant quota pool not found")
	ErrInsufficientSurplus  = errors.New("lender tenant has insufficient surplus quota to lend")
	ErrBorrowLimitExceeded  = errors.New("requested borrow amount exceeds maximum allowable lending ratio")
	ErrLeaseNotFound        = errors.New("quota lease not found")
	ErrLeaseNotActive       = errors.New("quota lease is not active")
	ErrSameTenantBorrow     = errors.New("cannot borrow quota from the same tenant")
)

// DistributedQuotaPool manages multi-tenant quota reservations, dynamic borrowing leases,
// and automated rebalancing when workloads fluctuate across instances.
type DistributedQuotaPool struct {
	mu           sync.RWMutex
	pools        map[string]*QuotaPool
	leases       map[string]*QuotaLease
	events       []QuotaRebalanceEvent
	maxEvents    int
	leaseCounter int64
}

// NewDistributedQuotaPool initializes an empty distributed quota arbitration pool.
func NewDistributedQuotaPool() *DistributedQuotaPool {
	return &DistributedQuotaPool{
		pools:     make(map[string]*QuotaPool),
		leases:    make(map[string]*QuotaLease),
		events:    make([]QuotaRebalanceEvent, 0, 50),
		maxEvents: 200,
	}
}

// SetTenantQuota sets or updates the baseline entitlement quota for a tenant.
func (qp *DistributedQuotaPool) SetTenantQuota(tenantID string, totalQuota int64) {
	qp.mu.Lock()
	defer qp.mu.Unlock()

	p, exists := qp.pools[tenantID]
	if !exists {
		p = &QuotaPool{TenantID: tenantID}
		qp.pools[tenantID] = p
	}
	p.TotalQuota = totalQuota
	qp.recalculatePoolLocked(p)
}

// recalculatePoolLocked recalculates AvailableQuota and Utilization metrics.
func (qp *DistributedQuotaPool) recalculatePoolLocked(p *QuotaPool) {
	effectiveCap := p.TotalQuota + p.BorrowedIn - p.LentOut
	if effectiveCap < 0 {
		effectiveCap = 0
	}
	p.AvailableQuota = effectiveCap - p.UsedQuota
	if p.AvailableQuota < 0 {
		p.AvailableQuota = 0
	}

	if effectiveCap > 0 {
		p.Utilization = math.Round((float64(p.UsedQuota)/float64(effectiveCap))*1000) / 1000
	} else {
		p.Utilization = 1.0
	}
}

// ConsumeQuota consumes quota for a tenant if available, returning true on success.
func (qp *DistributedQuotaPool) ConsumeQuota(tenantID string, amount int64) bool {
	qp.mu.Lock()
	defer qp.mu.Unlock()

	p, exists := qp.pools[tenantID]
	if !exists {
		return false
	}

	effectiveCap := p.TotalQuota + p.BorrowedIn - p.LentOut
	if p.UsedQuota+amount > effectiveCap {
		return false
	}

	p.UsedQuota += amount
	qp.recalculatePoolLocked(p)
	return true
}

// ResetUsage clears consumed usage for a tenant (e.g. at interval boundary).
func (qp *DistributedQuotaPool) ResetUsage(tenantID string) {
	qp.mu.Lock()
	defer qp.mu.Unlock()

	if p, exists := qp.pools[tenantID]; exists {
		p.UsedQuota = 0
		qp.recalculatePoolLocked(p)
	}
}

// BorrowQuota transfers quota temporarily from a surplus lender to a starved borrower.
func (qp *DistributedQuotaPool) BorrowQuota(borrower, lender string, amount int64, duration time.Duration) (*QuotaLease, error) {
	if borrower == lender {
		return nil, ErrSameTenantBorrow
	}
	if amount <= 0 {
		return nil, errors.New("borrow amount must be positive")
	}
	if duration <= 0 {
		duration = 15 * time.Minute
	}

	qp.mu.Lock()
	defer qp.mu.Unlock()

	bPool, bExists := qp.pools[borrower]
	if !bExists {
		return nil, fmt.Errorf("%w: borrower %s", ErrTenantNotFound, borrower)
	}

	lPool, lExists := qp.pools[lender]
	if !lExists {
		return nil, fmt.Errorf("%w: lender %s", ErrTenantNotFound, lender)
	}

	// Lender must preserve at least 30% headroom of its total quota
	reservedHeadroom := int64(float64(lPool.TotalQuota) * 0.30)
	availableToLend := lPool.AvailableQuota - reservedHeadroom
	if availableToLend < amount {
		return nil, ErrInsufficientSurplus
	}

	now := time.Now()
	qp.leaseCounter++
	leaseID := fmt.Sprintf("lease-%d-%x", now.Unix(), qp.leaseCounter)

	lease := &QuotaLease{
		LeaseID:        leaseID,
		BorrowerTenant: borrower,
		LenderTenant:   lender,
		Amount:         amount,
		BorrowedAt:     now,
		ExpiresAt:      now.Add(duration),
		Status:         LeaseActive,
	}

	// Apply adjustments
	lPool.LentOut += amount
	bPool.BorrowedIn += amount
	qp.recalculatePoolLocked(lPool)
	qp.recalculatePoolLocked(bPool)

	qp.leases[leaseID] = lease
	qp.recordEventLocked(QuotaRebalanceEvent{
		Timestamp:      now,
		Action:         "borrow",
		BorrowerTenant: borrower,
		LenderTenant:   lender,
		Amount:         amount,
		Reason:         "Tenant quota exhaustion mitigation",
		Status:         LeaseActive,
	})

	return lease, nil
}

// ReturnQuota returns borrowed quota from borrower back to lender before or upon expiry.
func (qp *DistributedQuotaPool) ReturnQuota(leaseID string) error {
	qp.mu.Lock()
	defer qp.mu.Unlock()

	lease, exists := qp.leases[leaseID]
	if !exists {
		return ErrLeaseNotFound
	}
	if lease.Status != LeaseActive {
		return ErrLeaseNotActive
	}

	return qp.terminateLeaseLocked(lease, LeaseReturned, "Voluntary return of borrowed quota")
}

// RecallQuota preemptively revokes a lease when the lender encounters unexpected load.
func (qp *DistributedQuotaPool) RecallQuota(leaseID, reason string) error {
	qp.mu.Lock()
	defer qp.mu.Unlock()

	lease, exists := qp.leases[leaseID]
	if !exists {
		return ErrLeaseNotFound
	}
	if lease.Status != LeaseActive {
		return ErrLeaseNotActive
	}

	if reason == "" {
		reason = "Lender high-watermark surge reclamation"
	}
	return qp.terminateLeaseLocked(lease, LeaseRecalled, reason)
}

func (qp *DistributedQuotaPool) terminateLeaseLocked(lease *QuotaLease, status LeaseStatus, reason string) error {
	bPool := qp.pools[lease.BorrowerTenant]
	lPool := qp.pools[lease.LenderTenant]

	if bPool != nil {
		bPool.BorrowedIn -= lease.Amount
		if bPool.BorrowedIn < 0 {
			bPool.BorrowedIn = 0
		}
		qp.recalculatePoolLocked(bPool)
	}

	if lPool != nil {
		lPool.LentOut -= lease.Amount
		if lPool.LentOut < 0 {
			lPool.LentOut = 0
		}
		qp.recalculatePoolLocked(lPool)
	}

	lease.Status = status
	lease.RecallReason = reason

	qp.recordEventLocked(QuotaRebalanceEvent{
		Timestamp:      time.Now(),
		Action:         string(status),
		BorrowerTenant: lease.BorrowerTenant,
		LenderTenant:   lease.LenderTenant,
		Amount:         lease.Amount,
		Reason:         reason,
		Status:         status,
	})

	return nil
}

// RebalanceQuotas evaluates active leases for expiration and recalls quota if lenders surge.
func (qp *DistributedQuotaPool) RebalanceQuotas() []QuotaRebalanceEvent {
	qp.mu.Lock()
	defer qp.mu.Unlock()

	now := time.Now()
	var triggeredEvents []QuotaRebalanceEvent

	// 1. Expire past leases
	for _, lease := range qp.leases {
		if lease.Status == LeaseActive && now.After(lease.ExpiresAt) {
			_ = qp.terminateLeaseLocked(lease, LeaseExpired, "Lease time-to-live expired")
			triggeredEvents = append(triggeredEvents, qp.events[len(qp.events)-1])
		}
	}

	// 2. Recall if lender utilization exceeds 85%
	for _, lease := range qp.leases {
		if lease.Status == LeaseActive {
			if lPool, ok := qp.pools[lease.LenderTenant]; ok && lPool.Utilization >= 0.85 {
				_ = qp.terminateLeaseLocked(lease, LeaseRecalled, "Lender utilization exceeded 85% threshold")
				triggeredEvents = append(triggeredEvents, qp.events[len(qp.events)-1])
			}
		}
	}

	return triggeredEvents
}

func (qp *DistributedQuotaPool) recordEventLocked(ev QuotaRebalanceEvent) {
	qp.events = append(qp.events, ev)
	if len(qp.events) > qp.maxEvents {
		qp.events = qp.events[len(qp.events)-qp.maxEvents:]
	}
}

// ListPools returns all tenant quota pools.
func (qp *DistributedQuotaPool) ListPools() []QuotaPool {
	qp.mu.RLock()
	defer qp.mu.RUnlock()

	out := make([]QuotaPool, 0, len(qp.pools))
	for _, p := range qp.pools {
		out = append(out, *p)
	}
	return out
}

// ListLeases returns all active and historical quota leases.
func (qp *DistributedQuotaPool) ListLeases() []QuotaLease {
	qp.mu.RLock()
	defer qp.mu.RUnlock()

	out := make([]QuotaLease, 0, len(qp.leases))
	for _, l := range qp.leases {
		out = append(out, *l)
	}
	return out
}

// RecentEvents returns recent arbitration and rebalancing audit events.
func (qp *DistributedQuotaPool) RecentEvents() []QuotaRebalanceEvent {
	qp.mu.RLock()
	defer qp.mu.RUnlock()

	out := make([]QuotaRebalanceEvent, len(qp.events))
	copy(out, qp.events)
	return out
}
