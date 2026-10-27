package healing

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAutoScalingBucket_BasicAndBurst(t *testing.T) {
	cfg := TokenBucketConfig{
		BaseCapacity:     10.0,
		MaxBurstCapacity: 25.0,
		BaseRefillRate:   5.0,
		MinRefillRate:    1.0,
		BurstMultiplier:  2.0,
		WindowDuration:   50 * time.Millisecond,
	}

	bucket := NewAutoScalingBucket(cfg)

	// Initial consume
	consumed, stats := bucket.TryConsume(5.0)
	if !consumed {
		t.Fatalf("expected initial consume to succeed")
	}
	if stats.CurrentTokens > 5.1 || stats.CurrentTokens < 4.9 {
		t.Errorf("unexpected remaining tokens: %f", stats.CurrentTokens)
	}

	// Consume remaining tokens
	consumed, _ = bucket.TryConsume(5.0)
	if !consumed {
		t.Fatalf("expected second consume to succeed")
	}

	// Consume when empty should fail
	consumed, _ = bucket.TryConsume(1.0)
	if consumed {
		t.Fatalf("expected consume to fail on empty bucket")
	}

	// Simulate healthy high-load burst
	bucket.RecordTelemetry(30, 0)
	time.Sleep(60 * time.Millisecond)

	// Trigger evaluate by consuming
	bucket.TryConsume(0)
	stats = bucket.Stats()
	if stats.Mode != ScaleModeBurst {
		t.Errorf("expected burst mode, got %s", stats.Mode)
	}
	if stats.Capacity <= cfg.BaseCapacity {
		t.Errorf("expected scaled capacity > base capacity, got %f", stats.Capacity)
	}
}

func TestAutoScalingBucket_ThrottleOnErrors(t *testing.T) {
	cfg := TokenBucketConfig{
		BaseCapacity:     20.0,
		MaxBurstCapacity: 40.0,
		BaseRefillRate:   10.0,
		MinRefillRate:    2.0,
		BurstMultiplier:  2.0,
		WindowDuration:   40 * time.Millisecond,
	}

	bucket := NewAutoScalingBucket(cfg)

	// Record heavy error rate (e.g. 50% errors)
	bucket.RecordTelemetry(20, 10)
	time.Sleep(50 * time.Millisecond)

	bucket.TryConsume(0)
	stats := bucket.Stats()
	if stats.Mode != ScaleModeThrottle {
		t.Errorf("expected throttle mode, got %s", stats.Mode)
	}
	if stats.ScaleMultiplier >= 1.0 {
		t.Errorf("expected scale multiplier < 1.0 under error load, got %f", stats.ScaleMultiplier)
	}
}

func TestHealingTunnel_TicketLifecycleAndReplay(t *testing.T) {
	tm := NewTunnelManager("test-secret-123", 200*time.Millisecond)

	// Record delta events in advance
	tm.RecordDeltaEvent("tenant-alpha", "client-1", "license_renewed", `{"status":"active"}`)
	tm.RecordDeltaEvent("tenant-alpha", "client-1", "feature_flag_updated", `{"tier":"enterprise"}`)
	tm.RecordDeltaEvent("tenant-beta", "client-2", "license_revoked", `{"reason":"fraud"}`)
	tm.RecordDeltaEvent("tenant-alpha", "", "system_announcement", `{"msg":"maintenance"}`)

	// Issue ticket for client-1 with lastAckSeq = 1
	ticket := tm.IssueTicket("sess-1", "client-1", "HWID-AA-BB", "tenant-alpha", 1, 500*time.Millisecond)
	if ticket.Signature == "" {
		t.Fatalf("expected non-empty ticket signature")
	}

	// Verify valid ticket
	if err := tm.VerifyTicket(ticket); err != nil {
		t.Fatalf("valid ticket verification failed: %v", err)
	}

	// Verify tampered ticket signature
	tampered := *ticket
	tampered.LastAckSeq = 0
	if err := tm.VerifyTicket(&tampered); err != ErrInvalidTicketSignature {
		t.Errorf("expected ErrInvalidTicketSignature, got %v", err)
	}

	// Disconnect client
	sess := tm.RecordDisconnect("client-1")
	if sess == nil || sess.State != TunnelStateDisconnected {
		t.Fatalf("expected disconnected state, got %v", sess)
	}

	// Resume tunnel with valid ticket
	resumedSess, missedEvents, err := tm.ResumeTunnel(ticket)
	if err != nil {
		t.Fatalf("resume tunnel failed: %v", err)
	}
	if resumedSess.State != TunnelStateResumed {
		t.Errorf("expected resumed state, got %s", resumedSess.State)
	}

	// Missed events: should include sequence 2 and sequence 4 (tenant broadcast),
	// but NOT sequence 1 (acknowledged) and NOT sequence 3 (tenant-beta).
	if len(missedEvents) != 2 {
		t.Fatalf("expected 2 missed events, got %d", len(missedEvents))
	}
	if missedEvents[0].Sequence != 2 || missedEvents[1].Sequence != 4 {
		t.Errorf("unexpected missed event sequences: %v", missedEvents)
	}
}

func TestHealingTunnel_ExpiredTicketAndSweep(t *testing.T) {
	tm := NewTunnelManager("test-secret-123", 50*time.Millisecond)

	ticket := tm.IssueTicket("sess-exp", "client-exp", "HWID-EXP", "tenant-test", 0, 30*time.Millisecond)
	tm.RecordDisconnect("client-exp")

	// Wait for ticket to expire
	time.Sleep(60 * time.Millisecond)

	err := tm.VerifyTicket(ticket)
	if err != ErrTicketExpired {
		t.Errorf("expected ErrTicketExpired, got %v", err)
	}

	// Sweep should close the expired disconnected session
	closed := tm.SweepExpiredTunnels()
	if closed != 1 {
		t.Errorf("expected 1 session closed by sweep, got %d", closed)
	}
}

func TestDistributedQuotaPool_BorrowAndReturn(t *testing.T) {
	qp := NewDistributedQuotaPool()

	qp.SetTenantQuota("tenant-lender", 1000)
	qp.SetTenantQuota("tenant-borrower", 200)

	// Borrower consumes 180 (90% utilization)
	consumed := qp.ConsumeQuota("tenant-borrower", 180)
	if !consumed {
		t.Fatalf("failed to consume quota for borrower")
	}

	// Borrower tries to consume another 50 -> should fail
	consumed = qp.ConsumeQuota("tenant-borrower", 50)
	if consumed {
		t.Fatalf("expected consume to fail due to quota exhaustion")
	}

	// Borrow 300 quota from lender
	lease, err := qp.BorrowQuota("tenant-borrower", "tenant-lender", 300, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("borrow quota failed: %v", err)
	}
	if lease.Status != LeaseActive || lease.Amount != 300 {
		t.Errorf("unexpected lease state: %+v", lease)
	}

	// Now borrower can consume 50 tokens
	consumed = qp.ConsumeQuota("tenant-borrower", 50)
	if !consumed {
		t.Fatalf("expected consume to succeed with borrowed quota")
	}

	// Return lease
	err = qp.ReturnQuota(lease.LeaseID)
	if err != nil {
		t.Fatalf("return quota failed: %v", err)
	}

	pools := qp.ListPools()
	var bPool, lPool QuotaPool
	for _, p := range pools {
		if p.TenantID == "tenant-borrower" {
			bPool = p
		}
		if p.TenantID == "tenant-lender" {
			lPool = p
		}
	}

	if bPool.BorrowedIn != 0 {
		t.Errorf("expected BorrowedIn to be 0 after return, got %d", bPool.BorrowedIn)
	}
	if lPool.LentOut != 0 {
		t.Errorf("expected LentOut to be 0 after return, got %d", lPool.LentOut)
	}
}

func TestDistributedQuotaPool_HeadroomConstraintsAndRecall(t *testing.T) {
	qp := NewDistributedQuotaPool()

	qp.SetTenantQuota("lender-small", 100)
	qp.SetTenantQuota("borrower-need", 100)

	// Lender small has 100 quota. 30% headroom = 30. Available to lend = 70.
	// Requesting 80 should fail with ErrInsufficientSurplus
	_, err := qp.BorrowQuota("borrower-need", "lender-small", 80, 1*time.Minute)
	if err != ErrInsufficientSurplus {
		t.Errorf("expected ErrInsufficientSurplus, got %v", err)
	}

	// Requesting 50 should succeed
	lease, err := qp.BorrowQuota("borrower-need", "lender-small", 50, 1*time.Minute)
	if err != nil {
		t.Fatalf("expected borrow of 50 to succeed, got %v", err)
	}

	// Recall lease
	err = qp.RecallQuota(lease.LeaseID, "Urgent reclamation")
	if err != nil {
		t.Fatalf("recall failed: %v", err)
	}

	leases := qp.ListLeases()
	if len(leases) != 1 || leases[0].Status != LeaseRecalled {
		t.Errorf("expected lease status recalled, got %+v", leases)
	}
}

func TestDistributedQuotaPool_AutoRebalanceExpiry(t *testing.T) {
	qp := NewDistributedQuotaPool()

	qp.SetTenantQuota("tenant-l", 500)
	qp.SetTenantQuota("tenant-b", 100)

	lease, err := qp.BorrowQuota("tenant-b", "tenant-l", 100, 30*time.Millisecond)
	if err != nil {
		t.Fatalf("borrow failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	events := qp.RebalanceQuotas()
	if len(events) == 0 {
		t.Fatalf("expected rebalance events on expired lease")
	}

	leases := qp.ListLeases()
	if leases[0].Status != LeaseExpired {
		t.Errorf("expected lease expired status, got %s", leases[0].Status)
	}
	_ = lease
}

func TestHealingManager_FacadeIntegration(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		BucketConfig: TokenBucketConfig{
			BaseCapacity:   50.0,
			BaseRefillRate: 10.0,
		},
		HealingSecret:         "facade-test-secret",
		DefaultGrace:          100 * time.Millisecond,
		AutoRebalanceInterval: 50 * time.Millisecond,
	})
	defer mgr.Close()

	mgr.SetTenantQuota("t-alpha", 1000)
	mgr.SetTenantQuota("t-beta", 1000)

	// Consume tokens
	ok, stats := mgr.ConsumeTokens(10.0)
	if !ok || stats.CurrentTokens > 40.1 {
		t.Errorf("consume tokens failed or returned unexpected stats")
	}

	// Issue healing ticket
	ticket := mgr.IssueHealingTicket("", "client-10", "HWID-10", "t-alpha", 0, 500*time.Millisecond)
	mgr.PublishDeltaEvent("t-alpha", "client-10", "alert", "welcome")

	resumed, deltas, err := mgr.ResumeHealingTunnel(ticket)
	if err != nil || len(deltas) != 1 || resumed.State != TunnelStateResumed {
		t.Errorf("facade resume tunnel failed: err=%v, deltas=%d", err, len(deltas))
	}

	// Borrow quota
	lease, err := mgr.BorrowQuota("t-alpha", "t-beta", 200, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("facade borrow quota failed: %v", err)
	}

	status := mgr.Status()
	if status.ActiveTunnels == 0 || len(status.ActiveLeases) == 0 {
		t.Errorf("unexpected status summary: %+v", status)
	}

	err = mgr.ReturnQuota(lease.LeaseID)
	if err != nil {
		t.Errorf("facade return quota failed: %v", err)
	}
}

func TestDistributedQuotaPool_ConcurrencyStress(t *testing.T) {
	qp := NewDistributedQuotaPool()
	qp.SetTenantQuota("t-concurrent", 10000)

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				qp.ConsumeQuota("t-concurrent", 1)
				if j%20 == 0 {
					qp.SetTenantQuota(fmt.Sprintf("dyn-%d", workerID), 500)
				}
			}
		}(i)
	}

	wg.Wait()

	pools := qp.ListPools()
	var mainPool *QuotaPool
	for _, p := range pools {
		if p.TenantID == "t-concurrent" {
			mainPool = &p
			break
		}
	}

	if mainPool == nil || mainPool.UsedQuota != int64(workers*iterations) {
		t.Errorf("expected 1000 used quota, got %v", mainPool)
	}
}
