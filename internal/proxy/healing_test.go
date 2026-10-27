package proxy

import (
	"context"
	"testing"
	"time"
)

func TestProxy_HealingSubsystem(t *testing.T) {
	p, err := NewProxy(ProxyConfig{
		OfflineMode:  true,
		GlobalSecret: "proxy-test-secret-healing",
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	mgr := p.HealingManager()
	if mgr == nil {
		t.Fatalf("expected initialized healing manager")
	}

	// 1. Bucket consume
	ok, stats := p.ConsumeHealingTokens(5.0)
	if !ok || stats.Capacity <= 0 {
		t.Errorf("expected successful token consumption, got ok=%v, stats=%+v", ok, stats)
	}

	// 2. Ticket and Tunnel
	ticket := p.IssueHealingTicket("proxy-sess-1", "client-proxy-1", "HWID-PROXY-1", "tenant-primary", 0, 1*time.Minute)
	if ticket == nil || ticket.Signature == "" {
		t.Fatalf("expected valid healing ticket")
	}

	sess, deltas, err := p.ResumeHealingTunnel(ticket)
	if err != nil {
		t.Fatalf("resume healing tunnel failed: %v", err)
	}
	if sess.ClientID != "client-proxy-1" || len(deltas) != 0 {
		t.Errorf("unexpected session resume state: sess=%+v, deltas=%d", sess, len(deltas))
	}

	// 3. Quota Borrow and Return
	ctx := context.Background()
	lease, err := p.BorrowHealingQuota(ctx, "tenant-secondary", "tenant-primary", 500, 5*time.Minute)
	if err != nil {
		t.Fatalf("borrow healing quota failed: %v", err)
	}
	if lease.Amount != 500 {
		t.Errorf("expected borrowed amount 500, got %d", lease.Amount)
	}

	// Verify status
	status := p.GetHealingStatus()
	if status.ActiveTunnels == 0 || len(status.ActiveLeases) == 0 {
		t.Errorf("unexpected healing status summary: %+v", status)
	}

	// Return quota
	err = p.ReturnHealingQuota(ctx, lease.LeaseID)
	if err != nil {
		t.Fatalf("return healing quota failed: %v", err)
	}

	// Rebalance
	events := p.RebalanceHealingQuotas(ctx)
	_ = events
}
