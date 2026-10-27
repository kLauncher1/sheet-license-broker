package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/healing"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// initHealing bootstraps the autonomous healing and quota rebalancing manager.
func (p *Proxy) initHealing(cfg ProxyConfig) {
	healingSecret := cfg.GlobalSecret
	if healingSecret == "" {
		healingSecret = "default-healing-secret"
	}

	mgr := healing.NewManager(healing.ManagerConfig{
		BucketConfig:          healing.DefaultBucketConfig(),
		HealingSecret:         healingSecret,
		DefaultGrace:          3 * time.Minute,
		AutoRebalanceInterval: 1 * time.Minute,
	})

	// Seed baseline tenant quota pools for local testing and operation
	mgr.SetTenantQuota("default", 10000)
	mgr.SetTenantQuota("tenant-primary", 5000)
	mgr.SetTenantQuota("tenant-secondary", 3000)

	p.healingManager = mgr
}

// HealingManager returns the active healing facade orchestrator.
func (p *Proxy) HealingManager() *healing.HealingManager {
	return p.healingManager
}

// GetHealingStatus returns a real-time snapshot of bucket stats, tunnels, and quotas.
func (p *Proxy) GetHealingStatus() healing.HealingStatus {
	if p.healingManager == nil {
		return healing.HealingStatus{}
	}
	return p.healingManager.Status()
}

// ConsumeHealingTokens consumes tokens from the auto-scaling rate bucket.
func (p *Proxy) ConsumeHealingTokens(tokens float64) (bool, healing.TokenBucketStats) {
	if p.healingManager == nil {
		return true, healing.TokenBucketStats{}
	}
	return p.healingManager.ConsumeTokens(tokens)
}

// IssueHealingTicket creates a verifiable reconnect ticket for a client.
func (p *Proxy) IssueHealingTicket(sessionID, clientID, hwid, tenantID string, lastAckSeq int64, ttl time.Duration) *healing.HealingTicket {
	if p.healingManager == nil {
		return nil
	}
	return p.healingManager.IssueHealingTicket(sessionID, clientID, hwid, tenantID, lastAckSeq, ttl)
}

// ResumeHealingTunnel validates the reconnect ticket and delivers missed events.
func (p *Proxy) ResumeHealingTunnel(ticket *healing.HealingTicket) (*healing.HealingSession, []healing.DeltaEvent, error) {
	if p.healingManager == nil {
		return nil, nil, fmt.Errorf("healing manager is not initialized")
	}

	sess, deltas, err := p.healingManager.ResumeHealingTunnel(ticket)
	if err != nil {
		return nil, nil, err
	}

	p.BroadcastStreamEvent("healing_tunnel_resumed", map[string]interface{}{
		"session_id":     sess.SessionID,
		"client_id":      sess.ClientID,
		"tenant_id":      sess.TenantID,
		"missed_events":  len(deltas),
		"reconnected_at": sess.LastHeartbeat,
	})

	return sess, deltas, nil
}

// BorrowHealingQuota allocates quota from a surplus tenant to a starved tenant.
func (p *Proxy) BorrowHealingQuota(ctx context.Context, borrower, lender string, amount int64, duration time.Duration) (*healing.QuotaLease, error) {
	if p.healingManager == nil {
		return nil, fmt.Errorf("healing manager is not initialized")
	}

	lease, err := p.healingManager.BorrowQuota(borrower, lender, amount, duration)
	if err != nil {
		return nil, err
	}

	p.BroadcastStreamEvent("healing_quota_borrowed", map[string]interface{}{
		"lease_id":        lease.LeaseID,
		"borrower_tenant": lease.BorrowerTenant,
		"lender_tenant":   lease.LenderTenant,
		"amount":          lease.Amount,
		"expires_at":      lease.ExpiresAt,
	})

	p.NotifyLicenseEvent(webhook.EventLicenseCreated, "", lease.LeaseID,
		fmt.Sprintf("Quota Borrowed: %s borrowed %d units from %s", borrower, amount, lender))

	if p.IsRemoteEnabled() && p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "healing_record_lease", map[string]interface{}{
				"lease_id":        lease.LeaseID,
				"borrower_tenant": lease.BorrowerTenant,
				"lender_tenant":   lease.LenderTenant,
				"amount":          lease.Amount,
				"borrowed_at":     lease.BorrowedAt.Format(time.RFC3339),
				"expires_at":      lease.ExpiresAt.Format(time.RFC3339),
				"status":          string(lease.Status),
			})
		}()
	}

	return lease, nil
}

// ReturnHealingQuota restores borrowed quota back to the lending tenant.
func (p *Proxy) ReturnHealingQuota(ctx context.Context, leaseID string) error {
	if p.healingManager == nil {
		return fmt.Errorf("healing manager is not initialized")
	}

	if err := p.healingManager.ReturnQuota(leaseID); err != nil {
		return err
	}

	p.BroadcastStreamEvent("healing_quota_returned", map[string]interface{}{
		"lease_id": leaseID,
		"status":   "returned",
	})

	if p.IsRemoteEnabled() && p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "healing_return_lease", map[string]interface{}{
				"lease_id": leaseID,
				"status":   "returned",
			})
		}()
	}

	return nil
}

// RecallHealingQuota preemptively reclaims lent quota when lender load surges.
func (p *Proxy) RecallHealingQuota(ctx context.Context, leaseID, reason string) error {
	if p.healingManager == nil {
		return fmt.Errorf("healing manager is not initialized")
	}

	if err := p.healingManager.RecallQuota(leaseID, reason); err != nil {
		return err
	}

	p.BroadcastStreamEvent("healing_quota_recalled", map[string]interface{}{
		"lease_id": leaseID,
		"reason":   reason,
		"status":   "recalled",
	})

	return nil
}

// RebalanceHealingQuotas triggers an explicit check for lease expirations and rebalancing.
func (p *Proxy) RebalanceHealingQuotas(ctx context.Context) []healing.QuotaRebalanceEvent {
	if p.healingManager == nil {
		return nil
	}
	return p.healingManager.RebalanceQuotas()
}
