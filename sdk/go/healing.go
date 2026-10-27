package sdk

import (
	"context"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/healing"
)

// HealingConsumeResponse captures the outcome of consuming capacity from the auto-scaling bucket.
type HealingConsumeResponse struct {
	Allowed bool                     `json:"allowed"`
	Stats   healing.TokenBucketStats `json:"stats"`
}

// HealingResumeResponse captures the result of resuming a client connection tunnel.
type HealingResumeResponse struct {
	Status       string                  `json:"status"`
	Session      *healing.HealingSession `json:"session"`
	MissedEvents []healing.DeltaEvent    `json:"missed_events"`
	MissedCount  int                     `json:"missed_count"`
}

// HealingBorrowResponse captures a newly created quota lease.
type HealingBorrowResponse struct {
	Status string              `json:"status"`
	Lease  *healing.QuotaLease `json:"lease"`
}

// HealingRebalanceResponse captures the outcome of an automated quota rebalance cycle.
type HealingRebalanceResponse struct {
	Status string                        `json:"status"`
	Events []healing.QuotaRebalanceEvent `json:"events"`
}

// GetHealingStatus retrieves operational telemetry from the autonomous healing subsystem.
func (c *Client) GetHealingStatus(ctx context.Context) (*healing.HealingStatus, error) {
	var res healing.HealingStatus
	if err := c.request(ctx, http.MethodGet, "/api/healing/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ConsumeHealingBucket consumes the requested token amount from the auto-scaling rate limiter.
func (c *Client) ConsumeHealingBucket(ctx context.Context, tokens float64) (*HealingConsumeResponse, error) {
	payload := map[string]interface{}{"tokens": tokens}
	var res HealingConsumeResponse
	if err := c.request(ctx, http.MethodPost, "/api/healing/bucket/consume", payload, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// IssueHealingTicket requests a signed reconnect ticket for a client.
func (c *Client) IssueHealingTicket(ctx context.Context, sessionID, clientID, hwid, tenantID string, lastAckSeq, ttlSeconds int64) (*healing.HealingTicket, error) {
	payload := map[string]interface{}{
		"session_id":   sessionID,
		"client_id":    clientID,
		"hwid":         hwid,
		"tenant_id":    tenantID,
		"last_ack_seq": lastAckSeq,
		"ttl_seconds":  ttlSeconds,
	}
	var res healing.HealingTicket
	if err := c.request(ctx, http.MethodPost, "/api/healing/tunnel/ticket", payload, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ResumeHealingTunnel presents a signed healing ticket to reconnect and fetch missed events.
func (c *Client) ResumeHealingTunnel(ctx context.Context, ticket *healing.HealingTicket) (*HealingResumeResponse, error) {
	var res HealingResumeResponse
	if err := c.request(ctx, http.MethodPost, "/api/healing/tunnel/resume", ticket, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// BorrowHealingQuota transfers quota temporarily between tenant pools.
func (c *Client) BorrowHealingQuota(ctx context.Context, borrower, lender string, amount, durationMinutes int64) (*HealingBorrowResponse, error) {
	payload := map[string]interface{}{
		"borrower_tenant":  borrower,
		"lender_tenant":    lender,
		"amount":           amount,
		"duration_minutes": durationMinutes,
	}
	var res HealingBorrowResponse
	if err := c.request(ctx, http.MethodPost, "/api/healing/quota/borrow", payload, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ReturnHealingQuota voluntarily returns a borrowed quota allocation.
func (c *Client) ReturnHealingQuota(ctx context.Context, leaseID string) error {
	payload := map[string]interface{}{"lease_id": leaseID}
	return c.request(ctx, http.MethodPost, "/api/healing/quota/return", payload, nil)
}

// RebalanceHealingQuotas explicitly evaluates active leases and rebalances quotas.
func (c *Client) RebalanceHealingQuotas(ctx context.Context) (*HealingRebalanceResponse, error) {
	var res HealingRebalanceResponse
	if err := c.request(ctx, http.MethodPost, "/api/healing/quota/rebalance", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
