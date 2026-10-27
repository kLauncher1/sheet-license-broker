package healing

import (
	"time"
)

// TunnelState represents the operational status of a client connection tunnel.
type TunnelState string

const (
	TunnelStateConnected    TunnelState = "connected"
	TunnelStateDisconnected TunnelState = "disconnected"
	TunnelStateResumed      TunnelState = "resumed"
	TunnelStateClosed       TunnelState = "closed"
)

// LeaseStatus represents the lifecycle state of a borrowed quota allocation.
type LeaseStatus string

const (
	LeaseActive   LeaseStatus = "active"
	LeaseReturned LeaseStatus = "returned"
	LeaseExpired  LeaseStatus = "expired"
	LeaseRecalled LeaseStatus = "recalled"
)

// ScaleMode indicates the dynamic scaling behavior of the token bucket.
type ScaleMode string

const (
	ScaleModeNormal   ScaleMode = "normal"
	ScaleModeBurst    ScaleMode = "burst"
	ScaleModeThrottle ScaleMode = "throttle"
)

// TokenBucketConfig configures the auto-scaling token bucket rate limiter.
type TokenBucketConfig struct {
	BaseCapacity     float64       `json:"base_capacity"`
	MaxBurstCapacity float64       `json:"max_burst_capacity"`
	BaseRefillRate   float64       `json:"base_refill_rate"`
	MinRefillRate    float64       `json:"min_refill_rate"`
	BurstMultiplier  float64       `json:"burst_multiplier"`
	WindowDuration   time.Duration `json:"window_duration"`
}

// TokenBucketStats captures real-time metrics of the auto-scaling token bucket.
type TokenBucketStats struct {
	CurrentTokens   float64   `json:"current_tokens"`
	Capacity        float64   `json:"capacity"`
	BaseCapacity    float64   `json:"base_capacity"`
	RefillRate      float64   `json:"refill_rate"`
	LoadScore       float64   `json:"load_score"`
	ScaleMultiplier float64   `json:"scale_multiplier"`
	Mode            ScaleMode `json:"mode"`
	LastRefill      time.Time `json:"last_refill"`
}

// HealingTicket is a cryptographically signed credential allowing a disconnected
// client to re-establish an authenticated session without cold re-authentication.
type HealingTicket struct {
	SessionID  string    `json:"session_id"`
	ClientID   string    `json:"client_id"`
	HWID       string    `json:"hwid"`
	TenantID   string    `json:"tenant_id"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastAckSeq int64     `json:"last_ack_seq"`
	Signature  string    `json:"signature"`
}

// HealingSession tracks active client connectivity and retry grace periods.
type HealingSession struct {
	SessionID         string      `json:"session_id"`
	ClientID          string      `json:"client_id"`
	HWID              string      `json:"hwid"`
	TenantID          string      `json:"tenant_id"`
	State             TunnelState `json:"state"`
	ConnectedAt       time.Time   `json:"connected_at"`
	LastHeartbeat     time.Time   `json:"last_heartbeat"`
	DisconnectedAt    time.Time   `json:"disconnected_at,omitempty"`
	GraceExpiresAt    time.Time   `json:"grace_expires_at,omitempty"`
	MissedEventsCount int         `json:"missed_events_count"`
}

// DeltaEvent represents a state transition or license event buffered for replay.
type DeltaEvent struct {
	Sequence  int64     `json:"sequence"`
	TenantID  string    `json:"tenant_id"`
	ClientID  string    `json:"client_id"`
	EventType string    `json:"event_type"`
	Payload   string    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// QuotaPool tracks entitlement limits and current utilization for a tenant.
type QuotaPool struct {
	TenantID       string  `json:"tenant_id"`
	TotalQuota     int64   `json:"total_quota"`
	UsedQuota      int64   `json:"used_quota"`
	BorrowedIn     int64   `json:"borrowed_in"`
	LentOut        int64   `json:"lent_out"`
	AvailableQuota int64   `json:"available_quota"`
	Utilization    float64 `json:"utilization"`
}

// QuotaLease records a time-bound quota transfer between tenant instances.
type QuotaLease struct {
	LeaseID        string      `json:"lease_id"`
	BorrowerTenant string      `json:"borrower_tenant"`
	LenderTenant   string      `json:"lender_tenant"`
	Amount         int64       `json:"amount"`
	BorrowedAt     time.Time   `json:"borrowed_at"`
	ExpiresAt      time.Time   `json:"expires_at"`
	Status         LeaseStatus `json:"status"`
	RecallReason   string      `json:"recall_reason,omitempty"`
}

// QuotaRebalanceEvent documents actions taken during distributed quota arbitration.
type QuotaRebalanceEvent struct {
	Timestamp      time.Time   `json:"timestamp"`
	Action         string      `json:"action"`
	BorrowerTenant string      `json:"borrower_tenant"`
	LenderTenant   string      `json:"lender_tenant"`
	Amount         int64       `json:"amount"`
	Reason         string      `json:"reason"`
	Status         LeaseStatus `json:"status"`
}

// HealingStatus provides a comprehensive overview of autonomous healing operations.
type HealingStatus struct {
	Bucket            TokenBucketStats      `json:"bucket"`
	ActiveTunnels     int                   `json:"active_tunnels"`
	SuspendedTunnels  int                   `json:"suspended_tunnels"`
	TotalMissedEvents int64                 `json:"total_missed_events"`
	QuotaPools        []QuotaPool           `json:"quota_pools"`
	ActiveLeases      []QuotaLease          `json:"active_leases"`
	RecentRebalances  []QuotaRebalanceEvent `json:"recent_rebalances"`
}
