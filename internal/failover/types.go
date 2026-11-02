package failover

import (
	"encoding/json"
	"time"
)

// CloudProviderType specifies the cloud edge infrastructure provider.
type CloudProviderType string

const (
	ProviderTypeCloudflare CloudProviderType = "cloudflare"
	ProviderTypeCloudFront CloudProviderType = "cloudfront"
	ProviderTypeFastly     CloudProviderType = "fastly"
	ProviderTypeCustom     CloudProviderType = "custom"
)

// ProviderStatus represents the health and routing posture of a cloud edge.
type ProviderStatus string

const (
	ProviderStatusHealthy     ProviderStatus = "healthy"
	ProviderStatusDegraded    ProviderStatus = "degraded"
	ProviderStatusOffline     ProviderStatus = "offline"
	ProviderStatusMaintenance ProviderStatus = "maintenance"
)

// CircuitState represents the circuit breaker state for a cloud edge provider.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitHalfOpen CircuitState = "half-open"
	CircuitOpen     CircuitState = "open"
)

// CloudProvider encapsulates configuration, health telemetry, and runtime metrics for an edge cloud.
type CloudProvider struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Type                 CloudProviderType `json:"type"`
	EndpointURL          string            `json:"endpoint_url"`
	Weight               float64           `json:"weight"`
	Status               ProviderStatus    `json:"status"`
	CircuitState         CircuitState      `json:"circuit_state"`
	ConsecutiveFailures  int               `json:"consecutive_failures"`
	ConsecutiveSuccesses int               `json:"consecutive_successes"`
	LatencyEMA           float64           `json:"latency_ema_ms"`
	Jitter               float64           `json:"jitter_ms"`
	SuccessRate          float64           `json:"success_rate"`
	TotalRequests        int64             `json:"total_requests"`
	FailedRequests       int64             `json:"failed_requests"`
	LastProbeTime        time.Time         `json:"last_probe_time"`
	LastStateChange      time.Time         `json:"last_state_change"`
}

// HealthProbeResult records the outcome of a synthetic or real-time latency probe.
type HealthProbeResult struct {
	ProviderID   string    `json:"provider_id"`
	Timestamp    time.Time `json:"timestamp"`
	Success      bool      `json:"success"`
	LatencyMS    float64   `json:"latency_ms"`
	StatusCode   int       `json:"status_code"`
	ErrorMessage string    `json:"error_message,omitempty"`
	OriginRegion string    `json:"origin_region,omitempty"`
}

// MultiCloudRoutingToken represents a cryptographically verified routing grant issued to clients.
type MultiCloudRoutingToken struct {
	TokenID      string `json:"token_id"`
	ProviderID   string `json:"provider_id"`
	EndpointURL  string `json:"endpoint_url"`
	ClientIP     string `json:"client_ip"`
	ClientRegion string `json:"client_region"`
	IssuedAt     int64  `json:"issued_at"`
	ExpiresAt    int64  `json:"expires_at"`
	Signature    string `json:"signature"`
}

// SyncDelta represents an atomic state mutation to be replicated across partitioned cloud providers.
type SyncDelta struct {
	DeltaID        string            `json:"delta_id"`
	OriginProvider string            `json:"origin_provider"`
	SequenceNumber uint64            `json:"sequence_number"`
	VectorClock    map[string]uint64 `json:"vector_clock"`
	Action         string            `json:"action"`
	Payload        json.RawMessage   `json:"payload"`
	Timestamp      int64             `json:"timestamp"`
	Checksum       string            `json:"checksum"`
}

// SyncVoucher represents a cryptographically signed acknowledgement that a delta was committed.
type SyncVoucher struct {
	VoucherID      string `json:"voucher_id"`
	DeltaID        string `json:"delta_id"`
	SequenceNumber uint64 `json:"sequence_number"`
	SourceProvider string `json:"source_provider"`
	TargetProvider string `json:"target_provider"`
	Signature      string `json:"signature"`
	ReplicatedAt   int64  `json:"replicated_at"`
}

// FailoverEvent records an automated sub-second failover shift between cloud providers.
type FailoverEvent struct {
	EventID          string    `json:"event_id"`
	PreviousProvider string    `json:"previous_provider"`
	NewProvider      string    `json:"new_provider"`
	Reason           string    `json:"reason"`
	TriggerLatency   float64   `json:"trigger_latency_ms"`
	TriggerErrorRate float64   `json:"trigger_error_rate"`
	Timestamp        time.Time `json:"timestamp"`
}

// MultiCloudStatus captures the operational health of the multi-cloud active-active routing mesh.
type MultiCloudStatus struct {
	ActiveProviderCount int             `json:"active_provider_count"`
	TotalProviders      int             `json:"total_providers"`
	ActiveActiveEnabled bool            `json:"active_active_enabled"`
	PrimaryProviderID   string          `json:"primary_provider_id"`
	Providers           []CloudProvider `json:"providers"`
	RecentFailovers     []FailoverEvent `json:"recent_failovers"`
	TotalDeltasSynced   int64           `json:"total_deltas_synced"`
	PendingDeltas       int             `json:"pending_deltas"`
	AverageLatencyMS    float64         `json:"average_latency_ms"`
	UptimeRatio         float64         `json:"uptime_ratio"`
}
