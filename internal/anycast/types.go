package anycast

import (
	"time"
)

// POPStatus represents the operational health status of a Point of Presence.
type POPStatus string

const (
	POPStatusHealthy  POPStatus = "healthy"
	POPStatusDegraded POPStatus = "degraded"
	POPStatusOffline  POPStatus = "offline"
)

// POP defines a geo-distributed edge CDN point of presence node.
type POP struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Region      string    `json:"region"`
	Country     string    `json:"country"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	EndpointURL string    `json:"endpoint_url"`
	Weight      float64   `json:"weight"`
	Status      POPStatus `json:"status"`
	LastSeen    time.Time `json:"last_seen"`
	AverageRTT  float64   `json:"average_rtt_ms,omitempty"`
}

// GeoCoordinates defines a spherical latitude and longitude point.
type GeoCoordinates struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// RoutingDecision encapsulates the calculated optimal POP and fallback options.
type RoutingDecision struct {
	SelectedPOP        POP       `json:"selected_pop"`
	FallbackPOPs       []POP     `json:"fallback_pops"`
	EstimatedLatencyMS float64   `json:"estimated_latency_ms"`
	SignedRoutingToken string    `json:"signed_routing_token"`
	Timestamp          time.Time `json:"timestamp"`
	ClientIP           string    `json:"client_ip,omitempty"`
}

// EdgeCacheStats captures microsecond-scale performance telemetry of L1 cache.
type EdgeCacheStats struct {
	Hits              int64   `json:"hits"`
	Misses            int64   `json:"misses"`
	Revalidations     int64   `json:"revalidations"`
	LookupLatencyUS   float64 `json:"lookup_latency_us"`
	CachedTierEntries int     `json:"cached_tier_entries"`
	HitRatio          float64 `json:"hit_ratio"`
}

// PartitionStatus defines network connectivity and isolation states.
type PartitionStatus string

const (
	PartitionNormal      PartitionStatus = "normal"
	PartitionPartitioned PartitionStatus = "partitioned"
	PartitionHealing     PartitionStatus = "healing"
)

// PartitionState tracks the partition isolation and recovery lifecycle for a region.
type PartitionState struct {
	RegionID           string          `json:"region_id"`
	Status             PartitionStatus `json:"status"`
	IsolatedSince      *time.Time      `json:"isolated_since,omitempty"`
	LocalLeaseDuration time.Duration   `json:"local_lease_duration"`
	RecoverySyncStatus string          `json:"recovery_sync_status"`
	LastProbeTime      time.Time       `json:"last_probe_time"`
	MitigationToken    string          `json:"mitigation_token,omitempty"`
}

// TelemetryProbe represents active health and latency telemetry from edge clients or brokers.
type TelemetryProbe struct {
	SourceRegion string    `json:"source_region"`
	SourceIP     string    `json:"source_ip"`
	TargetPOPID  string    `json:"target_pop_id"`
	RTTLatencyMS float64   `json:"rtt_latency_ms"`
	PacketLoss   float64   `json:"packet_loss"`
	JitterMS     float64   `json:"jitter_ms"`
	Timestamp    time.Time `json:"timestamp"`
}

// RoutingTokenClaims holds the payload of a cryptographically signed routing token.
type RoutingTokenClaims struct {
	POPID     string `json:"pop_id"`
	ClientIP  string `json:"client_ip"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
}

// EmergencyLeaseToken represents a signed mitigation grant during network partitions.
type EmergencyLeaseToken struct {
	RegionID    string    `json:"region_id"`
	LicenseKey  string    `json:"license_key"`
	ClientHWID  string    `json:"client_hwid"`
	LeaseExpiry time.Time `json:"lease_expiry"`
	IssuedAt    time.Time `json:"issued_at"`
	Signature   string    `json:"signature"`
}
