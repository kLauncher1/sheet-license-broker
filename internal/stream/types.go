package stream

import (
	"encoding/json"
	"time"
)

// Stream event types for bidirectional WebSocket communication.
const (
	EventConnected   = "stream:connected"
	EventSubscribe   = "stream:subscribe"
	EventHeartbeat   = "stream:heartbeat"
	EventTelemetry   = "stream:telemetry"
	EventRevocation  = "stream:revocation"
	EventKillSwitch  = "stream:kill_switch"
	EventPing        = "stream:ping"
	EventPong        = "stream:pong"
	EventError       = "stream:error"
	EventAcknowledge = "stream:ack"
)

// Message encapsulates a standard envelope sent over the WebSocket stream.
type Message struct {
	Event      string          `json:"event"`
	LicenseKey string          `json:"license_key,omitempty"`
	HWID       string          `json:"hwid,omitempty"`
	TenantID   string          `json:"tenant_id,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Timestamp  int64           `json:"timestamp"`
}

// NewMessage constructs a timestamped stream message envelope.
func NewMessage(event string, payload interface{}) (Message, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return Message{}, err
		}
		raw = b
	}
	return Message{
		Event:     event,
		Payload:   raw,
		Timestamp: time.Now().Unix(),
	}, nil
}

// ClientInfo captures active connection state and metadata for telemetry reporting.
type ClientInfo struct {
	ID            string            `json:"id"`
	LicenseKey    string            `json:"license_key"`
	HWID          string            `json:"hwid"`
	TenantID      string            `json:"tenant_id"`
	RemoteAddr    string            `json:"remote_addr"`
	ConnectedAt   time.Time         `json:"connected_at"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	LatencyMs     int64             `json:"latency_ms"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// HeartbeatPayload represents periodic telemetry transmitted from client devices.
type HeartbeatPayload struct {
	ClientVersion string  `json:"client_version"`
	OS            string  `json:"os"`
	MemoryUsageMB float64 `json:"memory_usage_mb"`
	CPUPercent    float64 `json:"cpu_percent"`
	Status        string  `json:"status"`
	Timestamp     int64   `json:"timestamp"`
}

// KillSwitchPayload represents an immediate remote termination directive.
type KillSwitchPayload struct {
	Target         string `json:"target"`
	Reason         string `json:"reason"`
	Immediate      bool   `json:"immediate"`
	GracePeriodSec int    `json:"grace_period_sec,omitempty"`
	Timestamp      int64  `json:"timestamp"`
}

// RevocationPayload indicates that an entitlement has been revoked remotely.
type RevocationPayload struct {
	LicenseKey string `json:"license_key,omitempty"`
	HWID       string `json:"hwid,omitempty"`
	Reason     string `json:"reason"`
	RevokedAt  int64  `json:"revoked_at"`
}

// TelemetrySummary provides aggregate metrics across all active stream connections.
type TelemetrySummary struct {
	ActiveConnections int                  `json:"active_connections"`
	UniqueLicenses    int                  `json:"unique_licenses"`
	UniqueDevices     int                  `json:"unique_devices"`
	TotalHeartbeats   int64                `json:"total_heartbeats"`
	TotalRevocations  int64                `json:"total_revocations"`
	UptimeSeconds     int64                `json:"uptime_seconds"`
	Clients           []ClientInfo         `json:"clients,omitempty"`
	RecentEvents      []RecentStreamEvent  `json:"recent_events,omitempty"`
}

// RecentStreamEvent stores an in-memory audit log entry for the web dashboard stream feed.
type RecentStreamEvent struct {
	ID        string `json:"id"`
	Event     string `json:"event"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	Timestamp int64  `json:"timestamp"`
}
