package anomaly

import (
	"time"
)

// RiskLevel defines normalized risk severity tiers.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// ChallengeType defines automated escalation challenge categories.
type ChallengeType string

const (
	ChallengeNone           ChallengeType = "none"
	ChallengeReAttestation  ChallengeType = "re_attestation"
	ChallengeCryptoProof    ChallengeType = "crypto_proof"
	ChallengeHardwarePin    ChallengeType = "hardware_pin"
)

// RiskFactor identifies specific anomalous behaviors contributing to risk.
type RiskFactor struct {
	Code        string    `json:"code"`
	Description string    `json:"description"`
	Severity    int       `json:"severity"` // Points added to score (1-50)
	DetectedAt  time.Time `json:"detected_at"`
}

// ClientObservation records a single heartbeat, verification, or telemetry event.
type ClientObservation struct {
	LicenseKey string            `json:"license_key"`
	HWID       string            `json:"hwid"`
	IP         string            `json:"ip"`
	Country    string            `json:"country,omitempty"`
	Region     string            `json:"region,omitempty"`
	ASN        string            `json:"asn,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Action     string            `json:"action"` // "heartbeat", "verify", "telemetry"
	Timestamp  time.Time         `json:"timestamp"`
	LatencyMs  int64             `json:"latency_ms,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// HeartbeatDrift captures statistical timing analysis for a client.
type HeartbeatDrift struct {
	SampleCount      int       `json:"sample_count"`
	MeanIntervalMs   float64   `json:"mean_interval_ms"`
	StdDevIntervalMs float64   `json:"std_dev_interval_ms"`
	LastIntervalMs   int64     `json:"last_interval_ms"`
	ZScore           float64   `json:"z_score"`
	DriftState       string    `json:"drift_state"` // "nominal", "mild_drift", "accelerated", "erratic"
	EvaluatedAt      time.Time `json:"evaluated_at"`
}

// GeoVelocityAnomaly captures impossible travel or rapid geographical shift detection.
type GeoVelocityAnomaly struct {
	PreviousCountry     string    `json:"previous_country"`
	CurrentCountry      string    `json:"current_country"`
	PreviousIP          string    `json:"previous_ip"`
	CurrentIP           string    `json:"current_ip"`
	TimeDeltaSec        float64   `json:"time_delta_sec"`
	EstimatedDistanceKm float64   `json:"estimated_distance_km"`
	CalculatedSpeedKmH  float64   `json:"calculated_speed_kmh"`
	ImpossibleTravel    bool      `json:"impossible_travel"`
	DetectedAt          time.Time `json:"detected_at"`
}

// RiskScore represents the comprehensive risk evaluation for a client entity.
type RiskScore struct {
	EntityID             string        `json:"entity_id"` // Normalized LicenseKey or HWID
	Score                int           `json:"score"`     // 0 to 100
	Level                RiskLevel     `json:"level"`     // low, medium, high, critical
	Factors              []RiskFactor  `json:"factors"`
	ChallengeEscalation  bool          `json:"challenge_escalation"`
	ChallengeType        ChallengeType `json:"challenge_type"`
	ChallengeToken       string        `json:"challenge_token,omitempty"`
	ChallengeExpiresAt   time.Time     `json:"challenge_expires_at,omitempty"`
	QuarantineTriggered  bool          `json:"quarantine_triggered"`
	EvaluatedAt          time.Time     `json:"evaluated_at"`
}

// GraphNode represents an entity in the SIEM security incident graph.
type GraphNode struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // "license", "hwid", "ip", "geo", "incident"
	Label      string                 `json:"label"`
	RiskScore  int                    `json:"risk_score"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// GraphEdge represents a directed relationship in the SIEM incident graph.
type GraphEdge struct {
	Source    string    `json:"source"`
	Target    string    `json:"target"`
	Relation  string    `json:"relation"` // "BOUND_TO", "ORIGINATING_FROM", "LOCATED_IN", "TRIGGERED"
	Weight    float64   `json:"weight"`
	Timestamp time.Time `json:"timestamp"`
}

// IncidentGraph represents an exportable topology graph for enterprise SIEM ingestion.
type IncidentGraph struct {
	Format      string      `json:"format"` // "siem-topology-v1"
	GeneratedAt time.Time   `json:"generated_at"`
	TotalNodes  int         `json:"total_nodes"`
	TotalEdges  int         `json:"total_edges"`
	Nodes       []GraphNode `json:"nodes"`
	Edges       []GraphEdge `json:"edges"`
}

// GraphFilter defines criteria for exporting SIEM incident graphs.
type GraphFilter struct {
	LicenseKey   string    `json:"license_key,omitempty"`
	HWID         string    `json:"hwid,omitempty"`
	MinRiskScore int       `json:"min_risk_score,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	Limit        int       `json:"limit,omitempty"`
}

// TelemetrySummary delivers real-time metrics on behavioral anomaly detection.
type TelemetrySummary struct {
	TotalObservations        int64     `json:"total_observations"`
	ActiveMonitoredEntities  int       `json:"active_monitored_entities"`
	AnomaliesDetected        int64     `json:"anomalies_detected"`
	ChallengesIssued         int64     `json:"challenges_issued"`
	ChallengesCleared        int64     `json:"challenges_cleared"`
	ActiveQuarantines        int64     `json:"active_quarantines"`
	LastAnomalyDetectedAt    time.Time `json:"last_anomaly_detected_at,omitempty"`
}
