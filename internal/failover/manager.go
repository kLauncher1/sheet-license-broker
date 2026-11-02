package failover

import (
	"sync"
	"time"
)

// Default predefined cloud edge providers for active-active multi-cloud routing.
var defaultCloudProviders = []*CloudProvider{
	{
		ID:           "cloudflare",
		Name:         "Cloudflare Anycast Global Edge",
		Type:         ProviderTypeCloudflare,
		EndpointURL:  "https://cloudflare.edge.sheet-broker.internal",
		Weight:       0.40,
		Status:       ProviderStatusHealthy,
		CircuitState: CircuitClosed,
		LatencyEMA:   28.5,
		SuccessRate:  100.0,
	},
	{
		ID:           "cloudfront",
		Name:         "AWS CloudFront Global POPs",
		Type:         ProviderTypeCloudFront,
		EndpointURL:  "https://cloudfront.edge.sheet-broker.internal",
		Weight:       0.35,
		Status:       ProviderStatusHealthy,
		CircuitState: CircuitClosed,
		LatencyEMA:   34.2,
		SuccessRate:  100.0,
	},
	{
		ID:           "fastly",
		Name:         "Fastly Edge Cloud Compute",
		Type:         ProviderTypeFastly,
		EndpointURL:  "https://fastly.edge.sheet-broker.internal",
		Weight:       0.25,
		Status:       ProviderStatusHealthy,
		CircuitState: CircuitClosed,
		LatencyEMA:   31.0,
		SuccessRate:  100.0,
	},
}

// MultiCloudManager orchestrates multi-cloud active-active routing, health probing, and delta synchronization.
type MultiCloudManager struct {
	mu               sync.RWMutex
	prober           *HealthProber
	router           *MultiCloudRouter
	ledger           *SyncLedger
	failoverListener func(event FailoverEvent)
}

// NewMultiCloudManager initializes the multi-cloud failover engine with default tri-edge providers.
func NewMultiCloudManager(secretKey []byte) *MultiCloudManager {
	if len(secretKey) == 0 {
		secretKey = []byte("default-sheet-license-broker-multicloud-key-32b")
	}

	knownPeers := make([]string, 0, len(defaultCloudProviders))
	for _, p := range defaultCloudProviders {
		knownPeers = append(knownPeers, p.ID)
	}

	prober := NewHealthProber(DefaultProberConfig(), defaultCloudProviders)
	router := NewMultiCloudRouter(secretKey, prober)
	ledger := NewSyncLedger(secretKey, knownPeers)

	return &MultiCloudManager{
		prober: prober,
		router: router,
		ledger: ledger,
	}
}

// SetFailoverListener registers a callback invoked whenever an automated failover event occurs.
func (m *MultiCloudManager) SetFailoverListener(listener func(event FailoverEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failoverListener = listener
}

// GetStatus compiles a comprehensive overview of multi-cloud health, failovers, and sync state.
func (m *MultiCloudManager) GetStatus() MultiCloudStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := m.prober.ListProviders()
	recentEvents := m.prober.RecentEvents()
	avgLatency, uptimeRatio, activeCount := m.prober.SummaryStats()
	totalSynced, pendingDeltas, _ := m.ledger.SummaryStats()

	primaryID := "cloudflare"
	if len(providers) > 0 {
		primaryID = providers[0].ID
	}

	return MultiCloudStatus{
		ActiveProviderCount: activeCount,
		TotalProviders:      len(providers),
		ActiveActiveEnabled: true,
		PrimaryProviderID:   primaryID,
		Providers:           providers,
		RecentFailovers:     recentEvents,
		TotalDeltasSynced:   totalSynced,
		PendingDeltas:       pendingDeltas,
		AverageLatencyMS:    avgLatency,
		UptimeRatio:         uptimeRatio,
	}
}

// ListProviders returns all registered cloud edge providers.
func (m *MultiCloudManager) ListProviders() []CloudProvider {
	return m.prober.ListProviders()
}

// RouteRequest evaluates client geo parameters and returns the optimal provider and signed routing token.
func (m *MultiCloudManager) RouteRequest(clientRegion, clientIP string) (*CloudProvider, *MultiCloudRoutingToken, error) {
	return m.router.SelectOptimalProvider(clientRegion, clientIP)
}

// RecordProbe records probe measurements and executes automated failovers if thresholds are breached.
func (m *MultiCloudManager) RecordProbe(res HealthProbeResult) (*FailoverEvent, error) {
	if res.Timestamp.IsZero() {
		res.Timestamp = time.Now().UTC()
	}

	_, event := m.prober.RecordProbe(res)
	if event != nil {
		m.mu.RLock()
		listener := m.failoverListener
		m.mu.RUnlock()
		if listener != nil {
			listener(*event)
		}
	}
	return event, nil
}

// SubmitDelta commits an atomic state mutation to the sync ledger for zero-packet-loss replication.
func (m *MultiCloudManager) SubmitDelta(originProvider string, action string, payload []byte) (*SyncDelta, error) {
	return m.ledger.RecordDelta(originProvider, action, payload)
}

// GetPendingSync returns uncommitted deltas queued for a recovering or partitioned cloud provider.
func (m *MultiCloudManager) GetPendingSync(providerID string, limit int) []*SyncDelta {
	return m.ledger.GetPendingDeltas(providerID, limit)
}

// AcknowledgeSync marks a delta as committed for a cloud provider.
func (m *MultiCloudManager) AcknowledgeSync(providerID, deltaID string, voucher *SyncVoucher) error {
	return m.ledger.AcknowledgeSync(providerID, deltaID, voucher)
}

// CreateVoucher signs a receipt acknowledging cross-cloud replication of a delta.
func (m *MultiCloudManager) CreateVoucher(deltaID string, seq uint64, src, tgt string) (*SyncVoucher, error) {
	return m.ledger.CreateVoucher(deltaID, seq, src, tgt)
}

// SimulateOutage triggers an administrative failover event for chaos engineering or testing.
func (m *MultiCloudManager) SimulateOutage(providerID, reason string) (*FailoverEvent, error) {
	event, err := m.router.SimulateOutage(providerID, reason)
	if err == nil && event != nil {
		m.mu.RLock()
		listener := m.failoverListener
		m.mu.RUnlock()
		if listener != nil {
			listener(*event)
		}
	}
	return event, err
}

// VerifyToken validates an issued multi-cloud routing token.
func (m *MultiCloudManager) VerifyToken(token MultiCloudRoutingToken) error {
	return m.router.VerifyRoutingToken(token)
}
