package failover

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// ProberConfig defines tuning parameters for the synthetic health and latency prober.
type ProberConfig struct {
	ProbeInterval      time.Duration
	ProbeTimeout       time.Duration
	FailureThreshold   int
	RecoveryThreshold  int
	LatencyThresholdMS float64
	EMASmoothingFactor float64
}

// DefaultProberConfig provides battle-tested production defaults for sub-second failover.
func DefaultProberConfig() ProberConfig {
	return ProberConfig{
		ProbeInterval:      5 * time.Second,
		ProbeTimeout:       500 * time.Millisecond,
		FailureThreshold:   3,
		RecoveryThreshold:  2,
		LatencyThresholdMS: 300.0,
		EMASmoothingFactor: 0.3,
	}
}

// HealthProber manages synthetic health probes, circuit breaker transitions, and failover triggers.
type HealthProber struct {
	mu        sync.RWMutex
	config    ProberConfig
	providers map[string]*CloudProvider
	events    []FailoverEvent
	maxEvents int
}

// NewHealthProber instantiates a health prober with a predefined set of cloud providers.
func NewHealthProber(cfg ProberConfig, initialProviders []*CloudProvider) *HealthProber {
	pMap := make(map[string]*CloudProvider)
	for _, p := range initialProviders {
		cp := *p
		pMap[cp.ID] = &cp
	}
	return &HealthProber{
		config:    cfg,
		providers: pMap,
		events:    make([]FailoverEvent, 0, 50),
		maxEvents: 50,
	}
}

// RecordProbe applies probe telemetry, updates EWMA latency and jitter, and executes circuit breaker state transitions.
func (hp *HealthProber) RecordProbe(res HealthProbeResult) (bool, *FailoverEvent) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	provider, exists := hp.providers[res.ProviderID]
	if !exists {
		return false, nil
	}

	provider.TotalRequests++
	provider.LastProbeTime = res.Timestamp
	prevStatus := provider.Status
	prevCircuit := provider.CircuitState

	// Compute EWMA Latency and Jitter
	alpha := hp.config.EMASmoothingFactor
	if provider.LatencyEMA <= 0 {
		provider.LatencyEMA = res.LatencyMS
		provider.Jitter = 0.0
	} else {
		jitter := math.Abs(res.LatencyMS - provider.LatencyEMA)
		provider.Jitter = (alpha * jitter) + ((1.0 - alpha) * provider.Jitter)
		provider.LatencyEMA = (alpha * res.LatencyMS) + ((1.0 - alpha) * provider.LatencyEMA)
	}

	var failoverEvent *FailoverEvent

	if res.Success {
		provider.ConsecutiveSuccesses++
		provider.ConsecutiveFailures = 0

		// Handle circuit breaker recovery
		if provider.CircuitState == CircuitHalfOpen {
			if provider.ConsecutiveSuccesses >= hp.config.RecoveryThreshold {
				provider.CircuitState = CircuitClosed
				provider.Status = ProviderStatusHealthy
				provider.LastStateChange = res.Timestamp
			}
		} else if provider.CircuitState == CircuitOpen {
			provider.CircuitState = CircuitHalfOpen
		} else {
			// In closed state, check if latency meets SLA
			if provider.LatencyEMA > hp.config.LatencyThresholdMS {
				provider.Status = ProviderStatusDegraded
			} else {
				provider.Status = ProviderStatusHealthy
			}
		}
	} else {
		provider.FailedRequests++
		provider.ConsecutiveFailures++
		provider.ConsecutiveSuccesses = 0

		// Evaluate failure thresholds
		if provider.ConsecutiveFailures >= hp.config.FailureThreshold {
			if provider.CircuitState != CircuitOpen {
				provider.CircuitState = CircuitOpen
				provider.Status = ProviderStatusOffline
				provider.LastStateChange = res.Timestamp

				// Find best alternative provider to target failover
				altID := hp.findBestAlternativeLocked(res.ProviderID)
				failoverEvent = &FailoverEvent{
					EventID:          fmt.Sprintf("fo-%d-%s", res.Timestamp.UnixNano(), res.ProviderID),
					PreviousProvider: res.ProviderID,
					NewProvider:      altID,
					Reason:           fmt.Sprintf("Circuit breaker opened: %d consecutive failures (error: %s)", provider.ConsecutiveFailures, res.ErrorMessage),
					TriggerLatency:   provider.LatencyEMA,
					TriggerErrorRate: hp.calculateErrorRate(provider),
					Timestamp:        res.Timestamp,
				}
				hp.recordEventLocked(*failoverEvent)
			}
		} else {
			provider.Status = ProviderStatusDegraded
		}
	}

	// Update overall success rate
	if provider.TotalRequests > 0 {
		successCount := float64(provider.TotalRequests - provider.FailedRequests)
		provider.SuccessRate = math.Round((successCount/float64(provider.TotalRequests))*10000.0) / 100.0
	}

	stateChanged := (prevStatus != provider.Status) || (prevCircuit != provider.CircuitState)
	return stateChanged, failoverEvent
}

// findBestAlternativeLocked locates the healthiest alternate cloud provider.
func (hp *HealthProber) findBestAlternativeLocked(excludeID string) string {
	var bestID string
	var bestScore float64 = -1.0

	for id, p := range hp.providers {
		if id == excludeID || p.Status == ProviderStatusOffline || p.CircuitState == CircuitOpen {
			continue
		}
		score := p.Weight * (p.SuccessRate / 100.0)
		if p.LatencyEMA > 0 {
			score *= (100.0 / (100.0 + p.LatencyEMA))
		}
		if score > bestScore {
			bestScore = score
			bestID = id
		}
	}
	if bestID == "" {
		for id := range hp.providers {
			if id != excludeID {
				return id
			}
		}
	}
	return bestID
}

// recordEventLocked appends a failover event into the rolling event history.
func (hp *HealthProber) recordEventLocked(event FailoverEvent) {
	if len(hp.events) >= hp.maxEvents {
		hp.events = hp.events[1:]
	}
	hp.events = append(hp.events, event)
}

// calculateErrorRate returns the error percentage for a provider.
func (hp *HealthProber) calculateErrorRate(p *CloudProvider) float64 {
	if p.TotalRequests == 0 {
		return 0.0
	}
	return (float64(p.FailedRequests) / float64(p.TotalRequests)) * 100.0
}

// GetProvider retrieves a copy of the specified cloud provider.
func (hp *HealthProber) GetProvider(id string) (CloudProvider, bool) {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	p, ok := hp.providers[id]
	if !ok {
		return CloudProvider{}, false
	}
	return *p, true
}

// ListProviders returns all registered providers in safe detached copies.
func (hp *HealthProber) ListProviders() []CloudProvider {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	out := make([]CloudProvider, 0, len(hp.providers))
	for _, p := range hp.providers {
		out = append(out, *p)
	}
	return out
}

// RecentEvents returns the list of recent failover occurrences.
func (hp *HealthProber) RecentEvents() []FailoverEvent {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	out := make([]FailoverEvent, len(hp.events))
	copy(out, hp.events)
	return out
}

// SummaryStats computes aggregate network health across all providers.
func (hp *HealthProber) SummaryStats() (avgLatency float64, uptimeRatio float64, activeCount int) {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	var totalLat float64
	var healthyCount int
	for _, p := range hp.providers {
		if p.Status == ProviderStatusHealthy || p.Status == ProviderStatusDegraded {
			activeCount++
			if p.Status == ProviderStatusHealthy {
				healthyCount++
			}
		}
		totalLat += p.LatencyEMA
	}
	if len(hp.providers) > 0 {
		avgLatency = math.Round((totalLat/float64(len(hp.providers)))*100.0) / 100.0
		uptimeRatio = math.Round((float64(healthyCount)/float64(len(hp.providers)))*10000.0) / 100.0
	}
	return avgLatency, uptimeRatio, activeCount
}
