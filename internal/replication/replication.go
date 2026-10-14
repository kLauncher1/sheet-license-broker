package replication

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/gas"
	"github.com/kLauncher1/sheet-license-broker/internal/metrics"
)

// ActiveRole specifies which backend sheet is currently active.
type ActiveRole string

const (
	RolePrimary ActiveRole = "primary"
	RoleStandby ActiveRole = "standby"
)

// BackendHealth reports the connectivity state of a backend sheet.
type BackendHealth struct {
	URL         string        `json:"url"`
	Healthy     bool          `json:"healthy"`
	Latency     time.Duration `json:"latency_ms"`
	LastChecked time.Time     `json:"last_checked"`
	LastError   string        `json:"last_error,omitempty"`
}

// HAStatus exposes comprehensive telemetry regarding active-standby replication.
type HAStatus struct {
	ActiveRole        ActiveRole    `json:"active_role"`
	Primary           BackendHealth `json:"primary"`
	Standby           BackendHealth `json:"standby"`
	ReplicationCount  uint64        `json:"replication_count"`
	ReplicationErrors uint64        `json:"replication_errors"`
	FailoverCount     uint64        `json:"failover_count"`
	LastFailover      *time.Time    `json:"last_failover,omitempty"`
	AutoFailover      bool          `json:"auto_failover"`
}

// HAConfig configures the High Availability replication coordinator.
type HAConfig struct {
	PrimaryClient *gas.Client
	StandbyClient *gas.Client
	AutoFailover  bool
	ProbeInterval time.Duration
}

// HAManager coordinates dual-sheet active-standby replication, failovers, and reconciliations.
type HAManager struct {
	mu                sync.RWMutex
	primary           *gas.Client
	standby           *gas.Client
	activeRole        ActiveRole
	autoFailover      bool
	primaryHealth     BackendHealth
	standbyHealth     BackendHealth
	replicationCount  uint64
	replicationErrors uint64
	failoverCount     uint64
	lastFailover      *time.Time
	stopChan          chan struct{}
}

// NewHAManager creates a high-availability active-standby coordinator.
func NewHAManager(cfg HAConfig) *HAManager {
	mgr := &HAManager{
		primary:      cfg.PrimaryClient,
		standby:      cfg.StandbyClient,
		activeRole:   RolePrimary,
		autoFailover: cfg.AutoFailover,
		stopChan:     make(chan struct{}),
	}

	if mgr.primary != nil {
		mgr.primaryHealth.URL = mgr.primary.WebAppURL()
		mgr.primaryHealth.Healthy = true
	}
	if mgr.standby != nil {
		mgr.standbyHealth.URL = mgr.standby.WebAppURL()
		mgr.standbyHealth.Healthy = true
	}

	metrics.SetBackendHealth("primary", mgr.primary != nil)
	metrics.SetBackendHealth("standby", mgr.standby != nil)

	return mgr
}

// ActiveClient returns the currently designated active Apps Script client.
func (h *HAManager) ActiveClient() *gas.Client {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.activeRole == RoleStandby && h.standby != nil {
		return h.standby
	}
	return h.primary
}

// StandbyClient returns the standby secondary client.
func (h *HAManager) StandbyClient() *gas.Client {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.activeRole == RoleStandby {
		return h.primary
	}
	return h.standby
}

// CheckHealth probes both primary and standby endpoints and handles failover if needed.
func (h *HAManager) CheckHealth(ctx context.Context) HAStatus {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.primary != nil {
		start := time.Now()
		_, err := h.primary.Ping(ctx)
		latency := time.Since(start)
		h.primaryHealth.LastChecked = time.Now()
		h.primaryHealth.Latency = latency / time.Millisecond

		if err != nil {
			h.primaryHealth.Healthy = false
			h.primaryHealth.LastError = err.Error()
			metrics.SetBackendHealth("primary", false)
		} else {
			h.primaryHealth.Healthy = true
			h.primaryHealth.LastError = ""
			metrics.SetBackendHealth("primary", true)
		}
	}

	if h.standby != nil {
		start := time.Now()
		_, err := h.standby.Ping(ctx)
		latency := time.Since(start)
		h.standbyHealth.LastChecked = time.Now()
		h.standbyHealth.Latency = latency / time.Millisecond

		if err != nil {
			h.standbyHealth.Healthy = false
			h.standbyHealth.LastError = err.Error()
			metrics.SetBackendHealth("standby", false)
		} else {
			h.standbyHealth.Healthy = true
			h.standbyHealth.LastError = ""
			metrics.SetBackendHealth("standby", true)
		}
	}

	// Automatic failover logic
	if h.autoFailover && h.activeRole == RolePrimary && !h.primaryHealth.Healthy && h.standbyHealth.Healthy {
		h.activeRole = RoleStandby
		h.failoverCount++
		now := time.Now()
		h.lastFailover = &now
		metrics.RecordSecurityIncident("ha_failover_to_standby")
	} else if h.autoFailover && h.activeRole == RoleStandby && h.primaryHealth.Healthy {
		// Failback to primary once primary recovers
		h.activeRole = RolePrimary
		h.failoverCount++
		now := time.Now()
		h.lastFailover = &now
	}

	return h.statusLocked()
}

// ReplicateToStandby replicates a mutation asynchronously to the standby sheet backend.
func (h *HAManager) ReplicateToStandby(ctx context.Context, action string, payload interface{}) {
	standby := h.StandbyClient()
	if standby == nil {
		return
	}

	go func() {
		h.mu.Lock()
		h.replicationCount++
		h.mu.Unlock()

		asyncCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var payloadMap map[string]interface{}
		if pm, ok := payload.(map[string]interface{}); ok {
			payloadMap = pm
		} else {
			b, err := json.Marshal(payload)
			if err == nil {
				_ = json.Unmarshal(b, &payloadMap)
			}
		}

		respBytes, err := standby.ExecuteAction(asyncCtx, action, payloadMap)
		if err != nil {
			h.mu.Lock()
			h.replicationErrors++
			h.mu.Unlock()
			metrics.RecordHAReplication("standby", "failure")
			return
		}

		var res struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(respBytes, &res)
		if res.Status == "error" {
			h.mu.Lock()
			h.replicationErrors++
			h.mu.Unlock()
			metrics.RecordHAReplication("standby", "failure")
		} else {
			metrics.RecordHAReplication("standby", "success")
		}
	}()
}

// ForceFailover manually toggles the active role between primary and standby.
func (h *HAManager) ForceFailover(role ActiveRole) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if role == RoleStandby && h.standby == nil {
		return errors.New("cannot switch to standby: standby backend is not configured")
	}
	if role == RolePrimary && h.primary == nil {
		return errors.New("cannot switch to primary: primary backend is not configured")
	}

	h.activeRole = role
	h.failoverCount++
	now := time.Now()
	h.lastFailover = &now
	return nil
}

// Status returns current high-availability status snapshot.
func (h *HAManager) Status() HAStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.statusLocked()
}

func (h *HAManager) statusLocked() HAStatus {
	return HAStatus{
		ActiveRole:        h.activeRole,
		Primary:           h.primaryHealth,
		Standby:           h.standbyHealth,
		ReplicationCount:  h.replicationCount,
		ReplicationErrors: h.replicationErrors,
		FailoverCount:     h.failoverCount,
		LastFailover:      h.lastFailover,
		AutoFailover:      h.autoFailover,
	}
}
