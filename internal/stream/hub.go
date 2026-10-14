package stream

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxRecentEvents = 100

// Hub maintains active client sessions, index mappings, and broadcast dispatchers.
type Hub struct {
	mu               sync.RWMutex
	clients          map[string]*Client
	byLicense        map[string]map[string]*Client
	byHWID           map[string]map[string]*Client
	byTenant         map[string]map[string]*Client
	recentEvents     []RecentStreamEvent
	totalHeartbeats  int64
	totalRevocations int64
	startTime        time.Time
}

// NewHub constructs a centralized streaming hub.
func NewHub() *Hub {
	return &Hub{
		clients:      make(map[string]*Client),
		byLicense:    make(map[string]map[string]*Client),
		byHWID:       make(map[string]map[string]*Client),
		byTenant:     make(map[string]map[string]*Client),
		recentEvents: make([]RecentStreamEvent, 0, maxRecentEvents),
		startTime:    time.Now(),
	}
}

// Register registers a new client session and indexes its metadata.
func (h *Hub) Register(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.clients[c.id] = c
	info := c.GetInfo()

	h.indexClientLocked(c, info.LicenseKey, info.HWID, info.TenantID)
	h.recordEventLocked("client_connected", c.id, fmt.Sprintf("Client connected (License: %s, HWID: %s)", info.LicenseKey, info.HWID))
}

// Unregister removes a client session and cleans up index maps.
func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.clients[c.id]; !exists {
		return
	}

	delete(h.clients, c.id)
	info := c.GetInfo()
	h.deindexClientLocked(c, info.LicenseKey, info.HWID, info.TenantID)
	h.recordEventLocked("client_disconnected", c.id, "Client disconnected")
}

// ReindexClient updates lookup indices when a client changes or updates its credentials.
func (h *Hub) ReindexClient(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	info := c.GetInfo()
	h.indexClientLocked(c, info.LicenseKey, info.HWID, info.TenantID)
}

func (h *Hub) indexClientLocked(c *Client, licKey, hwid, tenantID string) {
	if licKey != "" {
		licKey = strings.ToUpper(strings.TrimSpace(licKey))
		if h.byLicense[licKey] == nil {
			h.byLicense[licKey] = make(map[string]*Client)
		}
		h.byLicense[licKey][c.id] = c
	}
	if hwid != "" {
		hwid = strings.TrimSpace(hwid)
		if h.byHWID[hwid] == nil {
			h.byHWID[hwid] = make(map[string]*Client)
		}
		h.byHWID[hwid][c.id] = c
	}
	if tenantID != "" {
		tenantID = strings.TrimSpace(tenantID)
		if h.byTenant[tenantID] == nil {
			h.byTenant[tenantID] = make(map[string]*Client)
		}
		h.byTenant[tenantID][c.id] = c
	}
}

func (h *Hub) deindexClientLocked(c *Client, licKey, hwid, tenantID string) {
	if licKey != "" {
		licKey = strings.ToUpper(strings.TrimSpace(licKey))
		if m, ok := h.byLicense[licKey]; ok {
			delete(m, c.id)
			if len(m) == 0 {
				delete(h.byLicense, licKey)
			}
		}
	}
	if hwid != "" {
		hwid = strings.TrimSpace(hwid)
		if m, ok := h.byHWID[hwid]; ok {
			delete(m, c.id)
			if len(m) == 0 {
				delete(h.byHWID, hwid)
			}
		}
	}
	if tenantID != "" {
		tenantID = strings.TrimSpace(tenantID)
		if m, ok := h.byTenant[tenantID]; ok {
			delete(m, c.id)
			if len(m) == 0 {
				delete(h.byTenant, tenantID)
			}
		}
	}
}

// PushRevocation immediately notifies all matching connected clients of license or device revocation.
func (h *Hub) PushRevocation(licenseKey, hwid, reason string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	normKey := strings.ToUpper(strings.TrimSpace(licenseKey))
	normHWID := strings.TrimSpace(hwid)

	targets := make(map[string]*Client)

	if normKey != "" {
		if m, ok := h.byLicense[normKey]; ok {
			for id, cl := range m {
				targets[id] = cl
			}
		}
	}
	if normHWID != "" {
		if m, ok := h.byHWID[normHWID]; ok {
			for id, cl := range m {
				targets[id] = cl
			}
		}
	}

	if len(targets) == 0 {
		return 0
	}

	payload := RevocationPayload{
		LicenseKey: normKey,
		HWID:       normHWID,
		Reason:     reason,
		RevokedAt:  time.Now().Unix(),
	}
	msg, _ := NewMessage(EventRevocation, payload)
	msg.LicenseKey = normKey
	msg.HWID = normHWID

	killMsg, _ := NewMessage(EventKillSwitch, KillSwitchPayload{
		Target:    fmt.Sprintf("%s/%s", normKey, normHWID),
		Reason:    reason,
		Immediate: true,
		Timestamp: time.Now().Unix(),
	})

	signaled := 0
	for _, client := range targets {
		_ = client.SendJSON(msg)
		_ = client.SendJSON(killMsg)
		signaled++
	}

	atomic.AddInt64(&h.totalRevocations, int64(signaled))
	h.recordEventLocked("revocation_pushed", fmt.Sprintf("Key: %s, HWID: %s", normKey, normHWID),
		fmt.Sprintf("Revocation signal delivered to %d connected clients. Reason: %s", signaled, reason))

	return signaled
}

// PushKillSwitch transmits a remote kill-switch execution directive to target clients.
func (h *Hub) PushKillSwitch(target, reason string, immediate bool) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	cleanTarget := strings.TrimSpace(target)
	targets := make(map[string]*Client)

	if cleanTarget == "" || cleanTarget == "*" || strings.EqualFold(cleanTarget, "all") {
		// Broadcast to all active clients
		for id, cl := range h.clients {
			targets[id] = cl
		}
	} else {
		// Check by Client ID
		if cl, ok := h.clients[cleanTarget]; ok {
			targets[cl.id] = cl
		}
		// Check by License Key
		upper := strings.ToUpper(cleanTarget)
		if m, ok := h.byLicense[upper]; ok {
			for id, cl := range m {
				targets[id] = cl
			}
		}
		// Check by HWID
		if m, ok := h.byHWID[cleanTarget]; ok {
			for id, cl := range m {
				targets[id] = cl
			}
		}
	}

	if len(targets) == 0 {
		return 0
	}

	killMsg, _ := NewMessage(EventKillSwitch, KillSwitchPayload{
		Target:    cleanTarget,
		Reason:    reason,
		Immediate: immediate,
		Timestamp: time.Now().Unix(),
	})

	signaled := 0
	for _, client := range targets {
		_ = client.SendJSON(killMsg)
		signaled++
	}

	h.recordEventLocked("kill_switch_executed", cleanTarget,
		fmt.Sprintf("Kill switch dispatched to %d clients. Reason: %s", signaled, reason))

	return signaled
}

// Broadcast broadcasts a message to all currently connected clients.
func (h *Hub) Broadcast(msg Message) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	sent := 0
	for _, client := range h.clients {
		if err := client.SendJSON(msg); err == nil {
			sent++
		}
	}
	return sent
}

// RecordHeartbeat logs telemetry heartbeat from a client.
func (h *Hub) RecordHeartbeat(clientID string, hb HeartbeatPayload) {
	atomic.AddInt64(&h.totalHeartbeats, 1)
}

// RecordTelemetry logs telemetry updates.
func (h *Hub) RecordTelemetry(clientID string, hb HeartbeatPayload) {
	atomic.AddInt64(&h.totalHeartbeats, 1)
}

func (h *Hub) recordEventLocked(event, target, detail string) {
	entry := RecentStreamEvent{
		ID:        fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Event:     event,
		Target:    target,
		Detail:    detail,
		Timestamp: time.Now().Unix(),
	}
	if len(h.recentEvents) >= maxRecentEvents {
		h.recentEvents = h.recentEvents[1:]
	}
	h.recentEvents = append(h.recentEvents, entry)
}

// GetClients returns a snapshot of all active client sessions.
func (h *Hub) GetClients() []ClientInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make([]ClientInfo, 0, len(h.clients))
	for _, client := range h.clients {
		result = append(result, client.GetInfo())
	}
	return result
}

// GetClientCount returns the number of active clients.
func (h *Hub) GetClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// GetTelemetrySnapshot compiles a full telemetry overview for dashboard and monitoring APIs.
func (h *Hub) GetTelemetrySnapshot() TelemetrySummary {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]ClientInfo, 0, len(h.clients))
	for _, client := range h.clients {
		clients = append(clients, client.GetInfo())
	}

	events := make([]RecentStreamEvent, len(h.recentEvents))
	copy(events, h.recentEvents)

	return TelemetrySummary{
		ActiveConnections: len(h.clients),
		UniqueLicenses:    len(h.byLicense),
		UniqueDevices:     len(h.byHWID),
		TotalHeartbeats:   atomic.LoadInt64(&h.totalHeartbeats),
		TotalRevocations:  atomic.LoadInt64(&h.totalRevocations),
		UptimeSeconds:     int64(time.Since(h.startTime).Seconds()),
		Clients:           clients,
		RecentEvents:      events,
	}
}
