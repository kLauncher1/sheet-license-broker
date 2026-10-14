package proxy

import (
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/stream"
)

func (p *Proxy) initStream() {
	p.streamHub = stream.NewHub()
}

// StreamHub returns the underlying WebSocket streaming hub.
func (p *Proxy) StreamHub() *stream.Hub {
	return p.streamHub
}

// ActiveStreamClients returns metadata for all currently connected streaming clients.
func (p *Proxy) ActiveStreamClients() []stream.ClientInfo {
	if p.streamHub == nil {
		return nil
	}
	return p.streamHub.GetClients()
}

// ActiveStreamCount returns the number of active streaming connections.
func (p *Proxy) ActiveStreamCount() int {
	if p.streamHub == nil {
		return 0
	}
	return p.streamHub.GetClientCount()
}

// PushRevocation immediately notifies matching active WebSocket clients of a revocation event.
func (p *Proxy) PushRevocation(licenseKey, hwid, reason string) int {
	if p.streamHub == nil {
		return 0
	}
	return p.streamHub.PushRevocation(licenseKey, hwid, reason)
}

// PushKillSwitch executes an immediate remote kill-switch directive against matching clients.
func (p *Proxy) PushKillSwitch(target, reason string, immediate bool) int {
	if p.streamHub == nil {
		return 0
	}
	return p.streamHub.PushKillSwitch(target, reason, immediate)
}

// BroadcastStreamEvent broadcasts an event payload to all connected clients.
func (p *Proxy) BroadcastStreamEvent(event string, payload interface{}) int {
	if p.streamHub == nil {
		return 0
	}
	msg, err := stream.NewMessage(event, payload)
	if err != nil {
		return 0
	}
	return p.streamHub.Broadcast(msg)
}

// GetStreamTelemetry compiles a telemetry and activity snapshot from the streaming hub.
func (p *Proxy) GetStreamTelemetry() stream.TelemetrySummary {
	if p.streamHub == nil {
		return stream.TelemetrySummary{}
	}
	return p.streamHub.GetTelemetrySnapshot()
}

// RegisterStreamClient helper wraps registration for new connections.
func (p *Proxy) RegisterStreamClient(c *stream.Client) {
	if p.streamHub != nil && c != nil {
		p.streamHub.Register(c)
	}
}

// UnregisterStreamClient helper wraps unregistration for closed connections.
func (p *Proxy) UnregisterStreamClient(c *stream.Client) {
	if p.streamHub != nil && c != nil {
		p.streamHub.Unregister(c)
	}
}

// FindConnectedClient returns client info if connected by LicenseKey or HWID.
func (p *Proxy) FindConnectedClient(identifier string) *stream.ClientInfo {
	if p.streamHub == nil {
		return nil
	}
	clean := strings.TrimSpace(identifier)
	upper := strings.ToUpper(clean)
	clients := p.streamHub.GetClients()
	for _, c := range clients {
		if strings.EqualFold(c.ID, clean) || strings.EqualFold(c.LicenseKey, upper) || strings.EqualFold(c.HWID, clean) {
			res := c
			return &res
		}
	}
	return nil
}
