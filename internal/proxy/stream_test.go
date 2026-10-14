package proxy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/stream"
)

func TestProxyStreamHubInitialization(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to initialize proxy: %v", err)
	}

	if p.StreamHub() == nil {
		t.Fatalf("expected non-nil StreamHub in proxy")
	}
	if p.ActiveStreamCount() != 0 {
		t.Errorf("expected 0 active stream connections initially, got %d", p.ActiveStreamCount())
	}

	snap := p.GetStreamTelemetry()
	if snap.ActiveConnections != 0 {
		t.Errorf("expected 0 active connections in telemetry snapshot, got %d", snap.ActiveConnections)
	}
}

func TestProxyRevokePushesStreamRevocation(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to initialize proxy: %v", err)
	}

	client := stream.NewClient("cl-stream-1", nil, p.StreamHub(), stream.ClientInfo{
		LicenseKey: "LIC-STREAM-ABC",
		HWID:       "HWID-STREAM-111",
		TenantID:   "tenant-test",
	})
	p.RegisterStreamClient(client)
	defer p.UnregisterStreamClient(client)

	if p.ActiveStreamCount() != 1 {
		t.Fatalf("expected 1 active client, got %d", p.ActiveStreamCount())
	}

	found := p.FindConnectedClient("LIC-STREAM-ABC")
	if found == nil || found.ID != "cl-stream-1" {
		t.Errorf("expected to find client by license key")
	}

	// Trigger proxy license revocation
	ctx := context.Background()
	err = p.RevokeLicense(ctx, "LIC-STREAM-ABC", "Security policy violation")
	if err != nil {
		t.Fatalf("RevokeLicense failed: %v", err)
	}

	// Verify message in client send channel
	var receivedRevocation bool
	for i := 0; i < 2; i++ {
		select {
		case msg := <-client.SendChanForTest():
			var env stream.Message
			_ = json.Unmarshal(msg, &env)
			if env.Event == stream.EventRevocation {
				receivedRevocation = true
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timed out waiting for stream revocation message")
		}
	}

	if !receivedRevocation {
		t.Errorf("client did not receive EventRevocation message")
	}
}

func TestProxyBlacklistPushesStreamRevocation(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to initialize proxy: %v", err)
	}

	client := stream.NewClient("cl-stream-2", nil, p.StreamHub(), stream.ClientInfo{
		LicenseKey: "LIC-STREAM-XYZ",
		HWID:       "HWID-BANNED-DEVICE",
	})
	p.RegisterStreamClient(client)
	defer p.UnregisterStreamClient(client)

	ctx := context.Background()
	err = p.BlacklistDevice(ctx, "HWID-BANNED-DEVICE", "Memory tamper detection")
	if err != nil {
		t.Fatalf("BlacklistDevice failed: %v", err)
	}

	// Verify kill switch frame received
	var receivedKill bool
	for i := 0; i < 2; i++ {
		select {
		case msg := <-client.SendChanForTest():
			var env stream.Message
			_ = json.Unmarshal(msg, &env)
			if env.Event == stream.EventKillSwitch {
				receivedKill = true
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timed out waiting for stream kill switch message")
		}
	}

	if !receivedKill {
		t.Errorf("client did not receive EventKillSwitch message")
	}
}

func TestProxyPushKillSwitchAndBroadcast(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to initialize proxy: %v", err)
	}

	c1 := stream.NewClient("c-1", nil, p.StreamHub(), stream.ClientInfo{LicenseKey: "LIC-1"})
	c2 := stream.NewClient("c-2", nil, p.StreamHub(), stream.ClientInfo{LicenseKey: "LIC-2"})

	p.RegisterStreamClient(c1)
	p.RegisterStreamClient(c2)
	defer func() {
		p.UnregisterStreamClient(c1)
		p.UnregisterStreamClient(c2)
	}()

	// Targeted kill switch on c1
	signaled := p.PushKillSwitch("c-1", "Admin intervention", true)
	if signaled != 1 {
		t.Errorf("expected 1 signaled client, got %d", signaled)
	}

	// Broadcast an alert
	sent := p.BroadcastStreamEvent("alert:maintenance", map[string]string{"msg": "Cluster upgrade"})
	if sent != 2 {
		t.Errorf("expected 2 clients to receive broadcast, got %d", sent)
	}
}
