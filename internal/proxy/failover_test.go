package proxy

import (
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/failover"
)

func TestProxy_FailoverInitAndStatus(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	if px.MultiCloudManager() == nil {
		t.Fatalf("expected multicloud manager to be initialized")
	}

	status := px.GetMultiCloudStatus()
	if status.TotalProviders != 3 {
		t.Fatalf("expected 3 providers, got %d", status.TotalProviders)
	}
	if !status.ActiveActiveEnabled {
		t.Fatalf("expected active-active enabled")
	}
}

func TestProxy_FailoverRoutingAndDeltaSync(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	// 1. Multi-cloud routing test
	provider, token, err := px.RouteMultiCloud("eu-central", "195.201.0.1")
	if err != nil {
		t.Fatalf("routing error: %v", err)
	}
	if provider == nil || token == nil {
		t.Fatalf("expected provider and token")
	}
	if token.ProviderID != provider.ID {
		t.Errorf("token provider %s != %s", token.ProviderID, provider.ID)
	}

	// 2. Multi-cloud delta sync test
	payload := []byte(`{"action":"license_revoke","key":"LIC-REVOKE-001"}`)
	delta, err := px.SyncMultiCloudDelta("cloudflare", "license_revoke", payload)
	if err != nil {
		t.Fatalf("failed to sync delta: %v", err)
	}
	if delta == nil || delta.SequenceNumber != 1 {
		t.Fatalf("expected delta sequence 1, got %v", delta)
	}

	// 3. Pending sync queue inspection
	pending := px.GetMultiCloudPendingSync("fastly", 10)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending delta for fastly, got %d", len(pending))
	}

	// 4. Acknowledge sync
	voucher, err := px.MultiCloudManager().CreateVoucher(delta.DeltaID, delta.SequenceNumber, "cloudflare", "fastly")
	if err != nil {
		t.Fatalf("failed to create voucher: %v", err)
	}
	if err := px.AcknowledgeMultiCloudSync("fastly", delta.DeltaID, voucher); err != nil {
		t.Fatalf("failed to acknowledge sync: %v", err)
	}

	if len(px.GetMultiCloudPendingSync("fastly", 10)) != 0 {
		t.Errorf("expected pending queue for fastly to be empty after ack")
	}

	// 5. Probe recording and outage simulation
	ev, err := px.RecordMultiCloudProbe(failover.HealthProbeResult{
		ProviderID: "cloudfront",
		Timestamp:  time.Now().UTC(),
		Success:    true,
		LatencyMS:  35.0,
		StatusCode: 200,
	})
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}
	if ev != nil {
		t.Fatalf("did not expect failover event on healthy probe")
	}

	simEv, err := px.SimulateMultiCloudOutage("cloudflare", "Simulated edge data center maintenance")
	if err != nil {
		t.Fatalf("failed to simulate outage: %v", err)
	}
	if simEv == nil || simEv.PreviousProvider != "cloudflare" {
		t.Fatalf("expected simulated failover event for cloudflare, got %v", simEv)
	}
}
