package failover

import (
	"sync"
	"testing"
	"time"
)

func TestMultiCloudManager_Initialization(t *testing.T) {
	mgr := NewMultiCloudManager([]byte("test-multicloud-secret-key-32b"))
	status := mgr.GetStatus()

	if status.TotalProviders != 3 {
		t.Fatalf("expected 3 providers, got %d", status.TotalProviders)
	}
	if status.ActiveProviderCount != 3 {
		t.Fatalf("expected 3 active providers, got %d", status.ActiveProviderCount)
	}
	if !status.ActiveActiveEnabled {
		t.Fatalf("expected active-active enabled")
	}

	providers := mgr.ListProviders()
	var totalWeight float64
	for _, p := range providers {
		totalWeight += p.Weight
		if p.Status != ProviderStatusHealthy {
			t.Errorf("provider %s status = %s, expected healthy", p.ID, p.Status)
		}
	}
	if totalWeight < 0.99 || totalWeight > 1.01 {
		t.Errorf("expected total weight ~1.0, got %f", totalWeight)
	}
}

func TestMultiCloudManager_ActiveActiveRoutingAndTokens(t *testing.T) {
	mgr := NewMultiCloudManager([]byte("test-multicloud-secret-key-32b"))

	provider, token, err := mgr.RouteRequest("us-east", "198.51.100.42")
	if err != nil {
		t.Fatalf("unexpected routing error: %v", err)
	}
	if provider == nil || token == nil {
		t.Fatalf("expected non-nil provider and token")
	}
	if token.ProviderID != provider.ID {
		t.Errorf("token provider %s != selected provider %s", token.ProviderID, provider.ID)
	}

	// Verify valid token
	if err := mgr.VerifyToken(*token); err != nil {
		t.Fatalf("expected token to be valid: %v", err)
	}

	// Tampered signature should fail
	tampered := *token
	tampered.Signature = "00112233445566778899aabbccddeeff"
	if err := mgr.VerifyToken(tampered); err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}

	// Expired token should fail
	expired := *token
	expired.ExpiresAt = time.Now().UTC().Add(-10 * time.Minute).Unix()
	if err := mgr.VerifyToken(expired); err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestMultiCloudManager_SubSecondFailover(t *testing.T) {
	mgr := NewMultiCloudManager([]byte("test-multicloud-secret-key-32b"))

	var failoverCaptured *FailoverEvent
	mgr.SetFailoverListener(func(event FailoverEvent) {
		failoverCaptured = &event
	})

	now := time.Now().UTC()

	// 2 failures: status becomes degraded
	for i := 0; i < 2; i++ {
		ev, err := mgr.RecordProbe(HealthProbeResult{
			ProviderID:   "cloudflare",
			Timestamp:    now.Add(time.Duration(i) * time.Second),
			Success:      false,
			LatencyMS:    450.0,
			StatusCode:   504,
			ErrorMessage: "Gateway Timeout",
		})
		if err != nil {
			t.Fatalf("probe error: %v", err)
		}
		if ev != nil {
			t.Fatalf("did not expect failover event at failure %d", i+1)
		}
	}

	// 3rd failure trips the circuit to open and triggers failover
	ev, err := mgr.RecordProbe(HealthProbeResult{
		ProviderID:   "cloudflare",
		Timestamp:    now.Add(3 * time.Second),
		Success:      false,
		LatencyMS:    500.0,
		StatusCode:   502,
		ErrorMessage: "Bad Gateway",
	})
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if ev == nil {
		t.Fatalf("expected failover event on 3rd failure")
	}
	if ev.PreviousProvider != "cloudflare" {
		t.Errorf("expected previous provider cloudflare, got %s", ev.PreviousProvider)
	}
	if ev.NewProvider == "cloudflare" || ev.NewProvider == "" {
		t.Errorf("expected new alternative provider, got %s", ev.NewProvider)
	}

	if failoverCaptured == nil {
		t.Fatalf("expected listener to capture failover event")
	}

	// Verify subsequent routing automatically bypasses Cloudflare
	for i := 0; i < 5; i++ {
		p, _, err := mgr.RouteRequest("global", "203.0.113.1")
		if err != nil {
			t.Fatalf("routing error after failover: %v", err)
		}
		if p.ID == "cloudflare" {
			t.Fatalf("expected Cloudflare to be bypassed, but got routed to Cloudflare")
		}
	}
}

func TestMultiCloudManager_CircuitRecovery(t *testing.T) {
	mgr := NewMultiCloudManager([]byte("test-multicloud-secret-key-32b"))
	now := time.Now().UTC()

	// Trip CloudFront
	for i := 0; i < 3; i++ {
		_, _ = mgr.RecordProbe(HealthProbeResult{
			ProviderID: "cloudfront",
			Timestamp:  now.Add(time.Duration(i) * time.Second),
			Success:    false,
			LatencyMS:  600.0,
			StatusCode: 500,
		})
	}

	cf, ok := mgr.prober.GetProvider("cloudfront")
	if !ok || cf.CircuitState != CircuitOpen {
		t.Fatalf("expected cloudfront circuit open, got %s", cf.CircuitState)
	}

	// Probe success moves to HalfOpen
	_, _ = mgr.RecordProbe(HealthProbeResult{
		ProviderID: "cloudfront",
		Timestamp:  now.Add(4 * time.Second),
		Success:    true,
		LatencyMS:  25.0,
		StatusCode: 200,
	})
	cf, _ = mgr.prober.GetProvider("cloudfront")
	if cf.CircuitState != CircuitHalfOpen {
		t.Fatalf("expected half-open, got %s", cf.CircuitState)
	}

	// 2nd probe success restores to Closed
	_, _ = mgr.RecordProbe(HealthProbeResult{
		ProviderID: "cloudfront",
		Timestamp:  now.Add(5 * time.Second),
		Success:    true,
		LatencyMS:  22.0,
		StatusCode: 200,
	})
	cf, _ = mgr.prober.GetProvider("cloudfront")
	if cf.CircuitState != CircuitClosed || cf.Status != ProviderStatusHealthy {
		t.Fatalf("expected closed and healthy, got circuit=%s status=%s", cf.CircuitState, cf.Status)
	}
}

func TestMultiCloudManager_ZeroPacketLossSync(t *testing.T) {
	mgr := NewMultiCloudManager([]byte("test-multicloud-secret-key-32b"))

	payload := []byte(`{"license_key":"KEY-ALPHA-1234","hwid":"HWID-99","action":"verify"}`)
	delta1, err := mgr.SubmitDelta("cloudflare", "license_verify", payload)
	if err != nil {
		t.Fatalf("failed to record delta: %v", err)
	}
	if delta1.SequenceNumber != 1 {
		t.Errorf("expected sequence 1, got %d", delta1.SequenceNumber)
	}

	// Idempotency check: duplicate payload returns existing delta
	deltaDup, err := mgr.SubmitDelta("cloudflare", "license_verify", payload)
	if err != nil {
		t.Fatalf("unexpected error on dup payload: %v", err)
	}
	if deltaDup.DeltaID != delta1.DeltaID {
		t.Errorf("expected same delta ID for duplicate payload, got %s vs %s", deltaDup.DeltaID, delta1.DeltaID)
	}

	// Check pending deltas for peer "cloudfront"
	pendingCF := mgr.GetPendingSync("cloudfront", 10)
	if len(pendingCF) != 1 {
		t.Fatalf("expected 1 pending delta for cloudfront, got %d", len(pendingCF))
	}
	if pendingCF[0].DeltaID != delta1.DeltaID {
		t.Errorf("mismatched delta in queue: %s", pendingCF[0].DeltaID)
	}

	// Create sync voucher and acknowledge
	voucher, err := mgr.CreateVoucher(delta1.DeltaID, delta1.SequenceNumber, "cloudflare", "cloudfront")
	if err != nil {
		t.Fatalf("failed to create voucher: %v", err)
	}
	if voucher.Signature == "" {
		t.Fatalf("expected voucher signature")
	}

	if err := mgr.AcknowledgeSync("cloudfront", delta1.DeltaID, voucher); err != nil {
		t.Fatalf("failed to acknowledge sync: %v", err)
	}

	// Verify pending queue for cloudfront is now empty
	pendingAfter := mgr.GetPendingSync("cloudfront", 10)
	if len(pendingAfter) != 0 {
		t.Errorf("expected empty pending queue for cloudfront after ack, got %d", len(pendingAfter))
	}
}

func TestMultiCloudManager_SimulateOutage(t *testing.T) {
	mgr := NewMultiCloudManager([]byte("test-multicloud-secret-key-32b"))

	event, err := mgr.SimulateOutage("fastly", "Planned network partition drill")
	if err != nil {
		t.Fatalf("failed to simulate outage: %v", err)
	}
	if event.PreviousProvider != "fastly" {
		t.Errorf("expected previous provider fastly, got %s", event.PreviousProvider)
	}

	fastly, ok := mgr.prober.GetProvider("fastly")
	if !ok || fastly.Status != ProviderStatusOffline || fastly.CircuitState != CircuitOpen {
		t.Errorf("expected fastly to be offline and open, got status=%s circuit=%s", fastly.Status, fastly.CircuitState)
	}
}

func TestMultiCloudManager_ConcurrentSafety(t *testing.T) {
	mgr := NewMultiCloudManager([]byte("test-multicloud-secret-key-32b"))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _, _ = mgr.RouteRequest("us-east", "10.0.0.1")
			_, _ = mgr.RecordProbe(HealthProbeResult{
				ProviderID: "cloudflare",
				Timestamp:  time.Now().UTC(),
				Success:    true,
				LatencyMS:  30.0 + float64(idx),
				StatusCode: 200,
			})
			payload := []byte(string(rune('A'+idx)) + "-test-delta-content")
			_, _ = mgr.SubmitDelta("fastly", "test_action", payload)
		}(i)
	}
	wg.Wait()

	status := mgr.GetStatus()
	if status.TotalProviders != 3 {
		t.Errorf("expected 3 providers in status, got %d", status.TotalProviders)
	}
}
