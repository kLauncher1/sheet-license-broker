package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/failover"
)

func TestGoSDK_FailoverSubsystem(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/multicloud/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(failover.MultiCloudStatus{
			ActiveProviderCount: 3,
			TotalProviders:      3,
			ActiveActiveEnabled: true,
			PrimaryProviderID:   "cloudflare",
			AverageLatencyMS:    31.2,
			UptimeRatio:         100.0,
		})
	})

	mux.HandleFunc("/api/multicloud/providers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": []failover.CloudProvider{
				{ID: "cloudflare", Name: "Cloudflare Anycast", Status: failover.ProviderStatusHealthy, Weight: 0.4},
				{ID: "cloudfront", Name: "AWS CloudFront", Status: failover.ProviderStatusHealthy, Weight: 0.35},
				{ID: "fastly", Name: "Fastly Edge", Status: failover.ProviderStatusHealthy, Weight: 0.25},
			},
			"count": 3,
		})
	})

	mux.HandleFunc("/api/multicloud/route", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": failover.CloudProvider{
				ID:          "cloudflare",
				Name:        "Cloudflare Anycast",
				EndpointURL: "https://cloudflare.edge.sheet-broker.internal",
				Status:      failover.ProviderStatusHealthy,
			},
			"token": failover.MultiCloudRoutingToken{
				TokenID:    "tok-12345",
				ProviderID: "cloudflare",
				Signature:  "sig-mock-hex",
				IssuedAt:   time.Now().Unix(),
				ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
			},
		})
	})

	mux.HandleFunc("/api/multicloud/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"failover_event": &failover.FailoverEvent{
				EventID:          "fo-test-1",
				PreviousProvider: "cloudflare",
				NewProvider:      "cloudfront",
				Reason:           "Simulated latency breach",
			},
		})
	})

	mux.HandleFunc("/api/multicloud/sync/delta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"delta": failover.SyncDelta{
				DeltaID:        "delta-test-1",
				OriginProvider: "cloudflare",
				SequenceNumber: 1,
				Action:         "license_revoke",
			},
		})
	})

	mux.HandleFunc("/api/multicloud/sync/pending", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider_id": "fastly",
			"pending": []failover.SyncDelta{
				{DeltaID: "delta-test-1", SequenceNumber: 1},
			},
			"count": 1,
		})
	})

	mux.HandleFunc("/api/multicloud/sync/acknowledge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	})

	mux.HandleFunc("/api/multicloud/failover/simulate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"failover_event": &failover.FailoverEvent{
				EventID:          "sim-1",
				PreviousProvider: "fastly",
				NewProvider:      "cloudflare",
				Reason:           "Maintenance",
			},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, nil, 5*time.Second)
	ctx := context.Background()

	// 1. Get status
	status, err := client.GetMultiCloudStatus(ctx)
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	if status.TotalProviders != 3 {
		t.Errorf("expected 3 providers, got %d", status.TotalProviders)
	}

	// 2. List providers
	provs, err := client.ListMultiCloudProviders(ctx)
	if err != nil {
		t.Fatalf("failed to list providers: %v", err)
	}
	if len(provs) != 3 {
		t.Errorf("expected 3 providers, got %d", len(provs))
	}

	// 3. Route request
	p, tok, err := client.RouteMultiCloud(ctx, "us-east", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to route: %v", err)
	}
	if p.ID != "cloudflare" || tok.Signature != "sig-mock-hex" {
		t.Errorf("unexpected route response: %v, %v", p, tok)
	}

	// 4. Submit probe
	ev, err := client.SubmitMultiCloudProbe(ctx, failover.HealthProbeResult{
		ProviderID: "cloudflare",
		Success:    true,
		LatencyMS:  25.0,
	})
	if err != nil {
		t.Fatalf("failed to submit probe: %v", err)
	}
	if ev == nil || ev.EventID != "fo-test-1" {
		t.Errorf("unexpected probe event: %v", ev)
	}

	// 5. Submit delta
	delta, err := client.SubmitMultiCloudDelta(ctx, "cloudflare", "license_revoke", []byte(`{"key":"VAL"}`))
	if err != nil {
		t.Fatalf("failed to submit delta: %v", err)
	}
	if delta.DeltaID != "delta-test-1" {
		t.Errorf("unexpected delta ID: %s", delta.DeltaID)
	}

	// 6. Get pending sync
	pending, err := client.GetMultiCloudPendingSync(ctx, "fastly", 10)
	if err != nil {
		t.Fatalf("failed to get pending: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("expected 1 pending delta, got %d", len(pending))
	}

	// 7. Acknowledge sync
	if err := client.AcknowledgeMultiCloudSync(ctx, "fastly", "delta-test-1", nil); err != nil {
		t.Fatalf("failed to ack sync: %v", err)
	}

	// 8. Simulate failover
	simEv, err := client.SimulateMultiCloudFailover(ctx, "fastly", "Maintenance")
	if err != nil {
		t.Fatalf("failed to simulate failover: %v", err)
	}
	if simEv == nil || simEv.PreviousProvider != "fastly" {
		t.Errorf("unexpected simulate event: %v", simEv)
	}
}
