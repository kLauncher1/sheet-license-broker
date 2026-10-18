package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anycast"
)

func TestGoClientAnycastWorkflow(t *testing.T) {
	mux := http.NewServeMux()

	// 1. /api/anycast/route
	mux.HandleFunc("/api/anycast/route", func(w http.ResponseWriter, r *http.Request) {
		decision := anycast.RoutingDecision{
			SelectedPOP: anycast.POP{
				ID:     "iad",
				Name:   "Ashburn IAD",
				Region: "us-east",
				Status: anycast.POPStatusHealthy,
			},
			EstimatedLatencyMS: 8.5,
			SignedRoutingToken: "mock.routing.token",
			Timestamp:          time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decision)
	})

	// 2. /api/anycast/probe
	mux.HandleFunc("/api/anycast/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "recorded"})
	})

	// 3. /api/anycast/status
	mux.HandleFunc("/api/anycast/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"pop_count":            6,
			"edge_routing_enabled": true,
		})
	})

	// 4. /api/anycast/cache/stats
	mux.HandleFunc("/api/anycast/cache/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := anycast.EdgeCacheStats{
			Hits:            42,
			Misses:          3,
			LookupLatencyUS: 85.0,
			HitRatio:        0.933,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	// 5. /api/anycast/verify
	mux.HandleFunc("/api/anycast/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ValidationResult{
			Valid:   true,
			Tier:    "pro",
			Message: "Fast verify L1 cache hit",
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, nil, 5*time.Second)

	ctx := context.Background()

	// 1. GetAnycastRoute
	route, err := client.GetAnycastRoute(ctx, 39.0438, -77.4874, "US", "us-east")
	if err != nil {
		t.Fatalf("GetAnycastRoute failed: %v", err)
	}
	if route.SelectedPOP.ID != "iad" {
		t.Errorf("expected POP 'iad', got '%s'", route.SelectedPOP.ID)
	}

	// 2. ReportAnycastProbe
	err = client.ReportAnycastProbe(ctx, anycast.TelemetryProbe{
		TargetPOPID:  "iad",
		RTTLatencyMS: 8.5,
	})
	if err != nil {
		t.Fatalf("ReportAnycastProbe failed: %v", err)
	}

	// 3. GetAnycastStatus
	status, err := client.GetAnycastStatus(ctx)
	if err != nil {
		t.Fatalf("GetAnycastStatus failed: %v", err)
	}
	if status["edge_routing_enabled"] != true {
		t.Error("expected edge_routing_enabled true")
	}

	// 4. GetEdgeCacheStats
	cacheStats, err := client.GetEdgeCacheStats(ctx)
	if err != nil {
		t.Fatalf("GetEdgeCacheStats failed: %v", err)
	}
	if cacheStats.Hits != 42 {
		t.Errorf("expected 42 hits, got %d", cacheStats.Hits)
	}

	// 5. FastVerifyLicense
	vRes, err := client.FastVerifyLicense(ctx, "TEST-ANYCAST-LIC", "HWID-TEST-01")
	if err != nil {
		t.Fatalf("FastVerifyLicense failed: %v", err)
	}
	if !vRes.Valid {
		t.Error("expected valid license response")
	}
}
