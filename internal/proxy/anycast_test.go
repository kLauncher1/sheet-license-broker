package proxy_test

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anycast"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
)

func TestProxyAnycastIntegration(t *testing.T) {
	p, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:   true,
		GlobalSecret:  "test-secret-anycast-key",
		ClusterRegion: "us-east",
	})
	if err != nil {
		t.Fatalf("Failed to initialize proxy: %v", err)
	}

	// 1. Check Anycast subsystems are initialized
	if p.AnycastRouter() == nil {
		t.Fatal("Expected AnycastRouter to be non-nil")
	}
	if p.AnycastCache() == nil {
		t.Fatal("Expected AnycastCache to be non-nil")
	}
	if p.PartitionMitigator() == nil {
		t.Fatal("Expected PartitionMitigator to be non-nil")
	}

	// 2. Nearest POP routing for US East coordinates (NYC: 40.7128, -74.0060)
	decision, err := p.RouteNearestPOP(40.7128, -74.0060, "198.51.100.1", "")
	if err != nil {
		t.Fatalf("RouteNearestPOP failed: %v", err)
	}
	if decision.SelectedPOP.ID != "iad" {
		t.Errorf("Expected nearest POP to be 'iad', got '%s'", decision.SelectedPOP.ID)
	}
	if decision.SignedRoutingToken == "" {
		t.Error("Expected non-empty SignedRoutingToken")
	}

	// 3. Verify routing token
	claims, err := p.VerifyRoutingToken(decision.SignedRoutingToken)
	if err != nil {
		t.Fatalf("VerifyRoutingToken failed: %v", err)
	}
	if claims.POPID != "iad" {
		t.Errorf("Expected claims POPID 'iad', got '%s'", claims.POPID)
	}

	// 4. Create a test license
	lic, err := p.CreateLicense(context.Background(), 30, 2)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// 5. Test FastVerifyLicense (First call: full verify + cache warm-up)
	res1, err := p.FastVerifyLicense(context.Background(), lic.LicenseKey, "HWID-ANYCAST-TEST-01")
	if err != nil {
		t.Fatalf("FastVerifyLicense 1 failed: %v", err)
	}
	if !res1.Valid {
		t.Errorf("Expected valid license result, got invalid: %s", res1.Message)
	}

	// 6. Test FastVerifyLicense (Second call: sub-millisecond L1 cache hit)
	res2, err := p.FastVerifyLicense(context.Background(), lic.LicenseKey, "HWID-ANYCAST-TEST-01")
	if err != nil {
		t.Fatalf("FastVerifyLicense 2 failed: %v", err)
	}
	if !res2.Valid {
		t.Errorf("Expected valid cached license result, got invalid: %s", res2.Message)
	}

	// Verify L1 cache stats
	stats := p.AnycastCache().Stats()
	if stats.Hits < 1 {
		t.Errorf("Expected at least 1 cache hit, got %d", stats.Hits)
	}

	// 7. Test Partition Mitigation: simulate cloud partition
	p.PartitionMitigator().SetPartitioned("us-east", true)
	defer p.PartitionMitigator().SetPartitioned("us-east", false)

	// In partitioned state, FastVerifyLicense should grant emergency offline lease
	resPartition, err := p.FastVerifyLicense(context.Background(), "NEW-UNSEEN-KEY", "HWID-PARTITIONED-DEVICE")
	if err != nil {
		t.Fatalf("FastVerifyLicense under partition failed: %v", err)
	}
	if !resPartition.Valid {
		t.Errorf("Expected emergency mitigation lease to be valid, got invalid: %s", resPartition.Message)
	}

	// 8. Test Probe Ingestion
	p.IngestAnycastProbe(anycast.TelemetryProbe{
		SourceRegion: "us-east",
		SourceIP:     "198.51.100.5",
		TargetPOPID:  "iad",
		RTTLatencyMS: 8.5,
		PacketLoss:   0.0,
		Timestamp:    time.Now().UTC(),
	})

	// 9. Status map check
	status := p.GetAnycastStatus()
	if status["pop_count"].(int) < 6 {
		t.Errorf("Expected at least 6 POPs, got %v", status["pop_count"])
	}
	if status["edge_routing_enabled"] != true {
		t.Error("Expected edge_routing_enabled to be true")
	}
}
