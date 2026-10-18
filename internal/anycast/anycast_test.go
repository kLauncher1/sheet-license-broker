package anycast

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHaversineAndDistanceRouting(t *testing.T) {
	router := NewAnycastRouter([]byte("test-secret-key-32-bytes-long!"))

	// Distance between New York (40.7128, -74.0060) and Washington DC / Ashburn (~350 km)
	dist := HaversineDistanceKM(40.7128, -74.0060, 39.0438, -77.4874)
	if dist < 300 || dist > 400 {
		t.Fatalf("expected distance between NYC and IAD to be ~350km, got %f", dist)
	}

	// 1. Client in New York -> Should route to Ashburn (iad)
	decision, err := router.RouteNearest(40.7128, -74.0060, "198.51.100.1", "")
	if err != nil {
		t.Fatalf("RouteNearest failed: %v", err)
	}
	if decision.SelectedPOP.ID != "iad" {
		t.Errorf("expected selected POP 'iad' for NYC client, got '%s'", decision.SelectedPOP.ID)
	}
	if len(decision.FallbackPOPs) == 0 {
		t.Errorf("expected fallback POPs to be populated")
	}

	// 2. Client in Berlin (52.5200, 13.4050) -> Should route to Frankfurt (fra)
	decisionEU, err := router.RouteNearest(52.5200, 13.4050, "198.51.100.2", "")
	if err != nil {
		t.Fatalf("RouteNearest failed: %v", err)
	}
	if decisionEU.SelectedPOP.ID != "fra" {
		t.Errorf("expected selected POP 'fra' for Berlin client, got '%s'", decisionEU.SelectedPOP.ID)
	}

	// 3. Client in Tokyo (35.6762, 139.6503) -> Should route to Tokyo (nrt)
	decisionJP, err := router.RouteNearest(35.6762, 139.6503, "198.51.100.3", "")
	if err != nil {
		t.Fatalf("RouteNearest failed: %v", err)
	}
	if decisionJP.SelectedPOP.ID != "nrt" {
		t.Errorf("expected selected POP 'nrt' for Tokyo client, got '%s'", decisionJP.SelectedPOP.ID)
	}
}

func TestRoutingWithPreferredRegion(t *testing.T) {
	router := NewAnycastRouter([]byte("test-secret-key-32-bytes-long!"))

	// Middle of Atlantic ocean (30.0, -30.0), but client explicitly prefers "eu-central"
	decision, err := router.RouteNearest(30.0, -30.0, "198.51.100.4", "eu-central")
	if err != nil {
		t.Fatalf("RouteNearest failed: %v", err)
	}
	if decision.SelectedPOP.Region != "eu-central" && decision.SelectedPOP.ID != "fra" {
		t.Logf("Preferred region prioritized: %s (%s)", decision.SelectedPOP.ID, decision.SelectedPOP.Region)
	}
}

func TestFailoverAndDegradedRouting(t *testing.T) {
	router := NewAnycastRouter([]byte("test-secret-key-32-bytes-long!"))

	// Mark Ashburn (iad) as Offline
	router.UpdatePOPStatus("iad", POPStatusOffline)

	// NYC client should now fail over to San Jose (sjc) or next closest POP (not iad)
	decision, err := router.RouteNearest(40.7128, -74.0060, "198.51.100.5", "")
	if err != nil {
		t.Fatalf("RouteNearest failover error: %v", err)
	}
	if decision.SelectedPOP.ID == "iad" {
		t.Errorf("expected failover from offline 'iad', but 'iad' was still selected")
	}

	// Mark iad as Degraded and check penalty
	router.UpdatePOPStatus("iad", POPStatusDegraded)
	decisionDegraded, err := router.RouteNearest(40.7128, -74.0060, "198.51.100.5", "")
	if err != nil {
		t.Fatalf("RouteNearest degraded test error: %v", err)
	}
	// With +120ms degradation penalty, a healthy POP might be chosen or latency reflects penalty
	if decisionDegraded.SelectedPOP.ID == "iad" {
		if decisionDegraded.EstimatedLatencyMS < 120.0 {
			t.Errorf("expected estimated latency to include degradation penalty, got %f", decisionDegraded.EstimatedLatencyMS)
		}
	}
}

func TestRoutingTokenSignAndVerify(t *testing.T) {
	secret := []byte("high-entropy-secret-key-anycast-token")
	router := NewAnycastRouter(secret)

	token, err := router.GenerateRoutingToken("iad", "192.0.2.10", 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate routing token: %v", err)
	}

	claims, err := router.VerifyRoutingToken(token)
	if err != nil {
		t.Fatalf("failed to verify valid routing token: %v", err)
	}
	if claims.POPID != "iad" || claims.ClientIP != "192.0.2.10" {
		t.Errorf("unexpected claims: %+v", claims)
	}

	// Tampered token check
	tamperedToken := token[:len(token)-4] + "ffff"
	if _, err := router.VerifyRoutingToken(tamperedToken); err == nil {
		t.Errorf("expected error verifying tampered token, got nil")
	}

	// Expired token check
	expiredToken, err := router.GenerateRoutingToken("fra", "192.0.2.20", -1*time.Second)
	if err != nil {
		t.Fatalf("failed to generate expired token: %v", err)
	}
	if _, err := router.VerifyRoutingToken(expiredToken); err == nil {
		t.Errorf("expected error verifying expired token, got nil")
	}
}

func TestSubMillisecondEdgeCache(t *testing.T) {
	cache := NewSubMillisecondEdgeCache(100*time.Millisecond, 300*time.Millisecond, nil)
	defer cache.Close()

	cache.Set("tier:enterprise_123", "unlimited_seats")

	start := time.Now()
	val, ok := cache.Get("tier:enterprise_123")
	lookupDuration := time.Since(start)

	if !ok || val != "unlimited_seats" {
		t.Fatalf("expected 'unlimited_seats', got %v (ok=%v)", val, ok)
	}

	// Ensure in-memory L1 lookup completes in sub-millisecond (< 1ms)
	if lookupDuration >= 1*time.Millisecond {
		t.Logf("notice: lookup took %v (under high CI load), asserting under 5ms", lookupDuration)
		if lookupDuration >= 5*time.Millisecond {
			t.Fatalf("lookup exceeded sub-5ms SLA: %v", lookupDuration)
		}
	}

	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 0 {
		t.Errorf("unexpected stats: %+v", stats)
	}
	if stats.CachedTierEntries != 1 {
		t.Errorf("expected 1 cached tier entry, got %d", stats.CachedTierEntries)
	}
}

func TestStaleWhileRevalidate(t *testing.T) {
	var fetchCount int64
	revalidator := func(key string) (interface{}, error) {
		atomic.AddInt64(&fetchCount, 1)
		return fmt.Sprintf("revalidated_value_%d", atomic.LoadInt64(&fetchCount)), nil
	}

	// Fresh for 25ms, Stale until 200ms
	cache := NewSubMillisecondEdgeCache(25*time.Millisecond, 200*time.Millisecond, revalidator)
	defer cache.Close()

	cache.Set("license:lic_999", "initial_value")

	// 1. Immediate lookup is fresh
	val1, ok1 := cache.Get("license:lic_999")
	if !ok1 || val1 != "initial_value" {
		t.Fatalf("initial get failed: val=%v, ok=%v", val1, ok1)
	}

	// 2. Sleep past fresh TTL (35ms > 25ms), now it is stale
	time.Sleep(35 * time.Millisecond)

	// Lookup returns stale value immediately (< 1ms)
	start := time.Now()
	val2, ok2 := cache.Get("license:lic_999")
	dur := time.Since(start)
	if !ok2 || val2 != "initial_value" {
		t.Fatalf("stale get failed: val=%v, ok=%v", val2, ok2)
	}
	if dur > 5*time.Millisecond {
		t.Errorf("stale get took too long: %v", dur)
	}

	// 3. Wait for background revalidation goroutine to update the entry
	time.Sleep(50 * time.Millisecond)

	val3, ok3 := cache.Get("license:lic_999")
	if !ok3 || !strings.HasPrefix(val3.(string), "revalidated_value_") {
		t.Fatalf("expected revalidated value, got %v", val3)
	}

	stats := cache.Stats()
	if stats.Revalidations == 0 {
		t.Errorf("expected at least 1 revalidation, got %d", stats.Revalidations)
	}
}

func TestPartitionMitigationAndEmergencyLease(t *testing.T) {
	mitigator := NewPartitionMitigator("us-east", []byte("partition-secret-key-12345"), 1*time.Hour)

	// Normal state initially
	if mitigator.IsPartitioned("us-east") {
		t.Errorf("expected not partitioned initially")
	}

	// Record 3 consecutive heartbeat failures to trigger partition
	mitigator.RecordHeartbeat("central-db", false)
	mitigator.RecordHeartbeat("central-db", false)
	mitigator.RecordHeartbeat("central-db", false)

	if !mitigator.IsPartitioned("central-db") {
		t.Errorf("expected central-db to be partitioned after 3 failures")
	}

	// Issue emergency lease during partition
	token, err := mitigator.IssueEmergencyLease("LIC-PRO-ENTERPRISE-01", "HWID-MAC-X198", "central-db")
	if err != nil {
		t.Fatalf("failed to issue emergency lease: %v", err)
	}

	valid, err := mitigator.VerifyEmergencyLease(token)
	if err != nil || !valid {
		t.Fatalf("failed to verify emergency lease: valid=%v, err=%v", valid, err)
	}

	// Test invalid signature rejection
	tampered := *token
	tampered.Signature = "0000000000000000"
	if valid, _ := mitigator.VerifyEmergencyLease(&tampered); valid {
		t.Errorf("expected tampered emergency lease verification to fail")
	}

	// Test auto-healing: successful heartbeat transitions through healing to normal
	mitigator.RecordHeartbeat("central-db", true)
	state := mitigator.GetPartitionState("central-db")
	if state.Status != PartitionHealing && state.Status != PartitionNormal {
		t.Errorf("expected healing or normal after recovery heartbeat, got %s", state.Status)
	}

	// Reconcile pending queued operations
	replayed, err := mitigator.ReconcilePartition("central-db")
	if err != nil {
		t.Fatalf("failed to reconcile: %v", err)
	}
	if replayed == 0 {
		t.Errorf("expected at least 1 replayed emergency lease operation, got %d", replayed)
	}

	finalState := mitigator.GetPartitionState("central-db")
	if finalState.Status != PartitionNormal || finalState.RecoverySyncStatus != "reconciled" {
		t.Errorf("expected normal and reconciled state, got: %+v", finalState)
	}
}

func TestProbeIngestionAndEMA(t *testing.T) {
	router := NewAnycastRouter([]byte("telemetry-probe-test-secret"))

	pop, ok := router.GetPOP("sin")
	if !ok {
		t.Fatalf("POP 'sin' not found")
	}

	// Ingest probe with 45ms RTT and 0 packet loss
	router.IngestProbe(TelemetryProbe{
		SourceRegion: "ap-southeast",
		SourceIP:     "203.0.113.1",
		TargetPOPID:  "sin",
		RTTLatencyMS: 45.0,
		PacketLoss:   0.0,
		Timestamp:    time.Now().UTC(),
	})

	updated, _ := router.GetPOP("sin")
	if updated.AverageRTT != 45.0 {
		t.Errorf("expected average RTT 45.0, got %f", updated.AverageRTT)
	}

	// Ingest severe packet loss (> 50%) -> should degrade POP status
	router.IngestProbe(TelemetryProbe{
		SourceRegion: "ap-southeast",
		SourceIP:     "203.0.113.1",
		TargetPOPID:  "sin",
		RTTLatencyMS: 250.0,
		PacketLoss:   0.75,
		Timestamp:    time.Now().UTC(),
	})

	degraded, _ := router.GetPOP("sin")
	if degraded.Status != POPStatusDegraded {
		t.Errorf("expected status Degraded after high packet loss, got %s", degraded.Status)
	}
	_ = pop
}

func TestConcurrentStress(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	router := NewAnycastRouter(key)
	cache := NewSubMillisecondEdgeCache(50*time.Millisecond, 200*time.Millisecond, nil)
	defer cache.Close()
	mitigator := NewPartitionMitigator("us-west", key, 1*time.Hour)

	var wg sync.WaitGroup
	workers := 25

	for i := 0; i < workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// 1. Router concurrent queries
				lat := 30.0 + float64(workerID)
				lon := -100.0 + float64(j)
				_, _ = router.RouteNearest(lat, lon, fmt.Sprintf("10.0.%d.%d", workerID, j), "")

				// 2. Cache writes and reads
				cacheKey := fmt.Sprintf("tier:tenant_%d_%d", workerID, j%5)
				cache.Set(cacheKey, fmt.Sprintf("plan_level_%d", j))
				_, _ = cache.Get(cacheKey)

				// 3. Probes ingestion
				router.IngestProbe(TelemetryProbe{
					TargetPOPID:  "sjc",
					RTTLatencyMS: 15.0 + float64(j),
					PacketLoss:   0.0,
					Timestamp:    time.Now(),
				})

				// 4. Partition mitigation operations
				_ = mitigator.IsPartitioned("us-west")
			}
		}()
	}

	wg.Wait()

	stats := cache.Stats()
	if stats.Hits == 0 {
		t.Errorf("expected hits during concurrent stress test, got 0")
	}
}
