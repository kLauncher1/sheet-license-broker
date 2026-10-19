package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anycast"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func TestAnycastRoutes(t *testing.T) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:   true,
		GlobalSecret:  "test-anycast-secret",
		ClusterRegion: "us-east",
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	ctx := context.Background()
	lic, err := px.CreateLicense(ctx, 30, 2)
	if err != nil {
		t.Fatalf("failed to seed license: %v", err)
	}

	guard := security.NewGuard([]byte(""), 5*time.Minute, false)
	server := &AppServer{proxy: px, guard: guard}

	apiMux := http.NewServeMux()
	server.registerAnycastRoutes(apiMux)

	// 1. GET /api/anycast/status
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/anycast/status", nil)
	wStatus := httptest.NewRecorder()
	apiMux.ServeHTTP(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 from status, got %d", wStatus.Code)
	}
	var statusMap map[string]interface{}
	if err := json.NewDecoder(wStatus.Body).Decode(&statusMap); err != nil {
		t.Fatalf("failed to parse status json: %v", err)
	}
	if statusMap["pop_count"].(float64) < 6 {
		t.Errorf("expected at least 6 POPs, got %v", statusMap["pop_count"])
	}

	// 2. GET /api/anycast/route (Coordinates query: Tokyo 35.6762, 139.6503)
	reqRoute := httptest.NewRequest(http.MethodGet, "/api/anycast/route?lat=35.6762&lon=139.6503", nil)
	wRoute := httptest.NewRecorder()
	apiMux.ServeHTTP(wRoute, reqRoute)
	if wRoute.Code != http.StatusOK {
		t.Fatalf("expected 200 from route, got %d", wRoute.Code)
	}
	var decision anycast.RoutingDecision
	if err := json.NewDecoder(wRoute.Body).Decode(&decision); err != nil {
		t.Fatalf("failed to decode routing decision: %v", err)
	}
	if decision.SelectedPOP.ID != "nrt" {
		t.Errorf("expected selected POP 'nrt' for Tokyo coordinates, got '%s'", decision.SelectedPOP.ID)
	}
	if wRoute.Header().Get("X-Edge-POP") != "nrt" {
		t.Errorf("expected X-Edge-POP 'nrt', got '%s'", wRoute.Header().Get("X-Edge-POP"))
	}
	if decision.SignedRoutingToken == "" {
		t.Error("expected signed routing token")
	}

	// 2b. GET /api/anycast/route (Country header fallback: DE -> FRA)
	reqCountry := httptest.NewRequest(http.MethodGet, "/api/anycast/route", nil)
	reqCountry.Header.Set("CF-IPCountry", "DE")
	wCountry := httptest.NewRecorder()
	apiMux.ServeHTTP(wCountry, reqCountry)
	if wCountry.Code != http.StatusOK {
		t.Fatalf("expected 200 from country route, got %d", wCountry.Code)
	}
	var countryDecision anycast.RoutingDecision
	json.NewDecoder(wCountry.Body).Decode(&countryDecision)
	if countryDecision.SelectedPOP.ID != "fra" {
		t.Errorf("expected selected POP 'fra' for Germany centroid, got '%s'", countryDecision.SelectedPOP.ID)
	}

	// 3. POST /api/anycast/probe
	probeBody, _ := json.Marshal(map[string]interface{}{
		"source_region": "us-east",
		"source_ip":     "198.51.100.10",
		"target_pop_id": "iad",
		"rtt_latency_ms": 12.4,
		"packet_loss":   0.0,
		"jitter_ms":     1.2,
	})
	reqProbe := httptest.NewRequest(http.MethodPost, "/api/anycast/probe", bytes.NewReader(probeBody))
	wProbe := httptest.NewRecorder()
	apiMux.ServeHTTP(wProbe, reqProbe)
	if wProbe.Code != http.StatusOK {
		t.Fatalf("expected 200 from probe, got %d", wProbe.Code)
	}

	// 4. GET /api/anycast/pops
	reqPOPs := httptest.NewRequest(http.MethodGet, "/api/anycast/pops", nil)
	wPOPs := httptest.NewRecorder()
	apiMux.ServeHTTP(wPOPs, reqPOPs)
	if wPOPs.Code != http.StatusOK {
		t.Fatalf("expected 200 from get pops, got %d", wPOPs.Code)
	}

	// 4b. POST /api/anycast/pops (Register custom edge POP)
	newPOP := anycast.POP{
		ID:          "lhr",
		Name:        "London LHR",
		Region:      "eu-west",
		Country:     "GB",
		Latitude:    51.5074,
		Longitude:   -0.1278,
		EndpointURL: "https://lhr.edge.sheet-broker.internal",
		Weight:      1.0,
		Status:      anycast.POPStatusHealthy,
	}
	newPOPBytes, _ := json.Marshal(newPOP)
	reqNewPOP := httptest.NewRequest(http.MethodPost, "/api/anycast/pops", bytes.NewReader(newPOPBytes))
	wNewPOP := httptest.NewRecorder()
	apiMux.ServeHTTP(wNewPOP, reqNewPOP)
	if wNewPOP.Code != http.StatusOK {
		t.Fatalf("expected 200 from post pop, got %d: %s", wNewPOP.Code, wNewPOP.Body.String())
	}

	// 5. GET /api/anycast/cache/stats
	reqCache := httptest.NewRequest(http.MethodGet, "/api/anycast/cache/stats", nil)
	wCache := httptest.NewRecorder()
	apiMux.ServeHTTP(wCache, reqCache)
	if wCache.Code != http.StatusOK {
		t.Fatalf("expected 200 from cache stats, got %d", wCache.Code)
	}

	// 6. POST /api/anycast/verify (Fast verification fast-path)
	verifyBody, _ := json.Marshal(map[string]string{
		"license_key": lic.LicenseKey,
		"hwid":       "HWID-TEST-ANYCAST-CLIENT",
	})
	reqVerify := httptest.NewRequest(http.MethodPost, "/api/anycast/verify", bytes.NewReader(verifyBody))
	wVerify := httptest.NewRecorder()
	apiMux.ServeHTTP(wVerify, reqVerify)
	if wVerify.Code != http.StatusOK {
		t.Fatalf("expected 200 from fast verify, got %d: %s", wVerify.Code, wVerify.Body.String())
	}
	if wVerify.Header().Get("X-Lookup-Latency-US") == "" {
		t.Error("expected X-Lookup-Latency-US header")
	}

	// 7. POST /api/anycast/partition/simulate (Simulate cloud partition)
	simBody, _ := json.Marshal(map[string]interface{}{
		"region":      "us-east",
		"partitioned": true,
	})
	reqSim := httptest.NewRequest(http.MethodPost, "/api/anycast/partition/simulate", bytes.NewReader(simBody))
	wSim := httptest.NewRecorder()
	apiMux.ServeHTTP(wSim, reqSim)
	if wSim.Code != http.StatusOK {
		t.Fatalf("expected 200 from partition simulate, got %d", wSim.Code)
	}

	// Verify that under partition, emergency lease is returned
	verifyPartBody, _ := json.Marshal(map[string]string{
		"license_key": "UNKNOWN-PARTITION-KEY",
		"hwid":       "HWID-OFFLINE-ISOLATED",
	})
	reqVerifyPart := httptest.NewRequest(http.MethodPost, "/api/anycast/verify", bytes.NewReader(verifyPartBody))
	wVerifyPart := httptest.NewRecorder()
	apiMux.ServeHTTP(wVerifyPart, reqVerifyPart)
	if wVerifyPart.Code != http.StatusOK {
		t.Fatalf("expected 200 for emergency lease under partition, got %d", wVerifyPart.Code)
	}
}
