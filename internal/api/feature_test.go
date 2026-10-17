package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFeaturesEndpoints(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	// 1. GET /api/features (global catalogue)
	req := httptest.NewRequest(http.MethodGet, "/api/features", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/features, got %d", w.Code)
	}

	var catRes struct {
		Status   string        `json:"status"`
		Features []interface{} `json:"features"`
		Tiers    []string      `json:"tiers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &catRes); err != nil {
		t.Fatalf("failed to decode catalogue: %v", err)
	}
	if len(catRes.Features) == 0 {
		t.Errorf("expected registered features in catalogue")
	}

	// 2. Create a test license
	licRes, err := server.proxy.CreateLicense(context.Background(), 30, 1)
	if err != nil {
		t.Fatalf("failed to create license: %v", err)
	}
	key := licRes.LicenseKey

	// 3. GET /api/features?license_key=KEY
	req = httptest.NewRequest(http.MethodGet, "/api/features?license_key="+key, nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/features?license_key, got %d", w.Code)
	}

	var licFeatRes struct {
		Status     string   `json:"status"`
		LicenseKey string   `json:"license_key"`
		Tier       string   `json:"tier"`
		Features   []string `json:"features"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &licFeatRes); err != nil {
		t.Fatalf("failed to decode license features: %v", err)
	}
	if licFeatRes.Tier != "pro" {
		t.Errorf("expected pro tier default, got %s", licFeatRes.Tier)
	}

	// 4. POST /api/features/check
	checkPayload, _ := json.Marshal(map[string]string{
		"license_key": key,
		"feature":     "analytics",
	})
	checkReq := httptest.NewRequest(http.MethodPost, "/api/features/check", bytes.NewReader(checkPayload))
	checkW := httptest.NewRecorder()
	handler.ServeHTTP(checkW, checkReq)

	if checkW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/features/check, got %d", checkW.Code)
	}
	var checkRes struct {
		Status  string `json:"status"`
		Enabled bool   `json:"enabled"`
		Tier    string `json:"tier"`
	}
	_ = json.Unmarshal(checkW.Body.Bytes(), &checkRes)
	if !checkRes.Enabled {
		t.Errorf("expected analytics feature to be enabled on Pro license")
	}
}

func TestUsageEndpoints(t *testing.T) {
	server, handler := setupTestServer(t, "test-secret", false)
	defer server.proxy.Close()

	key := "KEY-TEST-API-USAGE"

	// 1. POST /api/usage/record
	body, _ := json.Marshal(map[string]interface{}{
		"license_key": key,
		"metric":      "api_calls",
		"units":       50,
		"limit":       100,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/usage/record", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/usage/record, got %d", w.Code)
	}

	var usageRes struct {
		Status   string `json:"status"`
		Exceeded bool   `json:"exceeded"`
		Record   struct {
			Key   string `json:"key"`
			Count int64  `json:"count"`
			Limit int64  `json:"limit"`
		} `json:"record"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &usageRes); err != nil {
		t.Fatalf("failed to decode usage response: %v", err)
	}
	if usageRes.Record.Count != 50 || usageRes.Exceeded {
		t.Errorf("unexpected usage result: count=%d, exceeded=%v", usageRes.Record.Count, usageRes.Exceeded)
	}

	// 2. GET /api/usage/stats?license_key=KEY
	statsReq := httptest.NewRequest(http.MethodGet, "/api/usage/stats?license_key="+key, nil)
	statsW := httptest.NewRecorder()
	handler.ServeHTTP(statsW, statsReq)

	if statsW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/usage/stats, got %d", statsW.Code)
	}
	var statsRes struct {
		Status     string        `json:"status"`
		LicenseKey string        `json:"license_key"`
		Records    []interface{} `json:"records"`
	}
	_ = json.Unmarshal(statsW.Body.Bytes(), &statsRes)
	if len(statsRes.Records) != 1 {
		t.Errorf("expected 1 record in stats, got %d", len(statsRes.Records))
	}
}
