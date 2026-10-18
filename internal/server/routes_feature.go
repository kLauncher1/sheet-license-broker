package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/feature"
)

// handleFeatures returns either all registered feature definitions or entitlements for a specific key.
func (s *AppServer) handleFeatures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := strings.TrimSpace(r.URL.Query().Get("license_key"))
	if key != "" {
		tier, feats := s.proxy.GetEffectiveFeatures(key)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":      "success",
			"license_key": strings.ToUpper(key),
			"tier":        tier,
			"features":    feats,
		})
		return
	}

	mgr := s.proxy.FeatureManager()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"features": mgr.ListFeatures(),
		"tiers":    []string{string(feature.TierFree), string(feature.TierPro), string(feature.TierEnterprise)},
	})
}

// handleFeatureCheck performs an atomic entitlement check for a specific license and feature.
func (s *AppServer) handleFeatureCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		Feature    string `json:"feature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	normKey := strings.TrimSpace(req.LicenseKey)
	normFeat := strings.TrimSpace(req.Feature)
	if normKey == "" || normFeat == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key and feature are required"})
		return
	}

	enabled, tier, err := s.proxy.CheckFeature(r.Context(), normKey, normFeat)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"license_key": strings.ToUpper(normKey),
		"feature":     normFeat,
		"enabled":     enabled,
		"tier":        tier,
	})
}

// handleUsageRecord increments usage consumption units for a metric with quota check.
func (s *AppServer) handleUsageRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LicenseKey string `json:"license_key"`
		Metric     string `json:"metric"`
		Period     string `json:"period"`
		Units      int64  `json:"units"`
		Limit      int64  `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	normKey := strings.TrimSpace(req.LicenseKey)
	normMetric := strings.TrimSpace(req.Metric)
	if normKey == "" || normMetric == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key and metric are required"})
		return
	}

	if req.Units <= 0 {
		req.Units = 1
	}

	rec, exceeded, err := s.proxy.RecordUsage(r.Context(), normKey, normMetric, req.Period, req.Units, req.Limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"record":   rec,
		"exceeded": exceeded,
	})
}

// handleUsageStats returns all usage metric consumption records for a key.
func (s *AppServer) handleUsageStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := strings.TrimSpace(r.URL.Query().Get("license_key"))
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license_key is required"})
		return
	}

	records, err := s.proxy.GetUsage(r.Context(), key)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"license_key": strings.ToUpper(key),
		"records":     records,
	})
}

// registerFeatureRoutes wires feature flag and usage metering endpoints onto the api router.
func (s *AppServer) registerFeatureRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/features", s.handleFeatures)
	apiMux.HandleFunc("/api/features/check", s.handleFeatureCheck)
	apiMux.HandleFunc("/api/usage/record", s.handleUsageRecord)
	apiMux.HandleFunc("/api/usage/stats", s.handleUsageStats)
}
