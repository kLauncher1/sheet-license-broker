package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anycast"
)

// registerAnycastRoutes mounts REST endpoints for geo-distributed Anycast edge routing and sub-5ms caching.
func (s *AppServer) registerAnycastRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/anycast/status", s.handleAnycastStatus)
	apiMux.HandleFunc("/api/anycast/route", s.handleAnycastRoute)
	apiMux.HandleFunc("/api/anycast/probe", s.handleAnycastProbe)
	apiMux.HandleFunc("/api/anycast/pops", s.handleAnycastPOPs)
	apiMux.HandleFunc("/api/anycast/cache/stats", s.handleAnycastCacheStats)
	apiMux.HandleFunc("/api/anycast/partition/simulate", s.handleAnycastPartitionSimulate)
	apiMux.HandleFunc("/api/anycast/verify", s.handleAnycastFastVerify)
}

func (s *AppServer) handleAnycastStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetAnycastStatus())
}

// Country centroid mapping for coarse geolocation fallback
var countryCoordinates = map[string][2]float64{
	"US": {37.0902, -95.7129},
	"CA": {56.1304, -106.3468},
	"GB": {55.3781, -3.4360},
	"DE": {51.1657, 10.4515},
	"FR": {46.2276, 2.2137},
	"JP": {36.2048, 138.2529},
	"KR": {35.9078, 127.7669},
	"SG": {1.3521, 103.8198},
	"AU": {-25.2744, 133.7751},
	"BR": {-14.2350, -51.9253},
}

func (s *AppServer) handleAnycastRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	clientIP := r.Header.Get("CF-Connecting-IP")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Forwarded-For")
	}
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if idx := strings.Index(clientIP, ":"); idx != -1 && !strings.Contains(clientIP, "::") {
		clientIP = clientIP[:idx]
	}

	var lat, lon float64
	if latStr := q.Get("lat"); latStr != "" {
		lat, _ = strconv.ParseFloat(latStr, 64)
	} else if cfLat := r.Header.Get("CF-IPLatitude"); cfLat != "" {
		lat, _ = strconv.ParseFloat(cfLat, 64)
	}

	if lonStr := q.Get("lon"); lonStr != "" {
		lon, _ = strconv.ParseFloat(lonStr, 64)
	} else if cfLon := r.Header.Get("CF-IPLongitude"); cfLon != "" {
		lon, _ = strconv.ParseFloat(cfLon, 64)
	}

	country := strings.ToUpper(strings.TrimSpace(q.Get("country")))
	if country == "" {
		country = strings.ToUpper(strings.TrimSpace(r.Header.Get("CF-IPCountry")))
	}

	// Fallback to country centroid if coordinates were omitted
	if lat == 0 && lon == 0 && country != "" {
		if coords, ok := countryCoordinates[country]; ok {
			lat, lon = coords[0], coords[1]
		}
	}

	preferredRegion := strings.TrimSpace(q.Get("region"))

	decision, err := s.proxy.RouteNearestPOP(lat, lon, clientIP, preferredRegion)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("X-Edge-POP", decision.SelectedPOP.ID)
	w.Header().Set("X-Edge-Region", decision.SelectedPOP.Region)
	w.Header().Set("X-Anycast-Routing-Token", decision.SignedRoutingToken)
	writeJSON(w, http.StatusOK, decision)
}

type probeReportReq struct {
	SourceRegion string  `json:"source_region"`
	SourceIP     string  `json:"source_ip"`
	TargetPOPID  string  `json:"target_pop_id"`
	RTTLatencyMS float64 `json:"rtt_latency_ms"`
	PacketLoss   float64 `json:"packet_loss"`
	JitterMS     float64 `json:"jitter_ms"`
}

func (s *AppServer) handleAnycastProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req probeReportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid probe payload"})
		return
	}

	probe := anycast.TelemetryProbe{
		SourceRegion: strings.TrimSpace(req.SourceRegion),
		SourceIP:     strings.TrimSpace(req.SourceIP),
		TargetPOPID:  strings.TrimSpace(req.TargetPOPID),
		RTTLatencyMS: req.RTTLatencyMS,
		PacketLoss:   req.PacketLoss,
		JitterMS:     req.JitterMS,
		Timestamp:    time.Now().UTC(),
	}

	s.proxy.IngestAnycastProbe(probe)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "recorded",
		"target":    probe.TargetPOPID,
		"timestamp": probe.Timestamp,
	})
}

func (s *AppServer) handleAnycastPOPs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.proxy.AnycastRouter() == nil {
			writeJSON(w, http.StatusOK, []anycast.POP{})
			return
		}
		writeJSON(w, http.StatusOK, s.proxy.AnycastRouter().ListPOPs())
	case http.MethodPost:
		var pop anycast.POP
		if err := json.NewDecoder(r.Body).Decode(&pop); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid POP payload"})
			return
		}
		if s.proxy.AnycastRouter() == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Anycast router not initialized"})
			return
		}
		if err := s.proxy.AnycastRouter().RegisterPOP(pop); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "registered",
			"pop":    pop,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *AppServer) handleAnycastCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.proxy.AnycastCache() == nil {
		writeJSON(w, http.StatusOK, anycast.EdgeCacheStats{})
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.AnycastCache().Stats())
}

type partitionSimReq struct {
	Region      string `json:"region"`
	Partitioned bool   `json:"partitioned"`
}

func (s *AppServer) handleAnycastPartitionSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req partitionSimReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	mitigator := s.proxy.PartitionMitigator()
	if mitigator == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Partition mitigator not initialized"})
		return
	}

	region := strings.TrimSpace(req.Region)
	if region == "" {
		region = mitigator.LocalRegion()
	}

	mitigator.SetPartitioned(region, req.Partitioned)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"region":         region,
		"is_partitioned": mitigator.IsPartitioned(region),
		"state":          mitigator.GetPartitionState(region),
	})
}

type fastVerifyReq struct {
	LicenseKey string `json:"license_key"`
	HWID       string `json:"hwid"`
}

func (s *AppServer) handleAnycastFastVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req fastVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	start := time.Now()
	res, err := s.proxy.FastVerifyLicense(r.Context(), req.LicenseKey, req.HWID)
	elapsedUS := float64(time.Since(start).Nanoseconds()) / 1000.0

	w.Header().Set("X-Lookup-Latency-US", strconv.FormatFloat(elapsedUS, 'f', 2, 64))

	if err != nil && (res == nil || !res.Valid) {
		msg := err.Error()
		if res != nil && res.Message != "" {
			msg = res.Message
		}
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"valid":   false,
			"message": msg,
		})
		return
	}

	writeJSON(w, http.StatusOK, res)
}
