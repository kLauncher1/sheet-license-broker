package anomaly

import (
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// countryCoordinates provides approximate geographic centroids (lat, lon) for common ISO codes.
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
	"IN": {20.5937, 78.9629},
	"BR": {-14.2350, -51.9253},
	"NL": {52.1326, 5.2913},
	"IE": {53.1424, -7.6921},
	"SE": {60.1282, 18.6435},
	"CH": {46.8182, 8.2275},
}

// clientTimingHistory records timestamps for inter-arrival statistical analysis.
type clientTimingHistory struct {
	lastTimestamp time.Time
	intervalsMs   []float64
}

// clientLocationHistory records geographical origin records for velocity tracking.
type clientLocationHistory struct {
	lastIP        string
	lastCountry   string
	lastTimestamp time.Time
	recentIPs     map[string]time.Time
}

// HeartbeatDriftAnalyzer tracks statistical drift in heartbeat arrival intervals.
type HeartbeatDriftAnalyzer struct {
	mu            sync.RWMutex
	histories     map[string]*clientTimingHistory
	maxWindowSize int
}

// NewHeartbeatDriftAnalyzer initializes a new drift analyzer.
func NewHeartbeatDriftAnalyzer(maxWindowSize int) *HeartbeatDriftAnalyzer {
	if maxWindowSize <= 0 {
		maxWindowSize = 32
	}
	return &HeartbeatDriftAnalyzer{
		histories:     make(map[string]*clientTimingHistory),
		maxWindowSize: maxWindowSize,
	}
}

// RecordHeartbeat evaluates inter-arrival timing and returns the calculated drift metrics.
func (hda *HeartbeatDriftAnalyzer) RecordHeartbeat(entityID string, ts time.Time) *HeartbeatDrift {
	hda.mu.Lock()
	defer hda.mu.Unlock()

	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return nil
	}

	hist, exists := hda.histories[entityID]
	if !exists {
		hda.histories[entityID] = &clientTimingHistory{
			lastTimestamp: ts,
			intervalsMs:   make([]float64, 0, hda.maxWindowSize),
		}
		return &HeartbeatDrift{
			SampleCount: 1,
			DriftState:  "nominal",
			EvaluatedAt: ts,
		}
	}

	intervalMs := float64(ts.Sub(hist.lastTimestamp).Milliseconds())
	if intervalMs < 0 {
		intervalMs = 0
	}
	hist.lastTimestamp = ts

	hist.intervalsMs = append(hist.intervalsMs, intervalMs)
	if len(hist.intervalsMs) > hda.maxWindowSize {
		hist.intervalsMs = hist.intervalsMs[1:]
	}

	n := len(hist.intervalsMs)
	if n < 3 {
		return &HeartbeatDrift{
			SampleCount:    n,
			LastIntervalMs: int64(intervalMs),
			DriftState:     "nominal",
			EvaluatedAt:    ts,
		}
	}

	var sum float64
	for _, val := range hist.intervalsMs {
		sum += val
	}
	mean := sum / float64(n)

	var varianceSum float64
	for _, val := range hist.intervalsMs {
		diff := val - mean
		varianceSum += diff * diff
	}
	stdDev := math.Sqrt(varianceSum / float64(n-1))

	var zScore float64
	if stdDev > 0 {
		zScore = math.Abs(intervalMs-mean) / stdDev
	}

	absDiff := math.Abs(intervalMs - mean)
	driftState := "nominal"
	// If difference is within 15% of mean, it is within expected network jitter tolerance
	if absDiff > 0.15*mean {
		if zScore > 3.0 {
			if intervalMs < mean*0.3 {
				driftState = "accelerated" // High-frequency flooding or replay attempt
			} else {
				driftState = "erratic" // Excessive jitter or timing anomaly
			}
		} else if zScore > 2.0 {
			driftState = "mild_drift"
		}
	}

	return &HeartbeatDrift{
		SampleCount:      n,
		MeanIntervalMs:   mean,
		StdDevIntervalMs: stdDev,
		LastIntervalMs:   int64(intervalMs),
		ZScore:           zScore,
		DriftState:       driftState,
		EvaluatedAt:      ts,
	}
}

// GeoVelocityDetector tracks impossible travel and rapid geographical origin anomalies.
type GeoVelocityDetector struct {
	mu          sync.RWMutex
	locations   map[string]*clientLocationHistory
	maxSpeedKmH float64
}

// NewGeoVelocityDetector initializes a geographical velocity detector.
func NewGeoVelocityDetector(maxSpeedKmH float64) *GeoVelocityDetector {
	if maxSpeedKmH <= 0 {
		maxSpeedKmH = 950.0 // Commercial airliner maximum ground speed
	}
	return &GeoVelocityDetector{
		locations:   make(map[string]*clientLocationHistory),
		maxSpeedKmH: maxSpeedKmH,
	}
}

// RecordLocation analyzes location changes for impossible travel velocity.
func (gvd *GeoVelocityDetector) RecordLocation(entityID, ip, country string, ts time.Time) (*GeoVelocityAnomaly, bool) {
	gvd.mu.Lock()
	defer gvd.mu.Unlock()

	entityID = strings.TrimSpace(entityID)
	country = strings.ToUpper(strings.TrimSpace(country))
	ip = strings.TrimSpace(ip)

	if entityID == "" || country == "" {
		return nil, false
	}

	hist, exists := gvd.locations[entityID]
	if !exists {
		gvd.locations[entityID] = &clientLocationHistory{
			lastIP:        ip,
			lastCountry:   country,
			lastTimestamp: ts,
			recentIPs:     map[string]time.Time{ip: ts},
		}
		return nil, false
	}

	// Purge recent IPs older than 5 minutes
	cutoff := ts.Add(-5 * time.Minute)
	for recordedIP, recordedTime := range hist.recentIPs {
		if recordedTime.Before(cutoff) {
			delete(hist.recentIPs, recordedIP)
		}
	}
	hist.recentIPs[ip] = ts

	timeDeltaSec := ts.Sub(hist.lastTimestamp).Seconds()
	prevCountry := hist.lastCountry
	prevIP := hist.lastIP

	hist.lastIP = ip
	hist.lastCountry = country
	hist.lastTimestamp = ts

	if prevCountry == country || timeDeltaSec <= 0 {
		return nil, false
	}

	c1, ok1 := countryCoordinates[prevCountry]
	c2, ok2 := countryCoordinates[country]

	var distKm float64
	if ok1 && ok2 {
		distKm = haversineDistance(c1[0], c1[1], c2[0], c2[1])
	} else {
		// Conservative estimated cross-border distance if unknown
		distKm = 1200.0
	}

	timeHours := timeDeltaSec / 3600.0
	speedKmH := distKm / timeHours

	isImpossible := speedKmH > gvd.maxSpeedKmH
	anomaly := &GeoVelocityAnomaly{
		PreviousCountry:     prevCountry,
		CurrentCountry:      country,
		PreviousIP:          prevIP,
		CurrentIP:           ip,
		TimeDeltaSec:        timeDeltaSec,
		EstimatedDistanceKm: distKm,
		CalculatedSpeedKmH:  speedKmH,
		ImpossibleTravel:    isImpossible,
		DetectedAt:          ts,
	}

	return anomaly, isImpossible
}

// DetectConcurrentSubnets checks if multiple distinct subnets access the same entity simultaneously.
func (gvd *GeoVelocityDetector) DetectConcurrentSubnets(entityID string) (int, bool) {
	gvd.mu.RLock()
	defer gvd.mu.RUnlock()

	hist, exists := gvd.locations[entityID]
	if !exists || len(hist.recentIPs) <= 1 {
		return 1, false
	}

	subnets := make(map[string]struct{})
	for ipStr := range hist.recentIPs {
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil {
			subnets[ipStr] = struct{}{}
			continue
		}
		if ipv4 := parsedIP.To4(); ipv4 != nil {
			// Mask /24 subnet
			mask := net.CIDRMask(24, 32)
			subnets[ipv4.Mask(mask).String()] = struct{}{}
		} else {
			// Mask /48 IPv6 subnet
			mask := net.CIDRMask(48, 128)
			subnets[parsedIP.Mask(mask).String()] = struct{}{}
		}
	}

	distinctSubnets := len(subnets)
	return distinctSubnets, distinctSubnets >= 2
}

// haversineDistance calculates great-circle distance between two coordinates in kilometers.
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0
	dLat := (lat2 - lat1) * (math.Pi / 180.0)
	dLon := (lon2 - lon1) * (math.Pi / 180.0)

	rLat1 := lat1 * (math.Pi / 180.0)
	rLat2 := lat2 * (math.Pi / 180.0)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rLat1)*math.Cos(rLat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c
}
