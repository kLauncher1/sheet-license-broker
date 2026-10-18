package anycast

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Default predefined global Points of Presence.
var defaultPOPs = []POP{
	{ID: "iad", Name: "Ashburn IAD", Region: "us-east", Country: "US", Latitude: 39.0438, Longitude: -77.4874, EndpointURL: "https://iad.edge.sheet-broker.internal", Weight: 1.0, Status: POPStatusHealthy},
	{ID: "sjc", Name: "San Jose SJC", Region: "us-west", Country: "US", Latitude: 37.3382, Longitude: -121.8863, EndpointURL: "https://sjc.edge.sheet-broker.internal", Weight: 1.0, Status: POPStatusHealthy},
	{ID: "fra", Name: "Frankfurt FRA", Region: "eu-central", Country: "DE", Latitude: 50.1109, Longitude: 8.6821, EndpointURL: "https://fra.edge.sheet-broker.internal", Weight: 1.0, Status: POPStatusHealthy},
	{ID: "nrt", Name: "Tokyo NRT", Region: "ap-northeast", Country: "JP", Latitude: 35.7720, Longitude: 140.3929, EndpointURL: "https://nrt.edge.sheet-broker.internal", Weight: 1.0, Status: POPStatusHealthy},
	{ID: "sin", Name: "Singapore SIN", Region: "ap-southeast", Country: "SG", Latitude: 1.3521, Longitude: 103.8198, EndpointURL: "https://sin.edge.sheet-broker.internal", Weight: 1.0, Status: POPStatusHealthy},
	{ID: "gru", Name: "Sao Paulo GRU", Region: "sa-east", Country: "BR", Latitude: -23.5505, Longitude: -46.6333, EndpointURL: "https://gru.edge.sheet-broker.internal", Weight: 1.0, Status: POPStatusHealthy},
}

// AnycastRouter performs geographic and latency-aware edge CDN routing with signed tokens.
type AnycastRouter struct {
	mu           sync.RWMutex
	pops         map[string]*POP
	probeHistory map[string][]TelemetryProbe
	secretKey    []byte
	defaultTTL   time.Duration
}

// NewAnycastRouter creates a router instance with predefined global POPs.
func NewAnycastRouter(secretKey []byte) *AnycastRouter {
	if len(secretKey) == 0 {
		secretKey = []byte("default-sheet-license-broker-anycast-key")
	}
	r := &AnycastRouter{
		pops:         make(map[string]*POP),
		probeHistory: make(map[string][]TelemetryProbe),
		secretKey:    secretKey,
		defaultTTL:   15 * time.Minute,
	}
	for _, pop := range defaultPOPs {
		copied := pop
		r.pops[copied.ID] = &copied
	}
	return r
}

// HaversineDistanceKM computes spherical distance between two coordinate pairs in kilometers.
func HaversineDistanceKM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKM = 6371.0
	dLat := (lat2 - lat1) * (math.Pi / 180.0)
	dLon := (lon2 - lon1) * (math.Pi / 180.0)
	radLat1 := lat1 * (math.Pi / 180.0)
	radLat2 := lat2 * (math.Pi / 180.0)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(radLat1)*math.Cos(radLat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusKM * c
}

type popScore struct {
	pop             POP
	score           float64
	estimatedRTT    float64
}

// RouteNearest identifies the optimal POP and fallbacks based on distance, latency, and health.
func (r *AnycastRouter) RouteNearest(clientLat, clientLon float64, clientIP, preferredRegion string) (*RoutingDecision, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.pops) == 0 {
		return nil, errors.New("no points of presence registered")
	}

	var candidates []popScore
	for _, pop := range r.pops {
		if pop.Status == POPStatusOffline {
			continue
		}

		distKM := HaversineDistanceKM(clientLat, clientLon, pop.Latitude, pop.Longitude)
		// Approx round-trip latency: 5ms base + 15ms per 1000km in terrestrial fiber
		calcLatency := 5.0 + (distKM * 0.015)
		if pop.AverageRTT > 0 {
			calcLatency = 0.35*calcLatency + 0.65*pop.AverageRTT
		}

		// Preferred region bonus
		if preferredRegion != "" && (strings.EqualFold(pop.Region, preferredRegion) || strings.EqualFold(pop.Country, preferredRegion)) {
			calcLatency *= 0.80
		}

		// Degraded health penalty
		if pop.Status == POPStatusDegraded {
			calcLatency += 120.0
		}

		weight := pop.Weight
		if weight <= 0 {
			weight = 1.0
		}
		finalScore := calcLatency / weight

		candidates = append(candidates, popScore{
			pop:          *pop,
			score:        finalScore,
			estimatedRTT: calcLatency,
		})
	}

	if len(candidates) == 0 {
		// All POPs offline, fallback to any POP with offline penalty
		for _, pop := range r.pops {
			distKM := HaversineDistanceKM(clientLat, clientLon, pop.Latitude, pop.Longitude)
			candidates = append(candidates, popScore{
				pop:          *pop,
				score:        distKM + 500.0,
				estimatedRTT: 500.0,
			})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score < candidates[j].score
	})

	selected := candidates[0].pop
	var fallbacks []POP
	for i := 1; i < len(candidates) && i <= 3; i++ {
		fallbacks = append(fallbacks, candidates[i].pop)
	}

	token, err := r.generateRoutingTokenLocked(selected.ID, clientIP, r.defaultTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate routing token: %w", err)
	}

	return &RoutingDecision{
		SelectedPOP:        selected,
		FallbackPOPs:       fallbacks,
		EstimatedLatencyMS: math.Round(candidates[0].estimatedRTT*100) / 100,
		SignedRoutingToken: token,
		Timestamp:          time.Now().UTC(),
		ClientIP:           clientIP,
	}, nil
}

// GenerateRoutingToken creates an HMAC-SHA256 signed routing token for a client and POP.
func (r *AnycastRouter) GenerateRoutingToken(popID, clientIP string, ttl time.Duration) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.generateRoutingTokenLocked(popID, clientIP, ttl)
}

func (r *AnycastRouter) generateRoutingTokenLocked(popID, clientIP string, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = r.defaultTTL
	}
	now := time.Now().UTC()
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}

	claims := RoutingTokenClaims{
		POPID:     popID,
		ClientIP:  clientIP,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Nonce:     hex.EncodeToString(nonceBytes),
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, r.secretKey)
	mac.Write([]byte(payloadB64))
	signature := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", payloadB64, signature), nil
}

// VerifyRoutingToken validates the HMAC-SHA256 signature and expiration of a routing token.
func (r *AnycastRouter) VerifyRoutingToken(tokenStr string) (*RoutingTokenClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed routing token")
	}

	payloadB64, signatureHex := parts[0], parts[1]

	r.mu.RLock()
	mac := hmac.New(sha256.New, r.secretKey)
	r.mu.RUnlock()

	mac.Write([]byte(payloadB64))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signatureHex), []byte(expectedSig)) {
		return nil, errors.New("invalid routing token signature")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims payload: %w", err)
	}

	var claims RoutingTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return nil, errors.New("routing token expired")
	}

	return &claims, nil
}

// RegisterPOP registers or updates a Point of Presence.
func (r *AnycastRouter) RegisterPOP(pop POP) error {
	if pop.ID == "" {
		return errors.New("pop ID cannot be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if pop.Status == "" {
		pop.Status = POPStatusHealthy
	}
	if pop.Weight <= 0 {
		pop.Weight = 1.0
	}
	if pop.LastSeen.IsZero() {
		pop.LastSeen = time.Now().UTC()
	}

	copied := pop
	r.pops[pop.ID] = &copied
	return nil
}

// GetPOP retrieves a registered POP by ID.
func (r *AnycastRouter) GetPOP(id string) (POP, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pop, ok := r.pops[id]
	if !ok {
		return POP{}, false
	}
	return *pop, true
}

// ListPOPs returns all registered POPs.
func (r *AnycastRouter) ListPOPs() []POP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]POP, 0, len(r.pops))
	for _, p := range r.pops {
		res = append(res, *p)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})
	return res
}

// UpdatePOPStatus changes the operational health status of a POP.
func (r *AnycastRouter) UpdatePOPStatus(id string, status POPStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pop, ok := r.pops[id]; ok {
		pop.Status = status
		pop.LastSeen = time.Now().UTC()
	}
}

// IngestProbe updates latency and health statistics based on incoming telemetry.
func (r *AnycastRouter) IngestProbe(probe TelemetryProbe) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if probe.Timestamp.IsZero() {
		probe.Timestamp = time.Now().UTC()
	}

	pop, ok := r.pops[probe.TargetPOPID]
	if !ok {
		return
	}

	// Exponential moving average for latency
	if pop.AverageRTT <= 0 {
		pop.AverageRTT = probe.RTTLatencyMS
	} else {
		pop.AverageRTT = (pop.AverageRTT * 0.70) + (probe.RTTLatencyMS * 0.30)
	}

	pop.LastSeen = probe.Timestamp

	// Automatic status adjustment based on packet loss
	if probe.PacketLoss >= 0.50 {
		pop.Status = POPStatusDegraded
	} else if probe.PacketLoss < 0.10 && pop.Status == POPStatusDegraded {
		pop.Status = POPStatusHealthy
	}

	// Keep bounded history of last 50 probes per POP
	history := r.probeHistory[probe.TargetPOPID]
	if len(history) >= 50 {
		history = history[1:]
	}
	r.probeHistory[probe.TargetPOPID] = append(history, probe)
}
