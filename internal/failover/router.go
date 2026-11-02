package failover

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoHealthyProviders = errors.New("no healthy cloud edge providers available")
	ErrTokenExpired       = errors.New("multi-cloud routing token has expired")
	ErrInvalidSignature   = errors.New("cryptographic signature on routing token is invalid")
	ErrProviderNotFound   = errors.New("requested cloud edge provider not found")
)

// MultiCloudRouter performs active-active geo-weighted routing and cryptographic token issuance.
type MultiCloudRouter struct {
	mu        sync.RWMutex
	prober    *HealthProber
	secretKey []byte
	tokenTTL  time.Duration
}

// NewMultiCloudRouter initializes the routing engine bound to the health prober.
func NewMultiCloudRouter(secretKey []byte, prober *HealthProber) *MultiCloudRouter {
	if len(secretKey) == 0 {
		secretKey = []byte("default-sheet-license-broker-multicloud-routing-key-32b")
	}
	return &MultiCloudRouter{
		prober:    prober,
		secretKey: secretKey,
		tokenTTL:  5 * time.Minute,
	}
}

// SelectOptimalProvider evaluates provider health, weights, and regional proximity to issue a signed token.
func (r *MultiCloudRouter) SelectOptimalProvider(clientRegion string, clientIP string) (*CloudProvider, *MultiCloudRoutingToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := r.prober.ListProviders()
	if len(providers) == 0 {
		return nil, nil, ErrNoHealthyProviders
	}

	normRegion := strings.ToLower(strings.TrimSpace(clientRegion))
	var bestProvider *CloudProvider
	var bestScore float64 = -1.0

	for i := range providers {
		p := &providers[i]
		if p.Status == ProviderStatusOffline || p.CircuitState == CircuitOpen {
			continue
		}

		// Calculate health and performance composite score
		weight := p.Weight
		if weight <= 0 {
			weight = 0.1
		}
		successFactor := p.SuccessRate / 100.0
		if successFactor <= 0 {
			successFactor = 0.5
		}

		latencyFactor := 1.0
		if p.LatencyEMA > 0 {
			latencyFactor = 100.0 / (100.0 + p.LatencyEMA)
		}

		// Regional affinity boost if matching
		geoBoost := 1.0
		if normRegion != "" {
			if strings.Contains(strings.ToLower(p.Name), normRegion) || strings.EqualFold(string(p.Type), normRegion) {
				geoBoost = 1.35
			}
		}

		score := weight * successFactor * latencyFactor * geoBoost
		if score > bestScore {
			bestScore = score
			bestProvider = p
		}
	}

	if bestProvider == nil {
		// Fallback to any provider that isn't completely offline
		for i := range providers {
			if providers[i].Status != ProviderStatusOffline {
				bestProvider = &providers[i]
				break
			}
		}
	}

	if bestProvider == nil {
		return nil, nil, ErrNoHealthyProviders
	}

	now := time.Now().UTC()
	tokenID := r.generateRandomID(16)
	issuedAt := now.Unix()
	expiresAt := now.Add(r.tokenTTL).Unix()

	sig := r.computeSignature(tokenID, bestProvider.ID, bestProvider.EndpointURL, clientIP, normRegion, issuedAt, expiresAt)

	token := &MultiCloudRoutingToken{
		TokenID:      tokenID,
		ProviderID:   bestProvider.ID,
		EndpointURL:  bestProvider.EndpointURL,
		ClientIP:     clientIP,
		ClientRegion: normRegion,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		Signature:    sig,
	}

	return bestProvider, token, nil
}

// VerifyRoutingToken cryptographically validates an issued multi-cloud routing token.
func (r *MultiCloudRouter) VerifyRoutingToken(token MultiCloudRoutingToken) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now().UTC().Unix()
	if now > token.ExpiresAt {
		return ErrTokenExpired
	}

	expectedSig := r.computeSignature(token.TokenID, token.ProviderID, token.EndpointURL, token.ClientIP, token.ClientRegion, token.IssuedAt, token.ExpiresAt)

	if subtle.ConstantTimeCompare([]byte(token.Signature), []byte(expectedSig)) != 1 {
		return ErrInvalidSignature
	}

	return nil
}

// UpdateProviderWeight adjusts dynamic traffic allocation weight for a cloud edge provider.
func (r *MultiCloudRouter) UpdateProviderWeight(providerID string, newWeight float64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, exists := r.prober.providers[providerID]
	if !exists {
		return ErrProviderNotFound
	}
	if newWeight < 0 {
		newWeight = 0
	} else if newWeight > 1.0 {
		newWeight = 1.0
	}
	p.Weight = math.Round(newWeight*100.0) / 100.0
	return nil
}

// SimulateOutage manually trips a provider into offline status and issues an immediate failover event.
func (r *MultiCloudRouter) SimulateOutage(failedProviderID string, reason string) (*FailoverEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, exists := r.prober.providers[failedProviderID]
	if !exists {
		return nil, ErrProviderNotFound
	}

	now := time.Now().UTC()
	p.Status = ProviderStatusOffline
	p.CircuitState = CircuitOpen
	p.ConsecutiveFailures = r.prober.config.FailureThreshold
	p.LastStateChange = now

	altID := r.prober.findBestAlternativeLocked(failedProviderID)
	event := &FailoverEvent{
		EventID:          fmt.Sprintf("sim-fo-%d-%s", now.UnixNano(), failedProviderID),
		PreviousProvider: failedProviderID,
		NewProvider:      altID,
		Reason:           reason,
		TriggerLatency:   p.LatencyEMA,
		TriggerErrorRate: 100.0,
		Timestamp:        now,
	}
	r.prober.recordEventLocked(*event)
	return event, nil
}

// computeSignature calculates HMAC-SHA256 over token parameters.
func (r *MultiCloudRouter) computeSignature(tokenID, providerID, endpoint, clientIP, region string, issuedAt, expiresAt int64) string {
	payload := fmt.Sprintf("%s:%s:%s:%s:%s:%d:%d", tokenID, providerID, endpoint, clientIP, region, issuedAt, expiresAt)
	mac := hmac.New(sha256.New, r.secretKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateRandomID generates a secure random hex identifier.
func (r *MultiCloudRouter) generateRandomID(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
