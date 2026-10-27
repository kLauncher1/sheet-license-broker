package healing

import (
	"math"
	"sync"
	"time"
)

// AutoScalingBucket implements an adaptive token bucket that scales its capacity
// and refill velocity based on incoming telemetry load and operational health.
type AutoScalingBucket struct {
	mu               sync.Mutex
	baseCapacity     float64
	maxBurstCapacity float64
	baseRefillRate   float64
	minRefillRate    float64
	burstMultiplier  float64
	windowDuration   time.Duration

	currentTokens   float64
	currentCapacity float64
	currentRefill   float64
	scaleMultiplier float64
	loadScore       float64
	mode            ScaleMode
	lastRefill      time.Time

	// Telemetry window tracking
	windowStart    time.Time
	windowRequests int
	windowErrors   int
}

// DefaultBucketConfig provides balanced defaults for licensing rate limits.
func DefaultBucketConfig() TokenBucketConfig {
	return TokenBucketConfig{
		BaseCapacity:     100.0,
		MaxBurstCapacity: 300.0,
		BaseRefillRate:   20.0,
		MinRefillRate:    5.0,
		BurstMultiplier:  2.5,
		WindowDuration:   10 * time.Second,
	}
}

// NewAutoScalingBucket initializes an adaptive token bucket with the given configuration.
func NewAutoScalingBucket(cfg TokenBucketConfig) *AutoScalingBucket {
	if cfg.BaseCapacity <= 0 {
		cfg.BaseCapacity = 100.0
	}
	if cfg.MaxBurstCapacity <= cfg.BaseCapacity {
		cfg.MaxBurstCapacity = cfg.BaseCapacity * 2.5
	}
	if cfg.BaseRefillRate <= 0 {
		cfg.BaseRefillRate = 20.0
	}
	if cfg.MinRefillRate <= 0 {
		cfg.MinRefillRate = 5.0
	}
	if cfg.BurstMultiplier <= 1.0 {
		cfg.BurstMultiplier = 2.0
	}
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 10 * time.Second
	}

	now := time.Now()
	return &AutoScalingBucket{
		baseCapacity:     cfg.BaseCapacity,
		maxBurstCapacity: cfg.MaxBurstCapacity,
		baseRefillRate:   cfg.BaseRefillRate,
		minRefillRate:    cfg.MinRefillRate,
		burstMultiplier:  cfg.BurstMultiplier,
		windowDuration:   cfg.WindowDuration,
		currentTokens:    cfg.BaseCapacity,
		currentCapacity:  cfg.BaseCapacity,
		currentRefill:    cfg.BaseRefillRate,
		scaleMultiplier:  1.0,
		loadScore:        0.0,
		mode:             ScaleModeNormal,
		lastRefill:       now,
		windowStart:      now,
	}
}

// RecordTelemetry submits request counts and error observations to steer bucket dynamics.
func (b *AutoScalingBucket) RecordTelemetry(requestCount int, errorCount int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.windowRequests += requestCount
	b.windowErrors += errorCount

	now := time.Now()
	if now.Sub(b.windowStart) >= b.windowDuration {
		b.evaluateScalingLocked(now)
	}
}

// evaluateScalingLocked updates bucket parameters based on observed telemetry.
func (b *AutoScalingBucket) evaluateScalingLocked(now time.Time) {
	elapsed := now.Sub(b.windowStart).Seconds()
	if elapsed <= 0 {
		elapsed = 1.0
	}

	reqRate := float64(b.windowRequests) / elapsed
	errRate := 0.0
	if b.windowRequests > 0 {
		errRate = float64(b.windowErrors) / float64(b.windowRequests)
	}

	// Calculate load score relative to base refill capacity
	expectedRate := b.baseRefillRate
	if expectedRate <= 0 {
		expectedRate = 1.0
	}
	b.loadScore = math.Min(3.0, reqRate/expectedRate)

	// Refill tokens before adjusting capacity
	b.refillLocked(now)

	if errRate >= 0.20 {
		// Degradation detected: apply defensive backpressure
		b.mode = ScaleModeThrottle
		b.scaleMultiplier = math.Max(0.25, 1.0-errRate)
		b.currentCapacity = math.Max(b.baseCapacity*0.25, b.baseCapacity*b.scaleMultiplier)
		b.currentRefill = math.Max(b.minRefillRate, b.baseRefillRate*b.scaleMultiplier)
	} else if b.loadScore > 1.2 && errRate < 0.05 {
		// Healthy burst detected: scale capacity and refill rate upwards
		b.mode = ScaleModeBurst
		burstFactor := 1.0 + (b.loadScore-1.0)*0.75
		b.scaleMultiplier = math.Min(b.burstMultiplier, burstFactor)
		b.currentCapacity = math.Min(b.maxBurstCapacity, b.baseCapacity*b.scaleMultiplier)
		b.currentRefill = b.baseRefillRate * b.scaleMultiplier
	} else {
		// Normal traffic profile: converge towards baseline
		b.mode = ScaleModeNormal
		b.scaleMultiplier = 1.0
		b.currentCapacity = b.baseCapacity
		b.currentRefill = b.baseRefillRate
	}

	// Clamp current tokens to new capacity
	if b.currentTokens > b.currentCapacity {
		b.currentTokens = b.currentCapacity
	}

	// Reset observation window
	b.windowStart = now
	b.windowRequests = 0
	b.windowErrors = 0
}

// refillLocked accumulates newly available tokens since the previous timestamp.
func (b *AutoScalingBucket) refillLocked(now time.Time) {
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	b.lastRefill = now

	tokensToAdd := elapsed * b.currentRefill
	b.currentTokens = math.Min(b.currentCapacity, b.currentTokens+tokensToAdd)
}

// TryConsume attempts to deduct the requested token amount from the bucket.
func (b *AutoScalingBucket) TryConsume(tokens float64) (bool, TokenBucketStats) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.refillLocked(now)

	// Check if window should roll over
	if now.Sub(b.windowStart) >= b.windowDuration {
		b.evaluateScalingLocked(now)
	}

	success := false
	if b.currentTokens >= tokens {
		b.currentTokens -= tokens
		success = true
		b.windowRequests++
	} else {
		b.windowRequests++
		b.windowErrors++
	}

	return success, b.statsLocked()
}

// Stats returns a point-in-time snapshot of the bucket state.
func (b *AutoScalingBucket) Stats() TokenBucketStats {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refillLocked(time.Now())
	return b.statsLocked()
}

func (b *AutoScalingBucket) statsLocked() TokenBucketStats {
	return TokenBucketStats{
		CurrentTokens:   math.Round(b.currentTokens*100) / 100,
		Capacity:        b.currentCapacity,
		BaseCapacity:    b.baseCapacity,
		RefillRate:      b.currentRefill,
		LoadScore:       math.Round(b.loadScore*100) / 100,
		ScaleMultiplier: math.Round(b.scaleMultiplier*100) / 100,
		Mode:            b.mode,
		LastRefill:      b.lastRefill,
	}
}
