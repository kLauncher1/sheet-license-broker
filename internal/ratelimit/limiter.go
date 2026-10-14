package ratelimit

import (
	"sync"
	"time"
)

// Config configures rate limiter thresholds and progressive backoff penalties.
type Config struct {
	// Window defines the sliding window duration (default 1 minute).
	Window time.Duration
	// MaxRequests defines allowed requests per window for general endpoints.
	MaxRequests int
	// SensitiveMaxRequests defines allowed requests per window for sensitive endpoints (auth, validation).
	SensitiveMaxRequests int
	// BackoffLevels defines progressive backoff penalty delays upon repeated violations.
	BackoffLevels []time.Duration
}

// DefaultConfig provides production-tuned defaults.
func DefaultConfig() Config {
	return Config{
		Window:               1 * time.Minute,
		MaxRequests:          60,
		SensitiveMaxRequests: 10,
		BackoffLevels: []time.Duration{
			2 * time.Second,
			5 * time.Second,
			15 * time.Second,
			60 * time.Second,
		},
	}
}

// clientBucket tracks request history and penalty state for a single client identifier.
type clientBucket struct {
	requests     []time.Time
	violationCnt int
	penaltyUntil time.Time
	lastSeen     time.Time
}

// Limiter implements in-memory token/sliding-window rate limiting with progressive backoff.
type Limiter struct {
	mu      sync.RWMutex
	cfg     Config
	buckets map[string]*clientBucket
}

// NewLimiter constructs a thread-safe rate limiter.
func NewLimiter(cfg Config) *Limiter {
	if cfg.Window <= 0 {
		cfg.Window = 1 * time.Minute
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 60
	}
	if cfg.SensitiveMaxRequests <= 0 {
		cfg.SensitiveMaxRequests = 10
	}
	if len(cfg.BackoffLevels) == 0 {
		cfg.BackoffLevels = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 60 * time.Second}
	}
	return &Limiter{
		cfg:     cfg,
		buckets: make(map[string]*clientBucket),
	}
}

// Result captures the evaluation result of a rate limit check.
type Result struct {
	Allowed    bool          `json:"allowed"`
	Remaining  int           `json:"remaining"`
	Limit      int           `json:"limit"`
	RetryAfter time.Duration `json:"retry_after,omitempty"`
	ResetTime  time.Time     `json:"reset_time"`
	Penalty    bool          `json:"penalty"`
}

// Allow evaluates an incoming request for the given key and sensitivity flag.
func (l *Limiter) Allow(key string, sensitive bool) Result {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	limit := l.cfg.MaxRequests
	if sensitive {
		limit = l.cfg.SensitiveMaxRequests
	}

	b, exists := l.buckets[key]
	if !exists {
		b = &clientBucket{
			requests: make([]time.Time, 0, limit),
			lastSeen: now,
		}
		l.buckets[key] = b
	}
	b.lastSeen = now

	// 1. Check if under active progressive backoff penalty
	if now.Before(b.penaltyUntil) {
		retry := b.penaltyUntil.Sub(now)
		return Result{
			Allowed:    false,
			Remaining:  0,
			Limit:      limit,
			RetryAfter: retry,
			ResetTime:  b.penaltyUntil,
			Penalty:    true,
		}
	}

	// 2. Slide window: prune expired requests
	cutoff := now.Add(-l.cfg.Window)
	valid := b.requests[:0]
	for _, t := range b.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.requests = valid

	// Reset violation counter if no requests remained in the window
	if len(b.requests) == 0 {
		b.violationCnt = 0
	}

	// 3. Check threshold
	if len(b.requests) >= limit {
		// Limit exceeded: escalate progressive penalty
		level := b.violationCnt
		if level >= len(l.cfg.BackoffLevels) {
			level = len(l.cfg.BackoffLevels) - 1
		}
		penaltyDur := l.cfg.BackoffLevels[level]
		b.penaltyUntil = now.Add(penaltyDur)
		b.violationCnt++

		return Result{
			Allowed:    false,
			Remaining:  0,
			Limit:      limit,
			RetryAfter: penaltyDur,
			ResetTime:  b.penaltyUntil,
			Penalty:    true,
		}
	}

	// 4. Record request
	b.requests = append(b.requests, now)
	remaining := limit - len(b.requests)
	reset := now.Add(l.cfg.Window)
	if len(b.requests) > 0 {
		reset = b.requests[0].Add(l.cfg.Window)
	}

	return Result{
		Allowed:    true,
		Remaining:  remaining,
		Limit:      limit,
		RetryAfter: 0,
		ResetTime:  reset,
		Penalty:    false,
	}
}

// Reset clears limits and penalties for a specific key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// Sweep removes inactive buckets older than 2x the window duration.
func (l *Limiter) Sweep() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-2 * l.cfg.Window)
	removed := 0
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) && now.After(b.penaltyUntil) {
			delete(l.buckets, k)
			removed++
		}
	}
	return removed
}

// Stats returns an overview of active rate limit buckets.
func (l *Limiter) Stats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := time.Now()
	activeBuckets := len(l.buckets)
	penalizedCount := 0
	for _, b := range l.buckets {
		if now.Before(b.penaltyUntil) {
			penalizedCount++
		}
	}

	return map[string]interface{}{
		"active_tracked_keys": activeBuckets,
		"penalized_keys":      penalizedCount,
		"window_seconds":      int(l.cfg.Window.Seconds()),
		"max_requests":        l.cfg.MaxRequests,
		"sensitive_max":       l.cfg.SensitiveMaxRequests,
	}
}
