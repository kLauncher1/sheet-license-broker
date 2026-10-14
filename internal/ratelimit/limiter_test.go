package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterAllowAndReset(t *testing.T) {
	cfg := Config{
		Window:               1 * time.Second,
		MaxRequests:          3,
		SensitiveMaxRequests: 2,
		BackoffLevels:        []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
	}
	limiter := NewLimiter(cfg)

	// 1st request
	res1 := limiter.Allow("ip-1", false)
	if !res1.Allowed || res1.Remaining != 2 {
		t.Fatalf("expected allowed with remaining 2, got: %+v", res1)
	}

	// 2nd request
	res2 := limiter.Allow("ip-1", false)
	if !res2.Allowed || res2.Remaining != 1 {
		t.Fatalf("expected allowed with remaining 1, got: %+v", res2)
	}

	// 3rd request
	res3 := limiter.Allow("ip-1", false)
	if !res3.Allowed || res3.Remaining != 0 {
		t.Fatalf("expected allowed with remaining 0, got: %+v", res3)
	}

	// 4th request (should be rejected and penalized)
	res4 := limiter.Allow("ip-1", false)
	if res4.Allowed || !res4.Penalty || res4.RetryAfter <= 0 {
		t.Fatalf("expected rejected with penalty, got: %+v", res4)
	}

	// Reset should allow immediately
	limiter.Reset("ip-1")
	res5 := limiter.Allow("ip-1", false)
	if !res5.Allowed {
		t.Fatalf("expected allowed after reset, got: %+v", res5)
	}
}

func TestLimiterProgressiveBackoff(t *testing.T) {
	cfg := Config{
		Window:               500 * time.Millisecond,
		MaxRequests:          1,
		SensitiveMaxRequests: 1,
		BackoffLevels:        []time.Duration{50 * time.Millisecond, 150 * time.Millisecond},
	}
	limiter := NewLimiter(cfg)

	// 1st request: allowed
	if res := limiter.Allow("client-a", false); !res.Allowed {
		t.Fatalf("expected request 1 allowed")
	}

	// 2nd request: 1st backoff level (50ms)
	res2 := limiter.Allow("client-a", false)
	if res2.Allowed || res2.RetryAfter <= 0 {
		t.Fatalf("expected 1st backoff level penalty, got: %+v", res2)
	}

	// Wait for penalty to expire
	time.Sleep(60 * time.Millisecond)

	// Next attempt over limit escalates to 2nd backoff level (150ms)
	res3 := limiter.Allow("client-a", false)
	if res3.Allowed || res3.RetryAfter < 100*time.Millisecond {
		t.Fatalf("expected 2nd backoff level penalty, got: %+v", res3)
	}
}

func TestReputationViolationAndAutoBan(t *testing.T) {
	cfg := ReputationConfig{
		WindowDuration: 1 * time.Second,
		BanThreshold:   30,
		BanDuration:    200 * time.Millisecond,
		Weights:        DefaultViolationWeights,
	}
	tracker := NewReputationTracker(cfg)

	// Initial check: not banned
	banned, _ := tracker.IsBanned("192.168.1.100")
	if banned {
		t.Fatalf("expected IP not banned initially")
	}

	// Record 1st violation: Failed validation (10 pts)
	score, autoBanned, ban := tracker.RecordViolation("192.168.1.100", ViolationFailedValidation, "unknown license")
	if score != 10 || autoBanned || ban != nil {
		t.Fatalf("expected score 10 and no ban, got: %d, %v", score, autoBanned)
	}

	// Record 2nd violation: Replay attack (25 pts -> total 35 pts >= 30)
	score2, autoBanned2, ban2 := tracker.RecordViolation("192.168.1.100", ViolationReplayAttack, "duplicate nonce")
	if score2 != 35 || !autoBanned2 || ban2 == nil {
		t.Fatalf("expected auto-ban triggered with score 35, got: %d, %v, %+v", score2, autoBanned2, ban2)
	}

	// Check IsBanned
	isBanned, activeBan := tracker.IsBanned("192.168.1.100")
	if !isBanned || activeBan == nil {
		t.Fatalf("expected IsBanned true")
	}

	// Verify ban expires after duration
	time.Sleep(250 * time.Millisecond)
	isBannedAfter, _ := tracker.IsBanned("192.168.1.100")
	if isBannedAfter {
		t.Fatalf("expected ban to expire after 200ms")
	}
}

func TestReputationManualBanAndUnban(t *testing.T) {
	tracker := NewReputationTracker(DefaultReputationConfig())

	// Manual ban
	ban := tracker.Ban("bad-hwid-999", "fraudulent device", 10*time.Minute)
	if ban == nil || ban.Key != "bad-hwid-999" {
		t.Fatalf("expected manual ban created")
	}

	banned, b := tracker.IsBanned("bad-hwid-999")
	if !banned || b.Reason != "fraudulent device" {
		t.Fatalf("expected active manual ban")
	}

	list := tracker.ListBanned()
	if len(list) != 1 {
		t.Fatalf("expected 1 banned entry, got %d", len(list))
	}

	// Unban
	if !tracker.Unban("bad-hwid-999") {
		t.Fatalf("expected unban to return true")
	}

	bannedNow, _ := tracker.IsBanned("bad-hwid-999")
	if bannedNow {
		t.Fatalf("expected key to be unbanned")
	}
}

func TestLimiterSweepAndStats(t *testing.T) {
	cfg := Config{
		Window:               10 * time.Millisecond,
		MaxRequests:          5,
		SensitiveMaxRequests: 2,
		BackoffLevels:        []time.Duration{10 * time.Millisecond},
	}
	limiter := NewLimiter(cfg)
	limiter.Allow("sweep-me", false)

	time.Sleep(30 * time.Millisecond)
	removed := limiter.Sweep()
	if removed != 1 {
		t.Fatalf("expected 1 bucket swept, got %d", removed)
	}

	stats := limiter.Stats()
	if stats["active_tracked_keys"] != 0 {
		t.Fatalf("expected 0 active keys after sweep, got %+v", stats)
	}
}
