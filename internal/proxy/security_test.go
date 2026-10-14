package proxy

import (
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/ratelimit"
)

func TestProxyRateLimitAndAudit(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	ip := "192.168.1.201"
	// Exhaust limit for sensitive endpoint (default 10)
	for i := 0; i < 10; i++ {
		res := p.CheckRateLimit(ip, true)
		if !res.Allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 11th request should be denied
	resDenied := p.CheckRateLimit(ip, true)
	if resDenied.Allowed || !resDenied.Penalty {
		t.Fatalf("expected rate limit denial with penalty")
	}

	// Audit records should include RATE_LIMIT_EXCEEDED
	records := p.ListAuditRecords(10, "", "RATE_LIMIT_EXCEEDED")
	if len(records) == 0 {
		t.Fatalf("expected RATE_LIMIT_EXCEEDED audit record logged")
	}
	if records[0].ActorIP != ip {
		t.Fatalf("expected audit record IP %s, got %s", ip, records[0].ActorIP)
	}
}

func TestProxyRecordSecurityViolationAndAutoBan(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	ip := "10.10.10.50"
	hwid := "HWID-SUSPECT-XYZ"

	// Record 1st violation: Signature mismatch (25 pts)
	score1, autoBanned1, _ := p.RecordSecurityViolation(hwid, ip, ratelimit.ViolationSignatureMismatch, "invalid hmac")
	if score1 != 25 || autoBanned1 {
		t.Fatalf("expected score 25, autoBanned false")
	}

	banned, _ := p.IsBanned(hwid)
	if banned {
		t.Fatalf("expected not banned yet")
	}

	// Record 2nd violation: Replay attack (25 pts -> 50 pts, exceeds threshold)
	score2, autoBanned2, ban := p.RecordSecurityViolation(hwid, ip, ratelimit.ViolationReplayAttack, "replayed nonce")
	if score2 != 50 || !autoBanned2 || ban == nil {
		t.Fatalf("expected auto-ban at score 50")
	}

	bannedNow, activeBan := p.IsBanned(hwid)
	if !bannedNow || activeBan == nil {
		t.Fatalf("expected IsBanned true after auto-ban")
	}

	// Verify reputation summary reflects active ban
	summary := p.GetReputationSummary()
	if summary.ActiveBansCount < 1 {
		t.Fatalf("expected active bans count >= 1 in summary")
	}
}

func TestProxyManualBanAndUnban(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	target := "203.0.113.19"
	p.ManualBan(target, "malicious probing", 5*time.Minute)

	banned, b := p.IsBanned(target)
	if !banned || b.Reason != "malicious probing" {
		t.Fatalf("expected manual ban active")
	}

	bannedList := p.ListBanned()
	found := false
	for _, item := range bannedList {
		if item.Key == target {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected target in ListBanned")
	}

	// Unban
	if !p.ManualUnban(target) {
		t.Fatalf("expected ManualUnban true")
	}
	bannedAfter, _ := p.IsBanned(target)
	if bannedAfter {
		t.Fatalf("expected target unbanned")
	}
}

func TestProxyAuditExportAndVerify(t *testing.T) {
	p, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}

	secretKey := []byte("audit-siem-integration-key-32b!")

	// Seed audit records
	p.RecordAuditEvent(audit.AuditRecord{
		EventType: "LICENSE_CREATED",
		Severity:  "INFO",
		Resource:  "LIC-AAA-BBB",
		Details:   "license generated for customer",
	})
	p.RecordAuditEvent(audit.AuditRecord{
		EventType: "TAMPER_DETECTED",
		Severity:  "CRITICAL",
		ActorIP:   "198.51.100.4",
		Details:   "memory modification attempt",
	})

	// Export encrypted bundle
	bundle, err := p.ExportEncryptedAudit(secretKey, 10, "", "")
	if err != nil {
		t.Fatalf("failed to export encrypted audit: %v", err)
	}
	if bundle.RecordCount < 2 {
		t.Fatalf("expected at least 2 records exported, got %d", bundle.RecordCount)
	}

	// Verify and decrypt
	decrypted, err := p.VerifyAuditBundle(bundle, secretKey)
	if err != nil {
		t.Fatalf("failed to decrypt audit bundle: %v", err)
	}
	if len(decrypted) != bundle.RecordCount {
		t.Fatalf("record count mismatch after decryption")
	}
}
