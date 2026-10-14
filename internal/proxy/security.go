package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/ratelimit"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// CheckRateLimit evaluates an incoming request from the specified client IP.
func (p *Proxy) CheckRateLimit(ip string, sensitive bool) ratelimit.Result {
	res := p.rateLimiter.Allow(ip, sensitive)
	if !res.Allowed {
		p.RecordAuditEvent(audit.AuditRecord{
			EventType: "RATE_LIMIT_EXCEEDED",
			Severity:  "WARNING",
			ActorIP:   ip,
			Details:   fmt.Sprintf("limit: %d, retry_after: %v", res.Limit, res.RetryAfter),
		})
	}
	return res
}

// RecordSecurityViolation logs an infraction, updates reputation, and triggers automated bans and alerts.
func (p *Proxy) RecordSecurityViolation(target, ip string, vType ratelimit.ViolationType, details string) (int, bool, *ratelimit.TemporaryBan) {
	key := ip
	if target != "" {
		key = target
	}

	score, autoBanned, ban := p.reputationTracker.RecordViolation(key, vType, details)

	// Log audit trail event
	sev := "WARNING"
	if autoBanned || vType == ratelimit.ViolationTamperDetected || vType == ratelimit.ViolationReplayAttack {
		sev = "CRITICAL"
	}
	p.RecordAuditEvent(audit.AuditRecord{
		EventType: string(vType),
		Severity:  sev,
		ActorIP:   ip,
		HWID:      target,
		Details:   fmt.Sprintf("%s (score: %d)", details, score),
	})

	// If threshold triggered automatic ban, dispatch high-priority security incident alert
	if autoBanned && ban != nil {
		incident := webhook.SecurityAlert{
			ID:        fmt.Sprintf("ban_%d", time.Now().UnixNano()),
			Type:      "ip_reputation_ban",
			Severity:  webhook.SeverityCritical,
			Target:    target,
			IPAddress: ip,
			Summary:   fmt.Sprintf("Automatic temporary ban applied to %s", key),
			Details:   ban.Reason,
			Timestamp: ban.BannedAt,
		}
		// Dispatch async alert to Discord/Slack channels
		go func() {
			_ = p.DispatchSecurityIncident(context.Background(), incident)
		}()
	}

	return score, autoBanned, ban
}

// IsBanned checks whether an IP or HWID is currently subject to a temporary restriction.
func (p *Proxy) IsBanned(target string) (bool, *ratelimit.TemporaryBan) {
	return p.reputationTracker.IsBanned(target)
}

// ManualBan applies an administrator-imposed temporary restriction.
func (p *Proxy) ManualBan(target, reason string, duration time.Duration) *ratelimit.TemporaryBan {
	ban := p.reputationTracker.Ban(target, reason, duration)
	p.RecordAuditEvent(audit.AuditRecord{
		EventType: "MANUAL_BAN",
		Severity:  "WARNING",
		Resource:  target,
		Details:   fmt.Sprintf("reason: %s, duration: %v", reason, duration),
	})
	return ban
}

// ManualUnban removes a restriction and clears violation history.
func (p *Proxy) ManualUnban(target string) bool {
	res := p.reputationTracker.Unban(target)
	if res {
		p.rateLimiter.Reset(target)
		p.RecordAuditEvent(audit.AuditRecord{
			EventType: "MANUAL_UNBAN",
			Severity:  "INFO",
			Resource:  target,
			Details:   "restriction cleared by admin",
		})
	}
	return res
}

// ListBanned returns all currently active temporary restrictions.
func (p *Proxy) ListBanned() []*ratelimit.TemporaryBan {
	return p.reputationTracker.ListBanned()
}

// GetReputationSummary delivers aggregated reputation and ban statistics.
func (p *Proxy) GetReputationSummary() ratelimit.Summary {
	return p.reputationTracker.GetSummary()
}

// LimiterStats delivers rate limiter metrics.
func (p *Proxy) LimiterStats() map[string]interface{} {
	return p.rateLimiter.Stats()
}

// RecordAuditEvent writes an event to the local audit ring buffer.
func (p *Proxy) RecordAuditEvent(rec audit.AuditRecord) {
	if p.auditCollector != nil {
		p.auditCollector.Record(rec)
	}
}

// ListAuditRecords returns audit events matching the provided filters.
func (p *Proxy) ListAuditRecords(limit int, severity, eventType string) []audit.AuditRecord {
	if p.auditCollector == nil {
		return nil
	}
	return p.auditCollector.List(limit, severity, eventType)
}

// ExportEncryptedAudit packages audit records into an AES-256-GCM encrypted bundle with HMAC integrity.
func (p *Proxy) ExportEncryptedAudit(secretKey []byte, limit int, severity, eventType string) (*audit.EncryptedAuditBundle, error) {
	records := p.ListAuditRecords(limit, severity, eventType)
	return audit.ExportEncrypted(records, secretKey)
}

// VerifyAuditBundle validates integrity and decrypts an audit bundle using the provided secret key.
func (p *Proxy) VerifyAuditBundle(bundle *audit.EncryptedAuditBundle, secretKey []byte) ([]audit.AuditRecord, error) {
	return audit.DecryptAndVerify(bundle, secretKey)
}
