package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/audit"
)

// extractClientIP retrieves the real client IP from standard proxy headers or RemoteAddr.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// securityRateLimitMiddleware wraps the HTTP handler with rate limiting and temporary ban enforcement.
func (s *AppServer) securityRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := extractClientIP(r)
		hwid := strings.TrimSpace(r.Header.Get("X-HWID"))

		// 1. Check if client IP or HWID is under active temporary ban
		if banned, ban := s.proxy.IsBanned(clientIP); banned && ban != nil {
			retrySec := int(time.Until(ban.ExpiresAt).Seconds())
			if retrySec < 1 {
				retrySec = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retrySec))
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":       "temporarily_banned",
				"reason":      ban.Reason,
				"banned_at":   ban.BannedAt,
				"expires_at":  ban.ExpiresAt,
				"retry_after": retrySec,
			})
			return
		}
		if hwid != "" {
			if banned, ban := s.proxy.IsBanned(hwid); banned && ban != nil {
				retrySec := int(time.Until(ban.ExpiresAt).Seconds())
				if retrySec < 1 {
					retrySec = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retrySec))
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":       "device_temporarily_banned",
					"reason":      ban.Reason,
					"hwid":        hwid,
					"expires_at":  ban.ExpiresAt,
					"retry_after": retrySec,
				})
				return
			}
		}

		// 2. Identify sensitive endpoints requiring stricter rate limiting
		path := r.URL.Path
		isSensitive := strings.HasPrefix(path, "/api/licenses/validate") ||
			strings.HasPrefix(path, "/api/users/login") ||
			strings.HasPrefix(path, "/api/users/register") ||
			strings.HasPrefix(path, "/api/attestation/verify")

		// 3. Evaluate rate limit
		res := s.proxy.CheckRateLimit(clientIP, isSensitive)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(res.Limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(res.ResetTime.Unix(), 10))

		if !res.Allowed {
			retrySec := int(res.RetryAfter.Seconds())
			if retrySec < 1 {
				retrySec = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retrySec))
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":       "rate_limit_exceeded",
				"limit":       res.Limit,
				"retry_after": retrySec,
				"reset_time":  res.ResetTime,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// registerSecurityRoutes attaches M09 rate limiting, reputation, and audit export endpoints.
func (s *AppServer) registerSecurityRoutes(apiMux *http.ServeMux) {
	apiMux.HandleFunc("/api/security/ratelimit/status", s.handleRateLimitStatus)
	apiMux.HandleFunc("/api/security/reputation", s.handleReputationStatus)
	apiMux.HandleFunc("/api/security/bans", s.handleBans)
	apiMux.HandleFunc("/api/security/bans/unban", s.handleUnban)
	apiMux.HandleFunc("/api/security/audit/records", s.handleAuditRecords)
	apiMux.HandleFunc("/api/security/audit/export", s.handleAuditExport)
	apiMux.HandleFunc("/api/security/audit/verify", s.handleAuditVerify)
}

func (s *AppServer) handleRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"stats":  s.proxy.LimiterStats(),
	})
}

func (s *AppServer) handleReputationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"summary": s.proxy.GetReputationSummary(),
	})
}

func (s *AppServer) handleBans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "success",
			"bans":   s.proxy.ListBanned(),
		})
	case http.MethodPost:
		var req struct {
			Key             string `json:"key"`
			Reason          string `json:"reason"`
			DurationMinutes int    `json:"duration_minutes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
			return
		}
		if strings.TrimSpace(req.Key) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
			return
		}
		dur := 15 * time.Minute
		if req.DurationMinutes > 0 {
			dur = time.Duration(req.DurationMinutes) * time.Minute
		}
		reason := req.Reason
		if reason == "" {
			reason = "Manual restriction by administrator"
		}
		ban := s.proxy.ManualBan(req.Key, reason, dur)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "success",
			"ban":    ban,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *AppServer) handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
		return
	}
	unbanned := s.proxy.ManualUnban(key)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"key":      key,
		"unbanned": unbanned,
	})
}

func (s *AppServer) handleAuditRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}
	sev := r.URL.Query().Get("severity")
	evType := r.URL.Query().Get("event_type")

	records := s.proxy.ListAuditRecords(limit, sev, evType)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"count":   len(records),
		"records": records,
	})
}

func (s *AppServer) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SecretKey string `json:"secret_key"`
		Limit     int    `json:"limit"`
		Severity  string `json:"severity"`
		EventType string `json:"event_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 500
	}

	keyBytes := []byte(strings.TrimSpace(req.SecretKey))
	if len(keyBytes) == 0 {
		keyBytes = []byte("sheet-license-broker-default-audit-key")
	}

	bundle, err := s.proxy.ExportEncryptedAudit(keyBytes, limit, req.Severity, req.EventType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"bundle": bundle,
	})
}

func (s *AppServer) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Bundle    *audit.EncryptedAuditBundle `json:"bundle"`
		SecretKey string                      `json:"secret_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}
	if req.Bundle == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bundle is required"})
		return
	}

	keyBytes := []byte(strings.TrimSpace(req.SecretKey))
	if len(keyBytes) == 0 {
		keyBytes = []byte("sheet-license-broker-default-audit-key")
	}

	records, err := s.proxy.VerifyAuditBundle(req.Bundle, keyBytes)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"status":   "failed",
			"verified": false,
			"error":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"verified":     true,
		"record_count": len(records),
		"records":      records,
	})
}
