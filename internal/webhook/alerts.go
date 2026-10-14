package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/metrics"
)

// SecuritySeverity represents the severity level of an alert.
type SecuritySeverity string

const (
	SeverityInfo     SecuritySeverity = "INFO"
	SeverityWarning  SecuritySeverity = "WARNING"
	SeverityCritical SecuritySeverity = "CRITICAL"
)

// SecurityAlert represents an actionable security incident.
type SecurityAlert struct {
	ID        string           `json:"id"`
	Type      string           `json:"type"` // e.g. "replay_attack", "tamper_detected", "device_banned", "failover_event"
	Severity  SecuritySeverity `json:"severity"`
	TenantID  string           `json:"tenant_id,omitempty"`
	Target    string           `json:"target,omitempty"` // HWID or License Key
	IPAddress string           `json:"ip_address,omitempty"`
	Summary   string           `json:"summary"`
	Details   string           `json:"details,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// FormatDiscordPayload generates Discord webhook JSON with rich embeds.
func FormatDiscordPayload(alert SecurityAlert) ([]byte, error) {
	color := 0x3B82F6 // Blue for Info
	switch alert.Severity {
	case SeverityWarning:
		color = 0xF59E0B // Amber
	case SeverityCritical:
		color = 0xDC2626 // Red
	}

	fields := []map[string]interface{}{
		{"name": "Alert Type", "value": alert.Type, "inline": true},
		{"name": "Severity", "value": string(alert.Severity), "inline": true},
	}
	if alert.TenantID != "" {
		fields = append(fields, map[string]interface{}{"name": "Tenant", "value": alert.TenantID, "inline": true})
	}
	if alert.Target != "" {
		fields = append(fields, map[string]interface{}{"name": "Target / HWID", "value": alert.Target, "inline": true})
	}
	if alert.IPAddress != "" {
		fields = append(fields, map[string]interface{}{"name": "Origin IP", "value": alert.IPAddress, "inline": true})
	}
	if alert.Details != "" {
		fields = append(fields, map[string]interface{}{"name": "Details", "value": alert.Details, "inline": false})
	}

	payload := map[string]interface{}{
		"username": "Sheet License Security Guard",
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("[%s] %s", alert.Severity, alert.Summary),
				"description": fmt.Sprintf("Incident ID: `%s`", alert.ID),
				"color":       color,
				"fields":      fields,
				"timestamp":   alert.Timestamp.Format(time.RFC3339),
				"footer": map[string]string{
					"text": "sheet-license-broker anti-tamper telemetry",
				},
			},
		},
	}

	return json.Marshal(payload)
}

// FormatSlackPayload generates Slack Incoming Webhook JSON blocks.
func FormatSlackPayload(alert SecurityAlert) ([]byte, error) {
	headerText := fmt.Sprintf(":shield: [%s] %s", alert.Severity, alert.Summary)
	fields := []map[string]string{
		{"type": "mrkdwn", "text": fmt.Sprintf("*Type:*\n%s", alert.Type)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:*\n%s", alert.Severity)},
	}
	if alert.TenantID != "" {
		fields = append(fields, map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*Tenant:*\n%s", alert.TenantID)})
	}
	if alert.Target != "" {
		fields = append(fields, map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*Target:*\n`%s`", alert.Target)})
	}
	if alert.IPAddress != "" {
		fields = append(fields, map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*Origin IP:*\n`%s`", alert.IPAddress)})
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": headerText,
			},
		},
		{
			"type":   "section",
			"fields": fields,
		},
	}
	if alert.Details != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Details:*\n%s", alert.Details),
			},
		})
	}

	payload := map[string]interface{}{
		"text":   headerText,
		"blocks": blocks,
	}

	return json.Marshal(payload)
}

// SendDiscordAlert posts a security alert directly to a Discord webhook URL.
func SendDiscordAlert(ctx context.Context, client *http.Client, webhookURL string, alert SecurityAlert) error {
	if webhookURL == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	data, err := FormatDiscordPayload(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook rejected with status: %d", resp.StatusCode)
	}

	metrics.RecordSecurityIncident("discord_alert_dispatched")
	return nil
}

// SendSlackAlert posts a security alert directly to a Slack Incoming Webhook URL.
func SendSlackAlert(ctx context.Context, client *http.Client, webhookURL string, alert SecurityAlert) error {
	if webhookURL == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	data, err := FormatSlackPayload(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook rejected with status: %d", resp.StatusCode)
	}

	metrics.RecordSecurityIncident("slack_alert_dispatched")
	return nil
}
