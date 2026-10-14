package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFormatDiscordPayload(t *testing.T) {
	alert := SecurityAlert{
		ID:        "sec-001",
		Type:      "tamper_detected",
		Severity:  SeverityCritical,
		TenantID:  "CORP",
		Target:    "HWID-BANNED-DEVICE",
		IPAddress: "203.0.113.195",
		Summary:   "Invalid HMAC signature on license verification",
		Details:   "Signature mismatch after 3 repeated attempts",
		Timestamp: time.Now(),
	}

	payloadBytes, err := FormatDiscordPayload(alert)
	if err != nil {
		t.Fatalf("failed to format discord payload: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &parsed); err != nil {
		t.Fatalf("failed to parse formatted json: %v", err)
	}

	embeds := parsed["embeds"].([]interface{})
	if len(embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(embeds))
	}

	embed := embeds[0].(map[string]interface{})
	if embed["color"].(float64) != float64(0xDC2626) {
		t.Errorf("expected critical red color (0xDC2626), got %v", embed["color"])
	}
	if !strings.Contains(embed["title"].(string), "CRITICAL") {
		t.Errorf("expected CRITICAL in title, got %s", embed["title"])
	}
}

func TestFormatSlackPayload(t *testing.T) {
	alert := SecurityAlert{
		ID:        "sec-002",
		Type:      "replay_attack",
		Severity:  SeverityWarning,
		TenantID:  "SAAS",
		Target:    "NONCE-DUP-XYZ",
		IPAddress: "198.51.100.42",
		Summary:   "Replay attack detected with duplicate nonce",
		Timestamp: time.Now(),
	}

	payloadBytes, err := FormatSlackPayload(alert)
	if err != nil {
		t.Fatalf("failed to format slack payload: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &parsed); err != nil {
		t.Fatalf("failed to parse slack json: %v", err)
	}

	blocks := parsed["blocks"].([]interface{})
	if len(blocks) < 2 {
		t.Fatalf("expected at least 2 blocks, got %d", len(blocks))
	}
}

func TestSendDiscordAndSlackAlerts(t *testing.T) {
	discordReceived := false
	discordServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "Sheet License Security Guard") {
			discordReceived = true
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discordServer.Close()

	slackReceived := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "replay_attack") {
			slackReceived = true
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer slackServer.Close()

	alert := SecurityAlert{
		ID:        "sec-test",
		Type:      "replay_attack",
		Severity:  SeverityWarning,
		Summary:   "Replay detected in test suite",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	client := discordServer.Client()

	err := SendDiscordAlert(ctx, client, discordServer.URL, alert)
	if err != nil {
		t.Fatalf("SendDiscordAlert failed: %v", err)
	}
	if !discordReceived {
		t.Errorf("Discord server did not receive expected alert body")
	}

	err = SendSlackAlert(ctx, client, slackServer.URL, alert)
	if err != nil {
		t.Fatalf("SendSlackAlert failed: %v", err)
	}
	if !slackReceived {
		t.Errorf("Slack server did not receive expected alert body")
	}
}
