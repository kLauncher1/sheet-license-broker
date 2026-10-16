package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/anomaly"
)

// RecordAnomalyObservation submits client heartbeat, location, or telemetry to the behavioral anomaly engine.
func (c *Client) RecordAnomalyObservation(ctx context.Context, obs anomaly.ClientObservation) (*anomaly.RiskScore, error) {
	if obs.HWID == "" {
		obs.HWID = GetMachineHWID()
	}
	var res struct {
		Status    string             `json:"status"`
		RiskScore *anomaly.RiskScore `json:"risk_score"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/anomaly/record", obs, &res); err != nil {
		return nil, err
	}
	return res.RiskScore, nil
}

// GetAnomalyRiskScore queries the current adaptive risk score and factors for an entity.
func (c *Client) GetAnomalyRiskScore(ctx context.Context, licenseKey, hwid string) (*anomaly.RiskScore, error) {
	if hwid == "" && licenseKey == "" {
		hwid = GetMachineHWID()
	}
	endpoint := fmt.Sprintf("/api/anomaly/score?license_key=%s&hwid=%s", licenseKey, hwid)
	var res anomaly.RiskScore
	if err := c.request(ctx, http.MethodGet, endpoint, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// IssueAnomalyChallenge manually requests a re-attestation challenge token.
func (c *Client) IssueAnomalyChallenge(ctx context.Context, licenseKey, hwid string) (string, *anomaly.RiskScore, error) {
	if hwid == "" {
		hwid = GetMachineHWID()
	}
	req := map[string]string{
		"license_key": licenseKey,
		"hwid":        hwid,
	}
	var res struct {
		Status         string             `json:"status"`
		ChallengeToken string             `json:"challenge_token"`
		RiskScore      *anomaly.RiskScore `json:"risk_score"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/anomaly/challenge/issue", req, &res); err != nil {
		return "", nil, err
	}
	return res.ChallengeToken, res.RiskScore, nil
}

// VerifyAnomalyChallenge submits a challenge token to clear escalation penalties.
func (c *Client) VerifyAnomalyChallenge(ctx context.Context, challengeToken string) (*anomaly.RiskScore, error) {
	req := map[string]string{
		"challenge_token": challengeToken,
	}
	var res struct {
		Status    string             `json:"status"`
		Valid     bool               `json:"valid"`
		RiskScore *anomaly.RiskScore `json:"risk_score"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/anomaly/challenge/verify", req, &res); err != nil {
		return nil, err
	}
	return res.RiskScore, nil
}

// ExportIncidentGraph retrieves a SIEM topology graph filtered by criteria.
func (c *Client) ExportIncidentGraph(ctx context.Context, minScore, limit int) (*anomaly.IncidentGraph, error) {
	endpoint := fmt.Sprintf("/api/anomaly/graph?min_score=%d&limit=%d", minScore, limit)
	var res anomaly.IncidentGraph
	if err := c.request(ctx, http.MethodGet, endpoint, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetAnomalyStatus queries real-time operational telemetry for the anomaly engine.
func (c *Client) GetAnomalyStatus(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/anomaly/status", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}
