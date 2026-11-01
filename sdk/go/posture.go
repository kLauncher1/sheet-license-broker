package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/posture"
)

type quarantineListResponse struct {
	TenantID    string                      `json:"tenant_id"`
	Quarantined []posture.QuarantinedDevice `json:"quarantined"`
	Count       int                         `json:"count"`
}

type quarantineReleaseResponse struct {
	Status    string `json:"status"`
	DeviceID  string `json:"device_id"`
	TenantID  string `json:"tenant_id"`
	Timestamp string `json:"timestamp"`
}

type stepUpVerifyResponse struct {
	Status      string `json:"status"`
	ChallengeID string `json:"challenge_id"`
	VerifiedAt  string `json:"verified_at"`
}

type devicePostureResponse struct {
	Scores      posture.PostureVectorScores `json:"scores"`
	Quarantined bool                        `json:"quarantined"`
	Quarantine  *posture.QuarantinedDevice  `json:"quarantine"`
}

// GetPostureStatus queries real-time status and telemetry for the posture evaluation engine.
func (c *Client) GetPostureStatus(ctx context.Context) (*posture.PostureStatus, error) {
	var res posture.PostureStatus
	if err := c.request(ctx, http.MethodGet, "/api/posture/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// EvaluateDevicePosture submits client device telemetry and evaluates security posture.
func (c *Client) EvaluateDevicePosture(ctx context.Context, report posture.DevicePostureReport) (*posture.PostureVectorScores, error) {
	var res posture.PostureVectorScores
	if err := c.request(ctx, http.MethodPost, "/api/posture/evaluate", report, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetQuarantinedDevices returns list of quarantined devices, optionally filtered by tenant.
func (c *Client) GetQuarantinedDevices(ctx context.Context, tenantID string) ([]posture.QuarantinedDevice, error) {
	path := "/api/posture/quarantine"
	if tenantID != "" {
		path = fmt.Sprintf("/api/posture/quarantine?tenant_id=%s", tenantID)
	}
	var res quarantineListResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res.Quarantined, nil
}

// ReleaseDeviceQuarantine requests removal of an endpoint from the quarantine isolation table.
func (c *Client) ReleaseDeviceQuarantine(ctx context.Context, tenantID, deviceID string) (bool, error) {
	reqBody := map[string]string{
		"tenant_id": tenantID,
		"device_id": deviceID,
	}
	var res quarantineReleaseResponse
	if err := c.request(ctx, http.MethodPost, "/api/posture/quarantine/release", reqBody, &res); err != nil {
		return false, err
	}
	return res.Status == "released", nil
}

// IssueDeviceStepUpChallenge requests a time-bound step-up authentication challenge for remediation.
func (c *Client) IssueDeviceStepUpChallenge(ctx context.Context, tenantID, deviceID string, actions []string) (*posture.StepUpChallenge, error) {
	reqBody := map[string]interface{}{
		"tenant_id": tenantID,
		"device_id": deviceID,
		"actions":   actions,
	}
	var res posture.StepUpChallenge
	if err := c.request(ctx, http.MethodPost, "/api/posture/step-up/challenge", reqBody, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// VerifyDeviceStepUpChallenge submits challenge nonce proof for step-up elevation.
func (c *Client) VerifyDeviceStepUpChallenge(ctx context.Context, challengeID, nonce string) (bool, error) {
	reqBody := map[string]string{
		"challenge_id": challengeID,
		"nonce":        nonce,
	}
	var res stepUpVerifyResponse
	if err := c.request(ctx, http.MethodPost, "/api/posture/step-up/verify", reqBody, &res); err != nil {
		return false, err
	}
	return res.Status == "verified", nil
}

// GetDevicePosture queries latest posture score and quarantine status for an endpoint.
func (c *Client) GetDevicePosture(ctx context.Context, tenantID, deviceID string) (*posture.PostureVectorScores, bool, error) {
	path := fmt.Sprintf("/api/posture/device?tenant_id=%s&device_id=%s", tenantID, deviceID)
	var res devicePostureResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, false, err
	}
	return &res.Scores, res.Quarantined, nil
}
