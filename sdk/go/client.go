package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/security"
	"github.com/kLauncher1/sheet-license-broker/internal/zkp"
)

// ErrLicenseInvalid indicates that the license key is expired, revoked, or device-mismatched.
var ErrLicenseInvalid = errors.New("license verification failed")

// LicenseRecord represents the underlying license entitlement model.
type LicenseRecord struct {
	Key          string   `json:"key"`
	CreatedAt    string   `json:"created_at"`
	ExpiresAt    string   `json:"expires_at"`
	Days         int      `json:"days"`
	MaxDevices   int      `json:"max_devices"`
	BoundDevices []string `json:"bound_devices"`
	Status       string   `json:"status"`
}

// ValidationResult represents response from /api/licenses/validate.
type ValidationResult struct {
	Valid    bool           `json:"valid"`
	Message  string         `json:"message,omitempty"`
	Error    string         `json:"error,omitempty"`
	Source   string         `json:"source,omitempty"`
	Tier     string         `json:"tier,omitempty"`
	Features []string       `json:"features,omitempty"`
	License  *LicenseRecord `json:"license,omitempty"`
}

// UsageRecord represents consumption telemetry for a metered metric.
type UsageRecord struct {
	Key       string `json:"key"`
	Metric    string `json:"metric"`
	Period    string `json:"period"`
	Count     int64  `json:"count"`
	Limit     int64  `json:"limit"`
	UpdatedAt string `json:"updated_at"`
}

// Client interacts with the sheet-license-broker HTTP API.
type Client struct {
	baseURL    string
	secretKey  []byte
	tenantID   string
	httpClient *http.Client
}

// NewClient initializes a new Sheet License Broker Go client.
func NewClient(baseURL string, secretKey []byte, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		secretKey: secretKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// WithTenant sets the tenant identifier for multi-tenant requests.
func (c *Client) WithTenant(tenantID string) *Client {
	c.tenantID = strings.TrimSpace(tenantID)
	return c
}

// GetMachineHWID extracts a stable, unique hardware identifier for the current machine.
func GetMachineHWID() string {
	var rawParts []string

	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-Command", "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID").Output()
		if err == nil && len(strings.TrimSpace(string(out))) > 8 {
			rawParts = append(rawParts, strings.TrimSpace(string(out)))
		}
	case "linux":
		for _, f := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			data, err := os.ReadFile(f)
			if err == nil && len(strings.TrimSpace(string(data))) > 0 {
				rawParts = append(rawParts, strings.TrimSpace(string(data)))
				break
			}
		}
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						rawParts = append(rawParts, strings.Trim(strings.TrimSpace(parts[1]), "\""))
						break
					}
				}
			}
		}
	}

	if len(rawParts) == 0 {
		host, _ := os.Hostname()
		rawParts = append(rawParts, host, runtime.GOARCH, fmt.Sprintf("%d", runtime.NumCPU()))
	}

	seed := strings.Join(rawParts, "|")
	sum := sha256.Sum256([]byte(seed))
	hexSum := strings.ToUpper(hex.EncodeToString(sum[:]))

	return fmt.Sprintf("HWID-%s-%s-%s-%s", hexSum[0:4], hexSum[4:8], hexSum[8:12], hexSum[12:16])
}

func (c *Client) request(ctx context.Context, method, path string, payload interface{}, target interface{}) error {
	url := fmt.Sprintf("%s%s", c.baseURL, path)
	var bodyBytes []byte
	if payload != nil {
		var err error
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to encode request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SheetLicenseClient-Go/0.5.0")
	if c.tenantID != "" {
		req.Header.Set("X-Tenant-ID", c.tenantID)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if len(c.secretKey) > 0 {
		ts := time.Now().Unix()
		nonceBytes := make([]byte, 16)
		_, _ = rand.Read(nonceBytes)
		nonce := hex.EncodeToString(nonceBytes)

		sig := security.Sign(c.secretKey, method, path, ts, nonce, bodyBytes)
		req.Header.Set(security.HeaderSignature, sig)
		req.Header.Set(security.HeaderTimestamp, fmt.Sprintf("%d", ts))
		req.Header.Set(security.HeaderNonce, nonce)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request execution failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%w: %s", ErrLicenseInvalid, string(respBody))
		}
		return fmt.Errorf("broker responded with status %d: %s", resp.StatusCode, string(respBody))
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return fmt.Errorf("failed to decode response JSON: %w", err)
		}
	}

	return nil
}

// VerifyLicense validates a license key against the broker.
func (c *Client) VerifyLicense(ctx context.Context, licenseKey, hwid string) (*ValidationResult, error) {
	if hwid == "" {
		hwid = GetMachineHWID()
	}

	req := map[string]string{
		"license_key": strings.TrimSpace(licenseKey),
		"hwid":        strings.TrimSpace(hwid),
	}

	var res ValidationResult
	if err := c.request(ctx, http.MethodPost, "/api/licenses/validate", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Health checks the status of the broker.
func (c *Client) Health(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/health", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// IsFeatureEnabled queries the broker to determine whether a feature is permitted.
func (c *Client) IsFeatureEnabled(ctx context.Context, licenseKey, feature string) (bool, string, error) {
	req := map[string]string{
		"license_key": strings.TrimSpace(licenseKey),
		"feature":     strings.TrimSpace(feature),
	}
	var res struct {
		Status  string `json:"status"`
		Enabled bool   `json:"enabled"`
		Tier    string `json:"tier"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/features/check", req, &res); err != nil {
		return false, "", err
	}
	return res.Enabled, res.Tier, nil
}

// RecordUsage reports resource consumption for a license key with optional limit check.
func (c *Client) RecordUsage(ctx context.Context, licenseKey, metric, period string, units, limit int64) (*UsageRecord, bool, error) {
	req := map[string]interface{}{
		"license_key": strings.TrimSpace(licenseKey),
		"metric":      strings.TrimSpace(metric),
		"period":      strings.TrimSpace(period),
		"units":       units,
		"limit":       limit,
	}
	var res struct {
		Status   string      `json:"status"`
		Record   UsageRecord `json:"record"`
		Exceeded bool        `json:"exceeded"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/usage/record", req, &res); err != nil {
		return nil, false, err
	}
	return &res.Record, res.Exceeded, nil
}

// GetUsage retrieves all recorded usage records for a license key.
func (c *Client) GetUsage(ctx context.Context, licenseKey string) ([]UsageRecord, error) {
	path := fmt.Sprintf("/api/usage/stats?license_key=%s", strings.TrimSpace(licenseKey))
	var res struct {
		Status  string        `json:"status"`
		Records []UsageRecord `json:"records"`
	}
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res.Records, nil
}

// RequestAttestationChallenge obtains a fresh single-use random nonce challenge from the broker.
func (c *Client) RequestAttestationChallenge(ctx context.Context, licenseKey, hwid string) (challengeID, nonce, expiresAt string, err error) {
	req := map[string]string{
		"license_key": strings.TrimSpace(licenseKey),
		"hwid":        strings.TrimSpace(hwid),
	}
	var res struct {
		Status      string `json:"status"`
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/attestation/challenge", req, &res); err != nil {
		return "", "", "", err
	}
	return res.ChallengeID, res.Nonce, res.ExpiresAt, nil
}

// VerifyTPMAttestation submits a signed TPM 2.0 PCR quote to attest hardware integrity.
func (c *Client) VerifyTPMAttestation(ctx context.Context, licenseKey, hwid, challengeID string, quote interface{}) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"license_key":      strings.TrimSpace(licenseKey),
		"hwid":             strings.TrimSpace(hwid),
		"challenge_id":     strings.TrimSpace(challengeID),
		"attestation_type": "tpm2",
		"tpm_quote":        quote,
	}
	var res struct {
		Status string                 `json:"status"`
		Record map[string]interface{} `json:"record"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/attestation/verify", req, &res); err != nil {
		return nil, err
	}
	return res.Record, nil
}

// ReportTelemetry transmits anti-debug and memory integrity telemetry to the broker.
func (c *Client) ReportTelemetry(ctx context.Context, licenseKey, hwid string, report interface{}) (int, bool, string, error) {
	req := map[string]interface{}{
		"license_key": strings.TrimSpace(licenseKey),
		"hwid":        strings.TrimSpace(hwid),
		"report":      report,
	}
	var res struct {
		Status      string `json:"status"`
		TamperScore int    `json:"tamper_score"`
		Tampered    bool   `json:"tampered"`
		TrustLevel  string `json:"trust_level"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/attestation/telemetry", req, &res); err != nil {
		return 0, false, "", err
	}
	return res.TamperScore, res.Tampered, res.TrustLevel, nil
}

// ExportAuditToken requests an encrypted audit bundle for enterprise compliance auditing pipelines.
func (c *Client) ExportAuditToken(ctx context.Context, secretKey string, limit int) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"secret_key": secretKey,
		"limit":      limit,
	}
	var res struct {
		Status string                 `json:"status"`
		Bundle map[string]interface{} `json:"bundle"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/security/audit/export", req, &res); err != nil {
		return nil, err
	}
	return res.Bundle, nil
}

// GetClusterStatus queries the broker's distributed Raft role and quorum health.
func (c *Client) GetClusterStatus(ctx context.Context) (map[string]interface{}, error) {
	var status map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/consensus/status", nil, &status); err != nil {
		return nil, err
	}
	return status, nil
}

// GetClusterPeers returns the list of active peer nodes in the consensus mesh.
func (c *Client) GetClusterPeers(ctx context.Context) ([]map[string]interface{}, error) {
	var res struct {
		Status string                   `json:"status"`
		Peers  []map[string]interface{} `json:"peers"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/consensus/peers", nil, &res); err != nil {
		return nil, err
	}
	return res.Peers, nil
}

// GetStreamClients queries active WebSocket telemetry client sessions.
func (c *Client) GetStreamClients(ctx context.Context) ([]map[string]interface{}, error) {
	var res struct {
		Status  string                   `json:"status"`
		Count   int                      `json:"count"`
		Clients []map[string]interface{} `json:"clients"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/stream/clients", nil, &res); err != nil {
		return nil, err
	}
	return res.Clients, nil
}

// SendKillSwitch dispatches an instantaneous remote kill directive to matching clients.
func (c *Client) SendKillSwitch(ctx context.Context, target, reason string, immediate bool) (int, error) {
	req := map[string]interface{}{
		"target":    target,
		"reason":    reason,
		"immediate": immediate,
	}
	var res struct {
		Status          string `json:"status"`
		SignaledClients int    `json:"signaled_clients"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/stream/kill", req, &res); err != nil {
		return 0, err
	}
	return res.SignaledClients, nil
}

// GetStreamTelemetry queries aggregate streaming telemetry and active client metrics.
func (c *Client) GetStreamTelemetry(ctx context.Context) (map[string]interface{}, error) {
	var res struct {
		Status    string                 `json:"status"`
		Telemetry map[string]interface{} `json:"telemetry"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/stream/telemetry", nil, &res); err != nil {
		return nil, err
	}
	return res.Telemetry, nil
}

// GetZKPParams fetches the public elliptic curve parameters and issuer public key.
func (c *Client) GetZKPParams(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/zkp/params", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// IssueAnonymousCredential requests an issuer-signed zero-knowledge credential.
func (c *Client) IssueAnonymousCredential(
	ctx context.Context,
	licenseKey string,
	hwid string,
	tier string,
	validDays int,
	scope string,
) (*zkp.AnonymousCredential, *big.Int, error) {
	if hwid == "" {
		hwid = GetMachineHWID()
	}
	req := map[string]interface{}{
		"license_key": licenseKey,
		"hwid":        hwid,
		"tier":        tier,
		"valid_days":  validDays,
		"scope":       scope,
		"tenant_id":   c.tenantID,
	}
	var res struct {
		Status         string                   `json:"status"`
		Credential     *zkp.AnonymousCredential `json:"credential"`
		BlindingFactor string                   `json:"blinding_factor"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/zkp/credential/issue", req, &res); err != nil {
		return nil, nil, err
	}
	var rScalar *big.Int
	if res.BlindingFactor != "" {
		var ok bool
		rScalar, ok = new(big.Int).SetString(res.BlindingFactor, 16)
		if !ok {
			return nil, nil, fmt.Errorf("failed to parse blinding factor from response")
		}
	}
	return res.Credential, rScalar, nil
}

// VerifyZKPProof submits a zero-knowledge presentation proof for entitlement access.
func (c *Client) VerifyZKPProof(
	ctx context.Context,
	proof *zkp.ZKPProof,
	requiredTier string,
	epoch int64,
) (*zkp.VerificationResult, error) {
	req := map[string]interface{}{
		"proof":         proof,
		"required_tier": requiredTier,
		"epoch":         epoch,
	}
	var res struct {
		Status  string                  `json:"status"`
		Valid   bool                    `json:"valid"`
		Details *zkp.VerificationResult `json:"details"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/zkp/verify", req, &res); err != nil {
		return nil, err
	}
	return res.Details, nil
}

// GetZKPStatus queries overall telemetry metrics on zero-knowledge verification.
func (c *Client) GetZKPStatus(ctx context.Context) (map[string]interface{}, error) {
	var res struct {
		Status string                 `json:"status"`
		ZKP    map[string]interface{} `json:"zkp"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/zkp/status", nil, &res); err != nil {
		return nil, err
	}
	return res.ZKP, nil
}

