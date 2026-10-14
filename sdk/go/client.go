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
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/security"
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
	Valid   bool           `json:"valid"`
	Message string         `json:"message,omitempty"`
	Error   string         `json:"error,omitempty"`
	Source  string         `json:"source,omitempty"`
	License *LicenseRecord `json:"license,omitempty"`
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
