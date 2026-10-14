package gas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrEmptyURL        = errors.New("google apps script web app url is required")
	ErrRateLimited     = errors.New("rate limited by google apps script (http 429)")
	ErrServiceDown     = errors.New("google apps script service unavailable")
	ErrInvalidResponse = errors.New("invalid response from google apps script")
)

// Client handles communication with a deployed Google Apps Script Web App.
type Client struct {
	webAppURL   string
	httpClient  *http.Client
	timeout     time.Duration
	maxRetries  int
	backoffBase time.Duration
}

// ClientConfig holds configuration parameters for Google Apps Script client.
type ClientConfig struct {
	WebAppURL   string
	Timeout     time.Duration
	MaxRetries  int
	BackoffBase time.Duration
}

// PingResponse represents the response from ping action.
type PingResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// RegisterResponse represents registration outcome.
type RegisterResponse struct {
	Status   string `json:"status"`
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	Message  string `json:"message,omitempty"`
}

// LoginResponse represents authentication outcome.
type LoginResponse struct {
	Status   string `json:"status"`
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	Role     string `json:"role,omitempty"`
	Message  string `json:"message,omitempty"`
}

// LicenseResponse represents license generation response.
type LicenseResponse struct {
	Status     string `json:"status"`
	LicenseKey string `json:"license_key,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Message    string `json:"message,omitempty"`
}

// VerifyResponse represents license verification with HWID binding outcome.
type VerifyResponse struct {
	Status      string `json:"status"`
	Verified    bool   `json:"verified,omitempty"`
	HWIDBound   string `json:"hwid_bound,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Message     string `json:"message,omitempty"`
	LicenseKey  string `json:"license_key,omitempty"`
	Blacklisted bool   `json:"blacklisted,omitempty"`
	Revoked     bool   `json:"revoked,omitempty"`
}

// DocResponse represents NoSQL KV document operation result.
type DocResponse struct {
	Status     string      `json:"status"`
	Action     string      `json:"action,omitempty"`
	Collection string      `json:"collection,omitempty"`
	DocID      string      `json:"doc_id,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	UpdatedAt  string      `json:"updated_at,omitempty"`
	Message    string      `json:"message,omitempty"`
}

// NewClient initializes a Google Apps Script client with reasonable retry policies.
func NewClient(cfg ClientConfig) (*Client, error) {
	url := strings.TrimSpace(cfg.WebAppURL)
	if url == "" {
		return nil, ErrEmptyURL
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	backoff := cfg.BackoffBase
	if backoff <= 0 {
		backoff = 250 * time.Millisecond
	}

	return &Client{
		webAppURL: url,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				return nil
			},
		},
		timeout:     timeout,
		maxRetries:  maxRetries,
		backoffBase: backoff,
	}, nil
}

// WebAppURL returns the target Google Apps Script URL.
func (c *Client) WebAppURL() string {
	return c.webAppURL
}

func (c *Client) postAction(ctx context.Context, action string, payload map[string]interface{}) ([]byte, error) {
	if payload == nil {
		payload = make(map[string]interface{})
	}
	payload["action"] = action

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload error: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		if attempt > 0 {
			sleepDur := c.backoffBase * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(sleepDur):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webAppURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("create http request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = ErrRateLimited
			continue
		}

		if resp.StatusCode >= 500 && resp.StatusCode <= 504 {
			lastErr = fmt.Errorf("%w (code: %d)", ErrServiceDown, resp.StatusCode)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		return respBody, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.maxRetries, lastErr)
}

// Ping verifies connectivity with the Google Apps Script Web App.
func (c *Client) Ping(ctx context.Context) (*PingResponse, error) {
	raw, err := c.postAction(ctx, "ping", nil)
	if err != nil {
		return nil, err
	}
	var res PingResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	return &res, nil
}

// RegisterUser registers a new user in the remote Users sheet tab.
func (c *Client) RegisterUser(ctx context.Context, username, password string) (*RegisterResponse, error) {
	raw, err := c.postAction(ctx, "register", map[string]interface{}{
		"username": username,
		"password": password,
	})
	if err != nil {
		return nil, err
	}
	var res RegisterResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("register error: %s", res.Message)
	}
	return &res, nil
}

// LoginUser validates credentials against the remote Users sheet tab.
func (c *Client) LoginUser(ctx context.Context, username, password string) (*LoginResponse, error) {
	raw, err := c.postAction(ctx, "login", map[string]interface{}{
		"username": username,
		"password": password,
	})
	if err != nil {
		return nil, err
	}
	var res LoginResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("login error: %s", res.Message)
	}
	return &res, nil
}

// CreateLicense issues an entitlement key stored in the remote Licenses sheet.
func (c *Client) CreateLicense(ctx context.Context, key string, days, maxDevices int) (*LicenseResponse, error) {
	raw, err := c.postAction(ctx, "create_license", map[string]interface{}{
		"license_key": key,
		"days":        days,
		"max_devices": maxDevices,
	})
	if err != nil {
		return nil, err
	}
	var res LicenseResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("create license error: %s", res.Message)
	}
	return &res, nil
}

// VerifyLicense validates a license key and binds it to machine HWID in Google Sheets.
func (c *Client) VerifyLicense(ctx context.Context, key, hwid string) (*VerifyResponse, error) {
	raw, err := c.postAction(ctx, "verify_license", map[string]interface{}{
		"license_key": key,
		"hwid":        hwid,
	})
	if err != nil {
		return nil, err
	}
	var res VerifyResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	res.LicenseKey = key
	if res.Status != "success" || !res.Verified {
		return &res, fmt.Errorf("verify license failed: %s", res.Message)
	}
	return &res, nil
}

// PutDocument persists a key-value document into KV_Database sheet.
func (c *Client) PutDocument(ctx context.Context, collection, docID string, data interface{}) (*DocResponse, error) {
	raw, err := c.postAction(ctx, "db_put", map[string]interface{}{
		"collection": collection,
		"doc_id":      docID,
		"data":        data,
	})
	if err != nil {
		return nil, err
	}
	var res DocResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("put document error: %s", res.Message)
	}
	return &res, nil
}

// GetDocument retrieves a document by collection and doc_id from KV_Database sheet.
func (c *Client) GetDocument(ctx context.Context, collection, docID string) (*DocResponse, error) {
	raw, err := c.postAction(ctx, "db_get", map[string]interface{}{
		"collection": collection,
		"doc_id":      docID,
	})
	if err != nil {
		return nil, err
	}
	var res DocResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("get document error: %s", res.Message)
	}
	return &res, nil
}
