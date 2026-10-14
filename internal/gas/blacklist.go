package gas

import (
	"context"
	"encoding/json"
	"fmt"
)

// BlacklistEntryResponse represents a single blacklist row.
type BlacklistEntryResponse struct {
	Type      string `json:"type"`
	Target    string `json:"target"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

// BlacklistListResponse represents the list of blacklist rows returned from Apps Script.
type BlacklistListResponse struct {
	Status  string                   `json:"status"`
	Entries []BlacklistEntryResponse `json:"entries"`
	Message string                   `json:"message,omitempty"`
}

// BlacklistActionResponse represents the result of adding, removing, or revoking.
type BlacklistActionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
	Target  string `json:"target,omitempty"`
}

// RevokeLicense remotely revokes a license key in Google Sheets.
func (c *Client) RevokeLicense(ctx context.Context, licenseKey, reason string) (*BlacklistActionResponse, error) {
	raw, err := c.postAction(ctx, "revoke_license", map[string]interface{}{
		"license_key": licenseKey,
		"reason":      reason,
	})
	if err != nil {
		return nil, err
	}
	var res BlacklistActionResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("revoke license error: %s", res.Message)
	}
	return &res, nil
}

// BlacklistAdd inserts or updates a blacklist entry in Google Sheets.
func (c *Client) BlacklistAdd(ctx context.Context, entryType, target, reason string) (*BlacklistActionResponse, error) {
	raw, err := c.postAction(ctx, "blacklist_add", map[string]interface{}{
		"type":   entryType,
		"target": target,
		"reason": reason,
	})
	if err != nil {
		return nil, err
	}
	var res BlacklistActionResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("blacklist add error: %s", res.Message)
	}
	return &res, nil
}

// BlacklistRemove clears a blacklist entry from Google Sheets.
func (c *Client) BlacklistRemove(ctx context.Context, entryType, target string) (*BlacklistActionResponse, error) {
	raw, err := c.postAction(ctx, "blacklist_remove", map[string]interface{}{
		"type":   entryType,
		"target": target,
	})
	if err != nil {
		return nil, err
	}
	var res BlacklistActionResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("blacklist remove error: %s", res.Message)
	}
	return &res, nil
}

// BlacklistList retrieves all blacklist entries from Google Sheets.
func (c *Client) BlacklistList(ctx context.Context) (*BlacklistListResponse, error) {
	raw, err := c.postAction(ctx, "blacklist_list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var res BlacklistListResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	if res.Status != "success" {
		return &res, fmt.Errorf("blacklist list error: %s", res.Message)
	}
	return &res, nil
}
