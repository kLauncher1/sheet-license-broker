package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/transparency"
)

type transparencyAppendResponse struct {
	Status string                       `json:"status"`
	Entry  *transparency.LogEntry       `json:"entry"`
	STH    *transparency.SignedTreeHead `json:"sth"`
}

type transparencyEntriesResponse struct {
	Start   int64                    `json:"start"`
	Count   int                      `json:"count"`
	Entries []*transparency.LogEntry `json:"entries"`
}

type transparencyVerifyProofResponse struct {
	Verified bool `json:"verified"`
}

type transparencyWitnessesResponse struct {
	Witnesses []string `json:"witnesses"`
	Count     int      `json:"count"`
}

// GetTransparencyStatus queries real-time status and operational health of the transparency log.
func (c *Client) GetTransparencyStatus(ctx context.Context) (*transparency.TransparencyStatus, error) {
	var res transparency.TransparencyStatus
	if err := c.request(ctx, http.MethodGet, "/api/transparency/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// AppendTransparencyEntry appends an audit record to the transparency log and returns the updated STH.
func (c *Client) AppendTransparencyEntry(ctx context.Context, action, tenantID string, payload interface{}) (*transparency.LogEntry, *transparency.SignedTreeHead, error) {
	reqBody := map[string]interface{}{
		"action":    action,
		"tenant_id": tenantID,
		"payload":   payload,
	}
	var res transparencyAppendResponse
	if err := c.request(ctx, http.MethodPost, "/api/transparency/append", reqBody, &res); err != nil {
		return nil, nil, err
	}
	return res.Entry, res.STH, nil
}

// GetTransparencySTH queries the current Signed Tree Head.
func (c *Client) GetTransparencySTH(ctx context.Context) (*transparency.SignedTreeHead, error) {
	var res transparency.SignedTreeHead
	if err := c.request(ctx, http.MethodGet, "/api/transparency/sth", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetTransparencyEntries queries a range of log entries from start up to count records.
func (c *Client) GetTransparencyEntries(ctx context.Context, start, count int64) ([]*transparency.LogEntry, error) {
	path := fmt.Sprintf("/api/transparency/entries?start=%d&count=%d", start, count)
	var res transparencyEntriesResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res.Entries, nil
}

// GetTransparencyInclusionProof generates an RFC 6962 audit path proving leaf inclusion.
func (c *Client) GetTransparencyInclusionProof(ctx context.Context, index, treeSize int64) (*transparency.InclusionProof, error) {
	path := fmt.Sprintf("/api/transparency/inclusion-proof?index=%d&tree_size=%d", index, treeSize)
	var res transparency.InclusionProof
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// VerifyTransparencyInclusionProof cryptographically checks an inclusion proof payload.
func (c *Client) VerifyTransparencyInclusionProof(ctx context.Context, proof *transparency.InclusionProof) (bool, error) {
	var res transparencyVerifyProofResponse
	if err := c.request(ctx, http.MethodPost, "/api/transparency/inclusion-proof/verify", proof, &res); err != nil {
		return false, err
	}
	return res.Verified, nil
}

// GetTransparencyConsistencyProof generates RFC 6962 intermediate hashes proving append-only consistency.
func (c *Client) GetTransparencyConsistencyProof(ctx context.Context, first, second int64) (*transparency.ConsistencyProof, error) {
	path := fmt.Sprintf("/api/transparency/consistency-proof?first=%d&second=%d", first, second)
	var res transparency.ConsistencyProof
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// VerifyTransparencyConsistencyProof cryptographically checks a consistency proof payload.
func (c *Client) VerifyTransparencyConsistencyProof(ctx context.Context, proof *transparency.ConsistencyProof) (bool, error) {
	var res transparencyVerifyProofResponse
	if err := c.request(ctx, http.MethodPost, "/api/transparency/consistency-proof/verify", proof, &res); err != nil {
		return false, err
	}
	return res.Verified, nil
}

// CosignTransparencySTH requests an independent witness co-signature on the active STH.
func (c *Client) CosignTransparencySTH(ctx context.Context, witnessID string) (*transparency.WitnessSignature, error) {
	reqBody := map[string]string{"witness_id": witnessID}
	var res transparency.WitnessSignature
	if err := c.request(ctx, http.MethodPost, "/api/transparency/witness/cosign", reqBody, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListTransparencyWitnesses retrieves the list of registered witness node identifiers.
func (c *Client) ListTransparencyWitnesses(ctx context.Context) ([]string, error) {
	var res transparencyWitnessesResponse
	if err := c.request(ctx, http.MethodGet, "/api/transparency/witnesses", nil, &res); err != nil {
		return nil, err
	}
	return res.Witnesses, nil
}
