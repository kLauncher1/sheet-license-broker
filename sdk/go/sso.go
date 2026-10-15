package sdk

import (
	"context"
	"fmt"
	"net/http"
)

// GetSSOStatus queries telemetry for SSO identity providers and SCIM directory users.
func (c *Client) GetSSOStatus(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/sso/status", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// IntrospectSessionToken validates an ephemeral session token and evaluates permissions.
func (c *Client) IntrospectSessionToken(ctx context.Context, token, requiredScope string) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"token":          token,
		"required_scope": requiredScope,
	}
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodPost, "/api/sso/token/introspect", req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// ListSCIMUsers queries the SCIM 2.0 directory users list with pagination.
func (c *Client) ListSCIMUsers(ctx context.Context, startIndex, count int) (map[string]interface{}, error) {
	if startIndex <= 0 {
		startIndex = 1
	}
	if count <= 0 {
		count = 50
	}
	path := fmt.Sprintf("/scim/v2/Users?startIndex=%d&count=%d", startIndex, count)
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}
