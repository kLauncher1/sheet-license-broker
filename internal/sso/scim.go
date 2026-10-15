package sso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DeprovisionHook defines a callback invoked when a directory user is deprovisioned.
type DeprovisionHook func(ctx context.Context, user *SCIMUser, reason string) error

// ProvisionHook defines a callback invoked when a directory user is newly provisioned.
type ProvisionHook func(ctx context.Context, user *SCIMUser) error

// SCIMDirectory manages SCIM 2.0 user resources with lifecycle event hooks.
type SCIMDirectory struct {
	mu             sync.RWMutex
	users          map[string]*SCIMUser // key: user.ID
	userNames      map[string]string    // key: lower(userName) -> user.ID
	onProvision    ProvisionHook
	onDeprovision  DeprovisionHook
	allocatedSeats int
}

// NewSCIMDirectory initializes a new SCIM directory engine.
func NewSCIMDirectory(onProvision ProvisionHook, onDeprovision DeprovisionHook) *SCIMDirectory {
	return &SCIMDirectory{
		users:         make(map[string]*SCIMUser),
		userNames:     make(map[string]string),
		onProvision:   onProvision,
		onDeprovision: onDeprovision,
	}
}

func generateSCIMID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("scim-%s", hex.EncodeToString(b))
}

// CreateUser provisions a new user in the directory per RFC 7644.
func (d *SCIMDirectory) CreateUser(ctx context.Context, u SCIMUser) (*SCIMUser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	trimmedUserName := strings.TrimSpace(u.UserName)
	if trimmedUserName == "" {
		return nil, errors.New("userName is required")
	}

	normName := strings.ToLower(trimmedUserName)
	if _, exists := d.userNames[normName]; exists {
		return nil, fmt.Errorf("user with userName %q already exists (conflict)", trimmedUserName)
	}

	if u.ID == "" {
		u.ID = generateSCIMID()
	}
	if len(u.Schemas) == 0 {
		u.Schemas = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}
	}
	if u.TenantID == "" {
		u.TenantID = "default"
	}

	now := time.Now().UTC()
	u.Meta = SCIMMeta{
		ResourceType: "User",
		Created:      now,
		LastModified: now,
		Version:      fmt.Sprintf("W/\"%d\"", now.UnixNano()),
	}

	// Store copy
	stored := u
	d.users[u.ID] = &stored
	d.userNames[normName] = u.ID

	if stored.Active {
		d.allocatedSeats++
	}

	// Trigger provisioning hook (e.g. automatic license seat binding)
	if d.onProvision != nil {
		_ = d.onProvision(ctx, &stored)
	}

	cpy := stored
	return &cpy, nil
}

// GetUser retrieves a user by their unique SCIM ID.
func (d *SCIMDirectory) GetUser(id string) (*SCIMUser, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	u, ok := d.users[id]
	if !ok {
		return nil, false
	}
	cpy := *u
	return &cpy, true
}

// GetUserByUserName looks up a user by their username or email.
func (d *SCIMDirectory) GetUserByUserName(userName string) (*SCIMUser, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	id, ok := d.userNames[strings.ToLower(strings.TrimSpace(userName))]
	if !ok {
		return nil, false
	}
	u, exists := d.users[id]
	if !exists {
		return nil, false
	}
	cpy := *u
	return &cpy, true
}

// UpdateUser modifies an existing user representation.
func (d *SCIMDirectory) UpdateUser(ctx context.Context, id string, updated SCIMUser) (*SCIMUser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	existing, ok := d.users[id]
	if !ok {
		return nil, fmt.Errorf("user %q not found", id)
	}

	newNorm := strings.ToLower(strings.TrimSpace(updated.UserName))
	oldNorm := strings.ToLower(existing.UserName)
	if newNorm != oldNorm {
		if _, clash := d.userNames[newNorm]; clash {
			return nil, fmt.Errorf("userName %q is already taken", updated.UserName)
		}
		delete(d.userNames, oldNorm)
		d.userNames[newNorm] = id
	}

	now := time.Now().UTC()
	wasActive := existing.Active
	existing.UserName = updated.UserName
	existing.Name = updated.Name
	existing.DisplayName = updated.DisplayName
	existing.Emails = updated.Emails
	existing.Roles = updated.Roles
	existing.Active = updated.Active
	existing.Meta.LastModified = now
	existing.Meta.Version = fmt.Sprintf("W/\"%d\"", now.UnixNano())

	// Check if user transitioned from active -> inactive (deprovisioning)
	if wasActive && !updated.Active {
		d.allocatedSeats--
		if d.onDeprovision != nil {
			_ = d.onDeprovision(ctx, existing, "SCIM user deactivated")
		}
	} else if !wasActive && updated.Active {
		d.allocatedSeats++
	}

	cpy := *existing
	return &cpy, nil
}

// DeprovisionUser marks a user inactive and triggers license revocation.
func (d *SCIMDirectory) DeprovisionUser(ctx context.Context, id, reason string) (*SCIMUser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	existing, ok := d.users[id]
	if !ok {
		return nil, fmt.Errorf("user %q not found", id)
	}

	if existing.Active {
		existing.Active = false
		d.allocatedSeats--
	}
	now := time.Now().UTC()
	existing.Meta.LastModified = now
	existing.Meta.Version = fmt.Sprintf("W/\"%d\"", now.UnixNano())

	if d.onDeprovision != nil {
		_ = d.onDeprovision(ctx, existing, reason)
	}

	cpy := *existing
	return &cpy, nil
}

// DeleteUser permanently deletes or deprovisions a SCIM user resource.
func (d *SCIMDirectory) DeleteUser(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	existing, ok := d.users[id]
	if !ok {
		return fmt.Errorf("user %q not found", id)
	}

	if existing.Active {
		d.allocatedSeats--
	}

	if d.onDeprovision != nil {
		_ = d.onDeprovision(ctx, existing, "SCIM user deleted")
	}

	delete(d.userNames, strings.ToLower(existing.UserName))
	delete(d.users, id)
	return nil
}

// ListUsers queries directory users with pagination.
func (d *SCIMDirectory) ListUsers(startIndex, count int, tenantID string) SCIMListResponse {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var matching []SCIMUser
	for _, u := range d.users {
		if tenantID == "" || u.TenantID == tenantID {
			matching = append(matching, *u)
		}
	}

	total := len(matching)
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = 100
	}

	start := startIndex - 1
	if start > total {
		start = total
	}
	end := start + count
	if end > total {
		end = total
	}

	slice := matching[start:end]
	return SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(slice),
		Resources:    slice,
	}
}

// Stats returns directory user metrics.
func (d *SCIMDirectory) Stats() (active int, deprovisioned int, seats int) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, u := range d.users {
		if u.Active {
			active++
		} else {
			deprovisioned++
		}
	}
	return active, deprovisioned, d.allocatedSeats
}

// BuildServiceProviderConfig delivers RFC 7643 service provider configuration JSON.
func BuildServiceProviderConfig() map[string]interface{} {
	return map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://github.com/kLauncher1/sheet-license-broker/docs/sso.md",
		"patch": map[string]bool{"supported": true},
		"bulk": map[string]interface{}{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter": map[string]interface{}{"supported": true, "maxResults": 200},
		"changePassword": map[string]bool{"supported": false},
		"sort": map[string]bool{"supported": false},
		"etag": map[string]bool{"supported": true},
		"authenticationSchemes": []map[string]interface{}{
			{
				"name":        "OAuth Bearer Token",
				"description": "Authentication via Ephemeral Bearer Token",
				"specUri":     "http://www.rfc-editor.org/info/rfc6750",
				"type":        "oauthbearertoken",
				"primary":     true,
			},
		},
	}
}
