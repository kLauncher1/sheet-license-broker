package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// User represents an authenticated identity stored in Google Sheets.
type User struct {
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Salt         string    `json:"salt"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// Manager coordinates local authentication cache and hash verification.
type Manager struct {
	mu    sync.RWMutex
	users map[string]*User
}

// NewManager initializes an auth manager with an in-memory test store.
func NewManager() *Manager {
	return &Manager{
		users: make(map[string]*User),
	}
}

// RegisterUser creates a new salted hashed user.
func (m *Manager) RegisterUser(username, password, role string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if username == "" || password == "" {
		return nil, errors.New("username and password cannot be empty")
	}
	if _, exists := m.users[username]; exists {
		return nil, errors.New("user already registered")
	}

	salt := hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))[:8]
	hash := HashPassword(password, salt)
	userID := "usr_" + hex.EncodeToString([]byte(username))[:6]

	user := &User{
		UserID:       userID,
		Username:     username,
		PasswordHash: hash,
		Salt:         salt,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}

	m.users[username] = user
	return user, nil
}

// PutUser registers or updates an existing user record.
func (m *Manager) PutUser(u *User) {
	if u == nil || u.Username == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.Username] = u
}

// Authenticate verifies user credentials.
func (m *Manager) Authenticate(username, password string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return nil, errors.New("user not found")
	}

	computed := HashPassword(password, user.Salt)
	if computed != user.PasswordHash {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

// ListUsers returns active users.
func (m *Manager) ListUsers() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]User, 0, len(m.users))
	for _, u := range m.users {
		res = append(res, *u)
	}
	return res
}

// HashPassword calculates salted SHA-256 digest compatible with Google Apps Script.
func HashPassword(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	return hex.EncodeToString(hasher.Sum(nil))
}
