package auth

import (
	"testing"
)

func TestAuthManager(t *testing.T) {
	mgr := NewManager()

	// 1. Register User
	user, err := mgr.RegisterUser("tester01", "SecretPass123!", "developer")
	if err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}
	if user.PasswordHash == "" || user.Salt == "" {
		t.Errorf("expected populated hash and salt")
	}

	// Duplicate register should fail
	_, err = mgr.RegisterUser("tester01", "AnotherPass", "user")
	if err == nil {
		t.Errorf("expected duplicate username error")
	}

	// 2. Authenticate
	authUser, err := mgr.Authenticate("tester01", "SecretPass123!")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if authUser.UserID != user.UserID {
		t.Errorf("expected user ID %s, got %s", user.UserID, authUser.UserID)
	}

	// Invalid password should fail
	_, err = mgr.Authenticate("tester01", "WrongPass")
	if err == nil {
		t.Errorf("expected error on invalid credentials")
	}
}
