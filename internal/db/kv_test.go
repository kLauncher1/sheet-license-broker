package db

import (
	"testing"
)

func TestStorageLifecycle(t *testing.T) {
	storage := NewStorage()

	// 1. Put
	doc := storage.Put("users_pref", "u_101", `{"lang":"ko","notifications":true}`)
	if doc.DocID != "u_101" {
		t.Fatalf("expected doc_id u_101, got %s", doc.DocID)
	}

	// 2. Get
	fetched, err := storage.Get("users_pref", "u_101")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if fetched.Payload != doc.Payload {
		t.Errorf("expected payload match")
	}

	// 3. Not Found
	_, err = storage.Get("users_pref", "non_existent")
	if err == nil {
		t.Errorf("expected error for non-existent document")
	}
}
