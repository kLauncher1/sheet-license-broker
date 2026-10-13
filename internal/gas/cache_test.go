package gas

import (
	"testing"
	"time"
)

func TestCacheBasic(t *testing.T) {
	c := NewCache()

	// Test Set and Get
	c.Set("k1", "val1", 50*time.Millisecond)
	val, ok := c.Get("k1")
	if !ok || val != "val1" {
		t.Fatalf("Expected val1, got %v", val)
	}

	// Test Expiry
	time.Sleep(60 * time.Millisecond)
	_, ok = c.Get("k1")
	if ok {
		t.Fatal("Expected key k1 to be expired")
	}

	// Test Offline Fallback
	val, found, expired := c.GetWithOfflineFallback("k1")
	if !found {
		t.Fatal("Expected key k1 to be found in offline fallback")
	}
	if !expired {
		t.Fatal("Expected key k1 to be marked as expired")
	}
	if val != "val1" {
		t.Fatalf("Expected val1 from offline fallback, got %v", val)
	}
}

func TestCacheLicenseAndDocHelpers(t *testing.T) {
	c := NewCache()

	lic := &VerifyResponse{
		Status:     "success",
		Verified:   true,
		HWIDBound:  "HWID-ABC",
		LicenseKey: "KEY-XYZ",
	}

	c.SetLicense("KEY-XYZ", lic, 100*time.Millisecond)

	retrieved, found, expired := c.GetLicense("KEY-XYZ")
	if !found || expired || retrieved.HWIDBound != "HWID-ABC" {
		t.Fatalf("Failed to retrieve valid license: found=%v, expired=%v", found, expired)
	}

	doc := &DocResponse{
		Status:     "success",
		Collection: "users",
		DocID:      "123",
	}

	c.SetDoc("users", "123", doc, 100*time.Millisecond)
	retDoc, found, expired := c.GetDoc("users", "123")
	if !found || expired || retDoc.DocID != "123" {
		t.Fatalf("Failed to retrieve doc: found=%v, expired=%v", found, expired)
	}

	// Test Purge
	time.Sleep(120 * time.Millisecond)
	purged := c.PurgeExpired()
	if purged != 2 {
		t.Errorf("Expected 2 purged entries, got %d", purged)
	}
	if c.Len() != 0 {
		t.Errorf("Expected cache to be empty after purge, got %d", c.Len())
	}
}
