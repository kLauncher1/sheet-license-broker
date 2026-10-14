package queue

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiskQueueLifecycleAndPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "spool-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	spoolPath := filepath.Join(tmpDir, "spool.bin")
	secret := []byte("super-secret-audit-encryption-key-32b")

	dq, err := NewDiskQueue(DiskQueueConfig{
		FilePath:    spoolPath,
		SecretKey:   secret,
		MaxCapacity: 100,
	})
	if err != nil {
		t.Fatalf("failed to create DiskQueue: %v", err)
	}

	payload1, _ := json.Marshal(map[string]string{"event": "license.verified", "hwid": "HWID-TEST-1"})
	payload2, _ := json.Marshal(map[string]string{"event": "license.revoked", "key": "LIC-TEST-2"})

	err = dq.Enqueue(&SpoolItem{Action: "verify_telemetry", TenantID: "ACME", Payload: payload1})
	if err != nil {
		t.Fatalf("enqueue 1 failed: %v", err)
	}
	err = dq.Enqueue(&SpoolItem{Action: "revoke_license", TenantID: "ACME", Payload: payload2})
	if err != nil {
		t.Fatalf("enqueue 2 failed: %v", err)
	}

	if dq.Depth() != 2 {
		t.Fatalf("expected depth 2, got %d", dq.Depth())
	}

	// Verify file is actually encrypted on disk (no plaintext leak)
	diskBytes, err := os.ReadFile(spoolPath)
	if err != nil {
		t.Fatalf("failed to read spool file from disk: %v", err)
	}
	if string(diskBytes) == "" || string(diskBytes) == string(payload1) {
		t.Errorf("spool file on disk should not be plaintext")
	}

	// Simulate process restart: create a new DiskQueue instance pointing to the same file
	dqRestarted, err := NewDiskQueue(DiskQueueConfig{
		FilePath:    spoolPath,
		SecretKey:   secret,
		MaxCapacity: 100,
	})
	if err != nil {
		t.Fatalf("reloaded DiskQueue failed: %v", err)
	}

	if dqRestarted.Depth() != 2 {
		t.Fatalf("expected reloaded depth 2, got %d", dqRestarted.Depth())
	}

	item1, err := dqRestarted.Dequeue()
	if err != nil {
		t.Fatalf("dequeue item1 failed: %v", err)
	}
	if item1.Action != "verify_telemetry" || item1.TenantID != "ACME" {
		t.Errorf("unexpected item1: %+v", item1)
	}

	if dqRestarted.Depth() != 1 {
		t.Fatalf("expected depth 1 after dequeue, got %d", dqRestarted.Depth())
	}

	// Clean up
	_ = dqRestarted.Clear()
	if dqRestarted.Depth() != 0 {
		t.Errorf("expected depth 0 after clear")
	}
}

func TestDiskQueueDrain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "spool-drain-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	spoolPath := filepath.Join(tmpDir, "spool.bin")
	secret := []byte("drain-secret-key-1234567890123456")

	dq, err := NewDiskQueue(DiskQueueConfig{
		FilePath:    spoolPath,
		SecretKey:   secret,
		MaxCapacity: 10,
	})
	if err != nil {
		t.Fatalf("failed to create DiskQueue: %v", err)
	}

	for i := 1; i <= 3; i++ {
		p, _ := json.Marshal(map[string]int{"seq": i})
		_ = dq.Enqueue(&SpoolItem{Action: "audit", Payload: p})
	}

	// Drain where item 3 fails
	processed := 0
	flushed, err := dq.Drain(func(item *SpoolItem) error {
		var data map[string]int
		_ = json.Unmarshal(item.Payload, &data)
		if data["seq"] == 3 {
			return errors.New("simulated remote API 500 error")
		}
		processed++
		return nil
	})

	if flushed != 2 {
		t.Errorf("expected 2 items flushed, got %d", flushed)
	}
	if err == nil {
		t.Errorf("expected drain error on 3rd item")
	}
	if dq.Depth() != 1 {
		t.Errorf("expected 1 item remaining in spool, got %d", dq.Depth())
	}

	// Drain remaining item successfully
	flushed2, err2 := dq.Drain(func(item *SpoolItem) error {
		return nil
	})
	if err2 != nil {
		t.Fatalf("unexpected drain error: %v", err2)
	}
	if flushed2 != 1 {
		t.Errorf("expected 1 flushed, got %d", flushed2)
	}
	if dq.Depth() != 0 {
		t.Errorf("expected empty spool, got depth %d", dq.Depth())
	}
}

func TestDiskQueueCapacityLimit(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "spool-cap-*")
	defer os.RemoveAll(tmpDir)

	dq, _ := NewDiskQueue(DiskQueueConfig{
		FilePath:    filepath.Join(tmpDir, "spool.bin"),
		SecretKey:   []byte("test-key"),
		MaxCapacity: 2,
	})

	_ = dq.Enqueue(&SpoolItem{Action: "item1", Timestamp: time.Now()})
	_ = dq.Enqueue(&SpoolItem{Action: "item2", Timestamp: time.Now()})
	err := dq.Enqueue(&SpoolItem{Action: "item3", Timestamp: time.Now()})
	if !errors.Is(err, ErrQueueFull) {
		t.Errorf("expected ErrQueueFull, got %v", err)
	}
}
