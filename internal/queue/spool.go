package queue

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/metrics"
)

var (
	ErrQueueEmpty    = errors.New("spool queue is empty")
	ErrQueueFull     = errors.New("spool queue reached maximum capacity")
	ErrCorruptRecord = errors.New("corrupt spool record encountered on disk")
)

// SpoolItem represents an event or mutation stored during offline or degraded connectivity.
type SpoolItem struct {
	ID        string          `json:"id"`
	Action    string          `json:"action"`
	TenantID  string          `json:"tenant_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp time.Time       `json:"timestamp"`
	Attempts  int             `json:"attempts"`
}

// DiskQueueConfig holds parameters for the encrypted on-disk fallback spool.
type DiskQueueConfig struct {
	FilePath    string
	SecretKey   []byte
	MaxCapacity int
}

// DiskQueue manages a thread-safe, AES-256-GCM encrypted FIFO spool backed by a local disk journal.
type DiskQueue struct {
	mu          sync.Mutex
	filePath    string
	key         [32]byte
	maxCapacity int
	items       []*SpoolItem
}

// NewDiskQueue initializes or reloads an encrypted disk spool queue.
func NewDiskQueue(cfg DiskQueueConfig) (*DiskQueue, error) {
	if cfg.FilePath == "" {
		cfg.FilePath = filepath.Join("data", "spool.bin")
	}
	if cfg.MaxCapacity <= 0 {
		cfg.MaxCapacity = 5000
	}

	keyHash := sha256.Sum256(cfg.SecretKey)

	dir := filepath.Dir(cfg.FilePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create spool directory: %w", err)
		}
	}

	dq := &DiskQueue{
		filePath:    cfg.FilePath,
		key:         keyHash,
		maxCapacity: cfg.MaxCapacity,
		items:       make([]*SpoolItem, 0),
	}

	// Reload existing uncommitted items if file exists
	if _, err := os.Stat(cfg.FilePath); err == nil {
		if err := dq.loadFromDisk(); err != nil {
			return nil, fmt.Errorf("failed to load existing spool: %w", err)
		}
	}

	metrics.SetSpoolQueueDepth(len(dq.items))
	return dq, nil
}

// Enqueue encrypts and appends an item to the memory list and writes it to disk.
func (dq *DiskQueue) Enqueue(item *SpoolItem) error {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if len(dq.items) >= dq.maxCapacity {
		return ErrQueueFull
	}
	if item.Timestamp.IsZero() {
		item.Timestamp = time.Now()
	}
	if item.ID == "" {
		item.ID = fmt.Sprintf("spool-%d-%d", time.Now().UnixNano(), len(dq.items)+1)
	}

	dq.items = append(dq.items, item)
	if err := dq.persistToDiskLocked(); err != nil {
		// Roll back memory on disk write failure
		dq.items = dq.items[:len(dq.items)-1]
		return fmt.Errorf("failed to persist spool item to disk: %w", err)
	}

	metrics.SetSpoolQueueDepth(len(dq.items))
	return nil
}

// Dequeue pops the oldest item from the queue.
func (dq *DiskQueue) Dequeue() (*SpoolItem, error) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if len(dq.items) == 0 {
		return nil, ErrQueueEmpty
	}

	item := dq.items[0]
	dq.items = dq.items[1:]

	if err := dq.persistToDiskLocked(); err != nil {
		// Re-prepend item on write failure
		dq.items = append([]*SpoolItem{item}, dq.items...)
		return nil, fmt.Errorf("failed to update spool on dequeue: %w", err)
	}

	metrics.SetSpoolQueueDepth(len(dq.items))
	return item, nil
}

// Drain processes items using handler. It halts on the first handler failure to preserve order.
func (dq *DiskQueue) Drain(handler func(item *SpoolItem) error) (int, error) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if len(dq.items) == 0 {
		return 0, nil
	}

	flushed := 0
	var drainErr error

	remaining := make([]*SpoolItem, 0, len(dq.items))
	for i, item := range dq.items {
		item.Attempts++
		if err := handler(item); err != nil {
			drainErr = err
			remaining = append(remaining, dq.items[i:]...)
			break
		}
		flushed++
	}

	dq.items = remaining
	if err := dq.persistToDiskLocked(); err != nil {
		return flushed, fmt.Errorf("error persisting drained spool: %w", err)
	}

	metrics.SetSpoolQueueDepth(len(dq.items))
	metrics.RecordSpoolFlushed(flushed)

	return flushed, drainErr
}

// Depth returns the current number of pending items in the spool.
func (dq *DiskQueue) Depth() int {
	dq.mu.Lock()
	defer dq.mu.Unlock()
	return len(dq.items)
}

// Encrypt encrypts raw plaintext using AES-256-GCM.
func (dq *DiskQueue) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(dq.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func (dq *DiskQueue) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(dq.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short for nonce")
	}
	nonce, actualCipher := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, actualCipher, nil)
}

func (dq *DiskQueue) persistToDiskLocked() error {
	raw, err := json.Marshal(dq.items)
	if err != nil {
		return fmt.Errorf("failed to marshal spool items: %w", err)
	}

	encrypted, err := dq.encrypt(raw)
	if err != nil {
		return fmt.Errorf("failed to encrypt spool payload: %w", err)
	}

	tmpFile := dq.filePath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// Write 4-byte length prefix + encrypted bytes
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
	if _, err := f.Write(lenBuf); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(encrypted); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmpFile, dq.filePath)
}

func (dq *DiskQueue) loadFromDisk() error {
	f, err := os.Open(dq.filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(f, lenBuf); err != nil {
		if errors.Is(err, io.EOF) {
			dq.items = make([]*SpoolItem, 0)
			return nil
		}
		return err
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	encrypted := make([]byte, payloadLen)
	if _, err := io.ReadFull(f, encrypted); err != nil {
		return fmt.Errorf("failed reading encrypted spool: %w", err)
	}

	decrypted, err := dq.decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("failed decrypting spool: %w", err)
	}

	var loaded []*SpoolItem
	if err := json.Unmarshal(decrypted, &loaded); err != nil {
		return fmt.Errorf("failed unmarshaling spool items: %w", err)
	}

	dq.items = loaded
	return nil
}

// Clear removes all pending spool items from memory and deletes the on-disk file.
func (dq *DiskQueue) Clear() error {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	dq.items = make([]*SpoolItem, 0)
	_ = os.Remove(dq.filePath)
	metrics.SetSpoolQueueDepth(0)
	return nil
}
