package gas

import (
	"fmt"
	"sync"
	"time"
)

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
	storedAt  time.Time
}

// Cache provides a thread-safe in-memory cache with TTL and offline fallback capability.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

// NewCache instantiates an empty cache.
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
	}
}

// Set stores a value with the specified time-to-live duration.
func (c *Cache) Set(key string, val interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var exp time.Time
	if ttl > 0 {
		exp = now.Add(ttl)
	}

	c.entries[key] = cacheEntry{
		value:     val,
		expiresAt: exp,
		storedAt:  now,
	}
}

// Get returns the value if present and not expired.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.value, true
}

// GetWithOfflineFallback returns the cached value even if expired,
// marking whether the entry was expired. This enables offline continuity during API outages.
func (c *Cache) GetWithOfflineFallback(key string) (val interface{}, found bool, expired bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false, false
	}

	isExp := !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt)
	return entry.value, true, isExp
}

// Delete removes a key from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear wipes all entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// Len returns the total number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// PurgeExpired removes any entries that have passed their TTL.
func (c *Cache) PurgeExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0
	for k, v := range c.entries {
		if !v.expiresAt.IsZero() && now.After(v.expiresAt) {
			delete(c.entries, k)
			count++
		}
	}
	return count
}

// SetLicense caches a verified license.
func (c *Cache) SetLicense(key string, lic *VerifyResponse, ttl time.Duration) {
	cacheKey := fmt.Sprintf("lic:%s", key)
	c.Set(cacheKey, lic, ttl)
}

// GetLicense retrieves a cached license with fallback status.
func (c *Cache) GetLicense(key string) (*VerifyResponse, bool, bool) {
	cacheKey := fmt.Sprintf("lic:%s", key)
	val, found, expired := c.GetWithOfflineFallback(cacheKey)
	if !found {
		return nil, false, false
	}
	lic, ok := val.(*VerifyResponse)
	return lic, ok, expired
}

// DeleteLicense removes a cached license entry immediately.
func (c *Cache) DeleteLicense(key string) {
	cacheKey := fmt.Sprintf("lic:%s", key)
	c.Delete(cacheKey)
}

// SetDoc caches a KV document.
func (c *Cache) SetDoc(collection, docID string, doc *DocResponse, ttl time.Duration) {
	cacheKey := fmt.Sprintf("doc:%s:%s", collection, docID)
	c.Set(cacheKey, doc, ttl)
}

// GetDoc retrieves a cached document with fallback status.
func (c *Cache) GetDoc(collection, docID string) (*DocResponse, bool, bool) {
	cacheKey := fmt.Sprintf("doc:%s:%s", collection, docID)
	val, found, expired := c.GetWithOfflineFallback(cacheKey)
	if !found {
		return nil, false, false
	}
	doc, ok := val.(*DocResponse)
	return doc, ok, expired
}
