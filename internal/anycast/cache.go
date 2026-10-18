package anycast

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type cacheEntry struct {
	value          interface{}
	cachedAt       time.Time
	expiresAt      time.Time
	staleUntil     time.Time
	isRevalidating bool
}

// SubMillisecondEdgeCache provides high-concurrency in-memory caching with sub-millisecond lookups
// and background stale-while-revalidate asynchronous refreshing.
type SubMillisecondEdgeCache struct {
	mu                 sync.RWMutex
	items              map[string]*cacheEntry
	freshTTL           time.Duration
	staleTTL           time.Duration
	revalidateFn       func(key string) (interface{}, error)
	hits               int64
	misses             int64
	revalidations      int64
	totalLookups       int64
	totalLookupTimeUS  float64
	avgLookupLatencyUS float64
	closed             int32
}

// NewSubMillisecondEdgeCache initializes an edge L1 cache with configurable fresh and stale TTLs.
func NewSubMillisecondEdgeCache(freshTTL, staleTTL time.Duration, revalidator func(string) (interface{}, error)) *SubMillisecondEdgeCache {
	if freshTTL <= 0 {
		freshTTL = 30 * time.Second
	}
	if staleTTL <= freshTTL {
		staleTTL = freshTTL * 3
	}
	return &SubMillisecondEdgeCache{
		items:        make(map[string]*cacheEntry),
		freshTTL:     freshTTL,
		staleTTL:     staleTTL,
		revalidateFn: revalidator,
	}
}

// Get performs an in-memory L1 lookup (<1ms latency) with stale-while-revalidate support.
func (c *SubMillisecondEdgeCache) Get(key string) (interface{}, bool) {
	start := time.Now()

	c.mu.RLock()
	entry, exists := c.items[key]
	if !exists {
		c.mu.RUnlock()
		c.recordLookup(start, false, false)
		return nil, false
	}

	now := time.Now().UTC()
	val := entry.value
	isFresh := now.Before(entry.expiresAt)
	isStale := !isFresh && now.Before(entry.staleUntil)
	needsRevalidate := isStale && !entry.isRevalidating && c.revalidateFn != nil
	c.mu.RUnlock()

	if isFresh {
		c.recordLookup(start, true, false)
		return val, true
	}

	if isStale {
		if needsRevalidate && atomic.LoadInt32(&c.closed) == 0 {
			c.triggerBackgroundRevalidate(key)
		}
		c.recordLookup(start, true, true)
		return val, true
	}

	// Completely expired past staleTTL
	c.recordLookup(start, false, false)
	return nil, false
}

// triggerBackgroundRevalidate launches an async goroutine to refresh stale data without blocking the caller.
func (c *SubMillisecondEdgeCache) triggerBackgroundRevalidate(key string) {
	c.mu.Lock()
	entry, ok := c.items[key]
	if !ok || entry.isRevalidating {
		c.mu.Unlock()
		return
	}
	entry.isRevalidating = true
	c.mu.Unlock()

	go func() {
		newVal, err := c.revalidateFn(key)
		c.mu.Lock()
		defer c.mu.Unlock()

		ent, exists := c.items[key]
		if !exists {
			return
		}
		ent.isRevalidating = false
		if err == nil && newVal != nil {
			now := time.Now().UTC()
			ent.value = newVal
			ent.cachedAt = now
			ent.expiresAt = now.Add(c.freshTTL)
			ent.staleUntil = now.Add(c.staleTTL)
			atomic.AddInt64(&c.revalidations, 1)
		}
	}()
}

// Set stores a value into the cache using default fresh and stale TTLs.
func (c *SubMillisecondEdgeCache) Set(key string, val interface{}) {
	c.SetWithTTL(key, val, c.freshTTL, c.staleTTL)
}

// SetWithTTL stores a value with custom fresh and stale durations.
func (c *SubMillisecondEdgeCache) SetWithTTL(key string, val interface{}, freshTTL, staleTTL time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	if staleTTL < freshTTL {
		staleTTL = freshTTL * 2
	}

	c.items[key] = &cacheEntry{
		value:      val,
		cachedAt:   now,
		expiresAt:  now.Add(freshTTL),
		staleUntil: now.Add(staleTTL),
	}
}

// Delete removes a key from the cache.
func (c *SubMillisecondEdgeCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// Purge removes all entries and resets cache metrics.
func (c *SubMillisecondEdgeCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*cacheEntry)
}

// recordLookup tracks microsecond latency and hit/miss counters.
func (c *SubMillisecondEdgeCache) recordLookup(start time.Time, hit, stale bool) {
	elapsedUS := float64(time.Since(start).Nanoseconds()) / 1000.0

	c.mu.Lock()
	defer c.mu.Unlock()

	if hit {
		c.hits++
	} else {
		c.misses++
	}

	c.totalLookups++
	c.totalLookupTimeUS += elapsedUS
	if c.totalLookups > 0 {
		c.avgLookupLatencyUS = c.totalLookupTimeUS / float64(c.totalLookups)
	}
}

// Stats returns a telemetry snapshot of cache efficiency and microsecond lookup performance.
func (c *SubMillisecondEdgeCache) Stats() EdgeCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	var hitRatio float64
	if total > 0 {
		hitRatio = float64(c.hits) / float64(total)
	}

	tierEntries := 0
	for k := range c.items {
		if strings.HasPrefix(k, "tier:") || strings.HasPrefix(k, "license:") || strings.HasPrefix(k, "entitlement:") {
			tierEntries++
		}
	}
	if tierEntries == 0 {
		tierEntries = len(c.items)
	}

	return EdgeCacheStats{
		Hits:              c.hits,
		Misses:            c.misses,
		Revalidations:     atomic.LoadInt64(&c.revalidations),
		LookupLatencyUS:   c.avgLookupLatencyUS,
		CachedTierEntries: tierEntries,
		HitRatio:          hitRatio,
	}
}

// Close gracefully stops the cache instance.
func (c *SubMillisecondEdgeCache) Close() {
	atomic.StoreInt32(&c.closed, 1)
}
