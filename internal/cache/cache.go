package cache

import (
	"fmt"
	"sync"
	"time"
)

// CacheEntry lưu trữ payload của gói tin phản hồi và thời điểm hết hạn
type CacheEntry struct {
	Data      []byte
	ExpiresAt time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
}

func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]CacheEntry),
	}
}

func generateKey(domain string, qtype uint16) string {
	return fmt.Sprintf("%s_%d", domain, qtype)
}

// Get kiểm tra và trả về dữ liệu nếu Cache Hit và chưa hết hạn TTL
func (c *Cache) Get(domain string, qtype uint16) ([]byte, bool) {
	key := generateKey(domain, qtype)

	c.mu.RLock()
	entry, found := c.entries[key]
	c.mu.RUnlock()

	if !found {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		c.Delete(domain, qtype)
		return nil, false
	}

	return entry.Data, true
}

// Set lưu gói tin phản hồi vào bộ đệm với thời gian TTL chỉ định (tính bằng giây)
func (c *Cache) Set(domain string, qtype uint16, data []byte, ttl uint32) {
	key := generateKey(domain, qtype)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = CacheEntry{
		Data: data,
		// Cộng thời gian hiện tại với TTL để ra thời điểm hết hạn
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (c *Cache) Delete(domain string, qtype uint16) {
	key := generateKey(domain, qtype)

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
}
