package blocker

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

type Blocker struct {
	mu      sync.RWMutex
	domains map[string]struct{}
}

func NewBlocker() *Blocker {
	return &Blocker{
		domains: make(map[string]struct{}),
	}
}

// IsBlocked kiểm tra xem một tên miền có nằm trong danh sách chặn hay không
func (b *Blocker) IsBlocked(domain string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domain = strings.ToLower(domain)

	if _, exists := b.domains[domain]; exists {
		return true
	}

	// (Subdomain)
	for blocked := range b.domains {
		if strings.HasSuffix(domain, "."+blocked) {
			return true
		}
	}

	return false
}

func (b *Blocker) Load(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open blocklist file: %w", err)
	}
	defer file.Close()

	newDomains := make(map[string]struct{})
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		var domain string
		if len(parts) >= 2 {
			domain = parts[1]
		} else {
			domain = parts[0]
		}

		newDomains[strings.ToLower(domain)] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist: %w", err)
	}

	b.mu.Lock()
	b.domains = newDomains
	b.mu.Unlock()

	fmt.Printf("[Blocker] Load (%d) domains from config successfully\n", len(newDomains))
	return nil
}
