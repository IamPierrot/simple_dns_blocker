package blocker

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

type Blocker struct {
	mu   sync.RWMutex
	trie *Trie
}

func NewBlocker() *Blocker {
	return &Blocker{
		trie: nil,
	}
}

// IsBlocked kiểm tra xem một tên miền có nằm trong danh sách chặn hay không
func (b *Blocker) IsBlocked(domain string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domain = strings.ToLower(domain)
	return b.trie.IsBlocked(domain)
}

func (b *Blocker) Load(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open blocklist file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var cnt uint
	newTrie := NewTrie()

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

		newTrie.Insert(domain)
		cnt += 1
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist: %w", err)
	}

	b.mu.Lock()
	b.trie = newTrie
	b.mu.Unlock()

	fmt.Printf("[Blocker] Load (%d) domains from config successfully\n", cnt)
	return nil
}
