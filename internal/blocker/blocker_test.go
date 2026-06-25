package blocker

import (
	"fmt"
	"testing"
)

func createBlocker(size int) *Blocker {
	b := NewBlocker()
	b.trie = NewTrie()

	for i := range size {
		b.trie.Insert(fmt.Sprintf("ads%d.example.com", i))
	}

	b.trie.Insert("doubleclick.net")
	return b
}

func BenchmarkIsBlocked_Hit(b *testing.B) {
	blocker := createBlocker(1e6)

	b.ReportAllocs()

	for b.Loop() {
		blocker.IsBlocked("ads.doubleclick.net")
	}
}

func BenchmarkIsBlocked_Miss(b *testing.B) {
	blocker := createBlocker(1e7)

	b.ReportAllocs()

	for b.Loop() {
		blocker.IsBlocked("google.com")
	}
}
