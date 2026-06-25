package blocker

import "strings"

type Node struct {
	children map[string]*Node
	blocked  bool
}

type Trie struct {
	root *Node
}

func NewTrie() *Trie {
	return &Trie{
		root: &Node{
			children: make(map[string]*Node),
		},
	}
}

func (t *Trie) Insert(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if domain == "" {
		return
	}

	parts := strings.Split(domain, ".")

	node := t.root

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		child, exists := node.children[part]
		if !exists {
			child = &Node{
				children: make(map[string]*Node),
			}

			node.children[part] = child
		}

		node = child
	}

	node.blocked = true
}

func (t *Trie) IsBlocked(domain string) bool {
	domain = strings.ToLower(domain)

	parts := strings.Split(domain, ".")

	node := t.root

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		child, exists := node.children[part]
		if !exists {
			return false
		}

		node = child

		if node.blocked {
			return true
		}
	}

	return node.blocked
}
