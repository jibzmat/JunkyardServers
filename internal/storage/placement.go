package storage

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// Place picks n distinct nodes for a chunk with rendezvous (highest random
// weight) hashing: every node scores hash(chunk, node) and the top n win.
// Adding or removing a node only moves the shards that node wins or loses.
// If there are fewer than n nodes, all of them are returned.
func Place(chunkID string, nodes []string, n int) []string {
	type scored struct {
		node  string
		score uint64
	}
	s := make([]scored, 0, len(nodes))
	for _, node := range nodes {
		h := sha256.New()
		h.Write([]byte(chunkID))
		h.Write([]byte{0})
		h.Write([]byte(node))
		s = append(s, scored{node, binary.BigEndian.Uint64(h.Sum(nil))})
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].score != s[j].score {
			return s[i].score > s[j].score
		}
		return s[i].node < s[j].node
	})
	if n > len(s) {
		n = len(s)
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = s[i].node
	}
	return out
}

// Rank orders nodes for a chunk: up to k of the owner's trusted PCs first,
// then everyone else, each group by rendezvous hash. Shards are written in
// rank order, so with k trusted PCs every chunk can still be decoded if all
// strangers' PCs vanish at once. Suspended nodes are left out.
func Rank(chunkID string, nodes []Node, k int) []string {
	var trusted, all []string
	for _, n := range nodes {
		if n.Suspended {
			continue
		}
		all = append(all, n.ID)
		if n.Trusted {
			trusted = append(trusted, n.ID)
		}
	}
	first := Place(chunkID, trusted, max(k, 0))
	out := append([]string(nil), first...)
	taken := map[string]bool{}
	for _, id := range first {
		taken[id] = true
	}
	for _, id := range Place(chunkID, all, len(all)) {
		if !taken[id] {
			out = append(out, id)
		}
	}
	return out
}
