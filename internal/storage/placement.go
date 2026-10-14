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
