package storage

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

// Node is a storage node shards can be placed on.
type Node struct {
	ID   string
	Addr string // shard server host:port
	// Name is what the node's certificate must name (its mesh IP). Empty
	// means the host part of Addr.
	Name string
	// Trusted is one of the owner's own PCs (not a stranger's).
	Trusted bool
	// Suspended nodes failed too many audits: they get no new shards and
	// repair moves their shards elsewhere.
	Suspended bool
}

// AuditResult is the outcome of asking a node for a shard it should hold.
type AuditResult struct {
	Node   string `json:"node"`
	Hash   string `json:"hash"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// ShardRef says where one shard of a chunk lives.
type ShardRef struct {
	Index int    `json:"i"` // position in the k+m shard set
	Hash  string `json:"h"`
	Node  string `json:"n"` // node ID
}

// ChunkRef describes one stored chunk.
type ChunkRef struct {
	Size       int        `json:"size"`   // plaintext bytes
	SealedSize int        `json:"sealed"` // ciphertext bytes before coding
	Shards     []ShardRef `json:"shards"`
}

// Layout records how an object was coded.
type Layout struct {
	DataShards   int        `json:"k"`
	ParityShards int        `json:"m"`
	Chunks       []ChunkRef `json:"chunks"`
}

// Size is the object's plaintext size.
func (l Layout) Size() int64 {
	var n int64
	for _, c := range l.Chunks {
		n += int64(c.Size)
	}
	return n
}

// Sum identifies the layout's exact contents.
func (l Layout) Sum() string {
	b, _ := json.Marshal(l)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Store reads and writes objects as shards on storage nodes. The coding for
// each new object is chosen from the number of storage nodes (ChooseCoding)
// and recorded in its layout.
type Store struct {
	Client *ShardClient
	// Nodes returns the storage nodes currently usable for placement and
	// the address of every known node (for reading shards placed earlier).
	Nodes func() []Node

	mu   sync.Mutex
	down map[string]time.Time // nodes that recently failed a write
}

// DownFor is how long a node that failed a shard write is left out of
// placement. Gossip notices dead nodes too, but only after tens of seconds.
const DownFor = 30 * time.Second

// writable returns the nodes not marked down.
func (s *Store) writable() []Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []Node
	for _, n := range s.Nodes() {
		if t, ok := s.down[n.ID]; (ok && now.Before(t)) || n.Suspended {
			continue
		}
		out = append(out, n)
	}
	return out
}

func (s *Store) markDown(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down == nil {
		s.down = map[string]time.Time{}
	}
	s.down[id] = time.Now().Add(DownFor)
}

// ErrNotEnoughNodes means fewer than k+1 storage nodes accepted a chunk.
var ErrNotEnoughNodes = errors.New("storage: not enough storage nodes reachable")

// Put reads r to the end, storing it as objectID under key. It returns the
// layout to record in metadata and the MD5 of the plaintext (the S3 ETag).
// A chunk counts as stored once k+1 of its k+m shards are on distinct nodes,
// so one more node can fail before the chunk is at risk; repair restores the
// rest later.
func (s *Store) Put(ctx context.Context, objectID string, key ObjectKey, r io.Reader) (Layout, string, error) {
	nodes := s.writable()
	if len(nodes) == 0 {
		return Layout{}, "", ErrNotEnoughNodes
	}
	k, m := ChooseCoding(len(nodes))
	layout := Layout{DataShards: k, ParityShards: m}
	sum := md5.New()
	buf := make([]byte, ChunkSize)
	for idx := uint64(0); ; idx++ {
		n, err := io.ReadFull(r, buf)
		if err == io.EOF && idx > 0 {
			break
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			// The body failed (a dropped client, a bad signature or
			// checksum): drop the chunks already stored.
			s.cleanup(context.WithoutCancel(ctx), layout)
			return Layout{}, "", err
		}
		plain := buf[:n]
		sum.Write(plain)
		ref, perr := s.putChunk(ctx, objectID, key, idx, plain, k, m, nodes)
		if perr != nil {
			s.cleanup(context.WithoutCancel(ctx), layout)
			return Layout{}, "", perr
		}
		layout.Chunks = append(layout.Chunks, ref)
		if n < ChunkSize {
			break
		}
	}
	return layout, hex.EncodeToString(sum.Sum(nil)), nil
}

func (s *Store) putChunk(ctx context.Context, objectID string, key ObjectKey, idx uint64, plain []byte, k, m int, nodes []Node) (ChunkRef, error) {
	sealed, err := SealChunk(key, objectID, idx, plain)
	if err != nil {
		return ChunkRef{}, err
	}
	ref, err := s.writeSealed(ctx, objectID, idx, sealed, k, m, nodes)
	ref.Size = len(plain)
	return ref, err
}

// writeSealed codes a sealed chunk and stores its shards on distinct nodes.
// It succeeds once k+1 shards (all of them, if m is 0) are stored.
func (s *Store) writeSealed(ctx context.Context, objectID string, idx uint64, sealed []byte, k, m int, nodes []Node) (ChunkRef, error) {
	shards, err := Encode(sealed, k, m)
	if err != nil {
		return ChunkRef{}, err
	}
	byID := map[string]Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	// Rank every node for this chunk; shard i goes to the i-th ranked node,
	// and falls through to later ones if that node fails.
	ranked := Rank(objectID+"/"+strconv.FormatUint(idx, 10), nodes, k)

	type result struct {
		ref ShardRef
		ok  bool
	}
	results := make([]result, len(shards))
	var mu sync.Mutex
	var lastErr error
	used := map[string]bool{}
	next := 0
	claim := func() (Node, bool) {
		mu.Lock()
		defer mu.Unlock()
		for next < len(ranked) {
			id := ranked[next]
			next++
			if !used[id] {
				used[id] = true
				return byID[id], true
			}
		}
		return Node{}, false
	}
	var wg sync.WaitGroup
	for i, shard := range shards {
		wg.Add(1)
		go func(i int, shard []byte) {
			defer wg.Done()
			hash := ShardHash(shard)
			for {
				node, ok := claim()
				if !ok {
					return
				}
				err := s.Client.Put(ctx, node, hash, shard)
				if err == nil {
					results[i] = result{ShardRef{Index: i, Hash: hash, Node: node.ID}, true}
					return
				}
				s.markDown(node.ID)
				mu.Lock()
				lastErr = err
				mu.Unlock()
			}
		}(i, shard)
	}
	wg.Wait()

	ref := ChunkRef{SealedSize: len(sealed)}
	for _, r := range results {
		if r.ok {
			ref.Shards = append(ref.Shards, r.ref)
		}
	}
	if need := min(k+1, k+m); len(ref.Shards) < need {
		s.cleanup(context.WithoutCancel(ctx), Layout{Chunks: []ChunkRef{ref}})
		return ChunkRef{}, fmt.Errorf("%w: %d of %d shards stored (%d nodes; last error: %v)", ErrNotEnoughNodes, len(ref.Shards), k+m, len(nodes), lastErr)
	}
	return ref, nil
}

// Get writes length bytes of the object starting at offset to w. A negative
// length means to the end.
func (s *Store) Get(ctx context.Context, objectID string, key ObjectKey, layout Layout, offset, length int64, w io.Writer) error {
	size := layout.Size()
	if offset < 0 || offset > size {
		return fmt.Errorf("storage: offset %d out of range", offset)
	}
	if length < 0 || offset+length > size {
		length = size - offset
	}
	addrs := s.addrs()
	var pos int64
	for idx, c := range layout.Chunks {
		start, end := pos, pos+int64(c.Size)
		pos = end
		if length == 0 || end <= offset {
			continue
		}
		if start >= offset+length {
			break
		}
		plain, err := s.getChunk(ctx, objectID, key, layout, uint64(idx), c, addrs)
		if err != nil {
			return err
		}
		from := max(offset-start, 0)
		to := min(offset+length-start, int64(c.Size))
		if _, err := w.Write(plain[from:to]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) addrs() map[string]Node {
	out := map[string]Node{}
	for _, n := range s.Nodes() {
		out[n.ID] = n
	}
	return out
}

// getChunk fetches a chunk's shards, decodes and decrypts it.
func (s *Store) getChunk(ctx context.Context, objectID string, key ObjectKey, layout Layout, idx uint64, c ChunkRef, addrs map[string]Node) ([]byte, error) {
	sealed, err := s.getSealed(ctx, layout, idx, c, addrs)
	if err != nil {
		return nil, err
	}
	return OpenChunk(key, objectID, idx, sealed)
}

// RebuildChunk recomputes every shard of a chunk from any k reachable ones.
// It needs no keys: coding works on ciphertext. Reed-Solomon coding is
// deterministic, so rebuilt shards hash the same as the originals.
func (s *Store) RebuildChunk(ctx context.Context, layout Layout, idx int, c ChunkRef) ([][]byte, error) {
	sealed, err := s.getSealed(ctx, layout, uint64(idx), c, s.addrs())
	if err != nil {
		return nil, err
	}
	return Encode(sealed, layout.DataShards, layout.ParityShards)
}

// getSealed fetches shards in parallel and decodes as soon as k have arrived.
func (s *Store) getSealed(ctx context.Context, layout Layout, idx uint64, c ChunkRef, addrs map[string]Node) ([]byte, error) {
	k, m := layout.DataShards, layout.ParityShards
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type got struct {
		i    int
		data []byte
	}
	ch := make(chan got, len(c.Shards))
	for _, sh := range c.Shards {
		go func(sh ShardRef) {
			n, ok := addrs[sh.Node]
			if !ok {
				ch <- got{sh.Index, nil}
				return
			}
			data, err := s.Client.Get(ctx, n, sh.Hash)
			if err != nil {
				data = nil
			}
			ch <- got{sh.Index, data}
		}(sh)
	}
	shards := make([][]byte, k+m)
	have := 0
	for range c.Shards {
		g := <-ch
		if g.data != nil && g.i >= 0 && g.i < k+m {
			shards[g.i] = g.data
			have++
			if have == k {
				break
			}
		}
	}
	if have < k {
		return nil, fmt.Errorf("storage: chunk %d: only %d of %d needed shards reachable", idx, have, k)
	}
	return Decode(shards, k, m, c.SealedSize)
}

// Recode rewrites a segment's chunks with k+m coding on the given nodes,
// returning the new layout. The chunks stay sealed throughout: no key is
// needed. On failure the shards already written are deleted.
func (s *Store) Recode(ctx context.Context, segmentID string, old Layout, k, m int, nodes []Node) (Layout, error) {
	out := Layout{DataShards: k, ParityShards: m}
	addrs := s.addrs()
	for i, c := range old.Chunks {
		sealed, err := s.getSealed(ctx, old, uint64(i), c, addrs)
		if err == nil {
			var ref ChunkRef
			ref, err = s.writeSealed(ctx, segmentID, uint64(i), sealed, k, m, nodes)
			ref.Size = c.Size
			out.Chunks = append(out.Chunks, ref)
		}
		if err != nil {
			s.cleanup(context.WithoutCancel(ctx), out)
			return Layout{}, err
		}
	}
	return out, nil
}

// Delete removes an object's shards. Unreachable nodes keep orphaned
// shards, which garbage collection (with repair) removes later.
func (s *Store) Delete(ctx context.Context, layout Layout) {
	s.cleanup(ctx, layout)
}

func (s *Store) cleanup(ctx context.Context, layout Layout) {
	addrs := s.addrs()
	var wg sync.WaitGroup
	for _, c := range layout.Chunks {
		for _, sh := range c.Shards {
			n, ok := addrs[sh.Node]
			if !ok {
				continue
			}
			wg.Add(1)
			go func(n Node, hash string) {
				defer wg.Done()
				_ = s.Client.Delete(ctx, n, hash)
			}(n, sh.Hash)
		}
	}
	wg.Wait()
}
