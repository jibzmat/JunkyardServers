// Package repair rebuilds shards lost with storage nodes that are gone for
// good. It runs on the control-plane leader and works on ciphertext only:
// it fetches any k shards of a chunk, re-encodes the rest and writes the
// missing ones to healthy nodes that hold no shard of that chunk yet.
package repair

import (
	"context"
	"errors"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// DefaultAfter is how long a storage node must be unreachable before its
// shards are rebuilt elsewhere. Shorter outages (reboots, a flaky router)
// heal on their own and shouldn't cost a full copy of everything.
const DefaultAfter = 15 * time.Minute

// Meta is what repair needs from the control plane.
type Meta interface {
	AllObjects() []s3meta.Object
	MoveShards(bucket, key, segmentID string, moves []s3meta.ShardMove) error
}

// Repairer finds and rebuilds missing shards.
type Repairer struct {
	Meta Meta
	// Store's Nodes must return the storage nodes alive right now.
	Store *storage.Store
	// After is how long a node must be gone before repair; 0 means
	// DefaultAfter. Tests use a negative value for "immediately".
	After  time.Duration
	Logger *log.Logger
	Now    func() time.Time

	mu       sync.Mutex
	started  time.Time
	lastSeen map[string]time.Time
}

// Stats summarises a pass.
type Stats struct {
	Chunks  int // chunks examined
	Rebuilt int // shards written to new nodes
	Lost    int // chunks with fewer than k shards anywhere
	Failed  int // chunks that needed repair but could not get it
}

func (r *Repairer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Repairer) after() time.Duration {
	if r.After == 0 {
		return DefaultAfter
	}
	return r.After
}

func (r *Repairer) logf(format string, args ...any) {
	if r.Logger != nil {
		r.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Run makes a pass every interval while leader() reports true.
func (r *Repairer) Run(ctx context.Context, interval time.Duration, leader func() bool) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		alive := r.observe()
		if !leader() {
			continue
		}
		st, err := r.pass(ctx, alive)
		if err != nil {
			r.logf("repair: %v", err)
		}
		if st.Rebuilt > 0 || st.Lost > 0 || st.Failed > 0 {
			r.logf("repair: rebuilt %d shards; %d chunks still need repair, %d lost", st.Rebuilt, st.Failed, st.Lost)
		}
	}
}

// Pass observes the live nodes and makes one repair pass.
func (r *Repairer) Pass(ctx context.Context) (Stats, error) {
	return r.pass(ctx, r.observe())
}

// observe notes which storage nodes are alive now.
func (r *Repairer) observe() map[string]storage.Node {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastSeen == nil {
		r.lastSeen = map[string]time.Time{}
		r.started = now
	}
	alive := map[string]storage.Node{}
	for _, n := range r.Store.Nodes() {
		alive[n.ID] = n
		r.lastSeen[n.ID] = now
	}
	return alive
}

// gone reports whether a node has been unreachable long enough. A node
// never seen counts from when repair started.
func (r *Repairer) gone(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen, ok := r.lastSeen[id]
	if !ok {
		seen = r.started
	}
	return r.now().Sub(seen) > r.after()
}

func (r *Repairer) pass(ctx context.Context, alive map[string]storage.Node) (Stats, error) {
	var st Stats
	ids := make([]string, 0, len(alive))
	for id := range alive {
		ids = append(ids, id)
	}
	for _, obj := range r.Meta.AllObjects() {
		for _, seg := range obj.Segments() {
			if err := ctx.Err(); err != nil {
				return st, err
			}
			r.segment(ctx, obj, seg, alive, ids, &st)
		}
	}
	return st, nil
}

// segment repairs one segment's chunks and records the moves in one write.
func (r *Repairer) segment(ctx context.Context, obj s3meta.Object, seg s3meta.Segment, alive map[string]storage.Node, ids []string, st *Stats) {
	l := seg.Layout
	total := l.DataShards + l.ParityShards
	var moves []s3meta.ShardMove
	var written []storage.ShardRef
	for ci, c := range l.Chunks {
		st.Chunks++
		healthy := map[int]bool{}
		holders := map[string]bool{}
		waiting := false
		for _, sh := range c.Shards {
			holders[sh.Node] = true
			switch {
			case alive[sh.Node].ID != "":
				healthy[sh.Index] = true
			case !r.gone(sh.Node):
				waiting = true // down, but maybe only for a reboot
			}
		}
		if len(healthy) == total || waiting {
			continue // complete, or wait for the down node to return or be gone
		}
		if len(healthy) < l.DataShards {
			st.Lost++
			continue
		}
		shards, err := r.Store.RebuildChunk(ctx, l, ci, c)
		if err != nil {
			st.Failed++
			continue
		}
		ranked := storage.Place(seg.ID+"/"+strconv.Itoa(ci), ids, len(ids))
		next := 0
		for idx := 0; idx < total; idx++ {
			if healthy[idx] {
				continue
			}
			hash := storage.ShardHash(shards[idx])
			if want := recorded(c, idx); want != "" && want != hash {
				r.logf("repair: %s/%s chunk %d shard %d rebuilt with a different hash; skipping", obj.Bucket, obj.Key, ci, idx)
				continue
			}
			for next < len(ranked) {
				n := alive[ranked[next]]
				next++
				if holders[n.ID] {
					continue
				}
				if err := r.Store.Client.Put(ctx, n, hash, shards[idx]); err != nil {
					continue
				}
				holders[n.ID] = true
				moves = append(moves, s3meta.ShardMove{Chunk: ci, Index: idx, Hash: hash, Node: n.ID})
				written = append(written, storage.ShardRef{Index: idx, Hash: hash, Node: n.ID})
				break
			}
		}
		if len(healthy)+countChunk(moves, ci) < total {
			st.Failed++ // not enough distinct nodes; try again next pass
		}
	}
	if len(moves) == 0 {
		return
	}
	err := r.Meta.MoveShards(obj.Bucket, obj.Key, seg.ID, moves)
	if err != nil {
		// The object was overwritten or deleted meanwhile: drop the copies.
		r.Store.Delete(context.WithoutCancel(ctx), storage.Layout{Chunks: []storage.ChunkRef{{Shards: written}}})
		if !errors.Is(err, context.Canceled) {
			r.logf("repair: %s/%s: %v", obj.Bucket, obj.Key, err)
		}
		return
	}
	st.Rebuilt += len(moves)
}

func recorded(c storage.ChunkRef, idx int) string {
	for _, sh := range c.Shards {
		if sh.Index == idx {
			return sh.Hash
		}
	}
	return ""
}

func countChunk(moves []s3meta.ShardMove, ci int) int {
	n := 0
	for _, m := range moves {
		if m.Chunk == ci {
			n++
		}
	}
	return n
}
