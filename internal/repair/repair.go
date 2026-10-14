// Package repair rebuilds shards lost with storage nodes that are gone for
// good. It runs on the control-plane leader and works on ciphertext only:
// it fetches any k shards of a chunk, re-encodes the rest and writes the
// missing ones to healthy nodes that hold no shard of that chunk yet. A
// shard a live node has lost (bit rot found by its scrubber, a wiped disk)
// is written back to the same node.
//
// Each pass also collects garbage: shards no object or upload refers to,
// left behind by failed writes, deletes that missed a node, or nodes that
// came back after repair moved their shards elsewhere.
package repair

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// DefaultAfter is how long a storage node must be unreachable before its
// shards are rebuilt elsewhere. Shorter outages (reboots, a flaky router)
// heal on their own and shouldn't cost a full copy of everything.
const DefaultAfter = 15 * time.Minute

// DefaultGCGrace is how old an unreferenced shard must be before it is
// deleted. Shards are written before the object that uses them is
// recorded, so a young unreferenced shard may belong to an upload still in
// flight.
const DefaultGCGrace = 24 * time.Hour

// GCHold is how long a shard must stay unreferenced before it is deleted,
// so a download that started before a re-code can
// still finish reading the old shards.
const GCHold = 15 * time.Minute

// DefaultScanEvery is how often node inventories are listed for lost
// shards and garbage. Listing walks every shard on every node, so it runs
// far less often than the repair pass itself.
const DefaultScanEvery = time.Hour

// DefaultUpgradeBytes bounds how much data one pass re-codes.
const DefaultUpgradeBytes = 1 << 30

// Meta is what repair needs from the control plane.
type Meta interface {
	AllObjects() []s3meta.Object
	AllUploads() []s3meta.Segment
	MoveShards(bucket, key, segmentID string, moves []s3meta.ShardMove) error
	Recode(bucket, key, segmentID, oldSum string, layout storage.Layout) error
}

// Repairer finds and rebuilds missing shards.
type Repairer struct {
	Meta Meta
	// Store's Nodes must return the storage nodes alive right now.
	Store *storage.Store
	// After is how long a node must be gone before repair; 0 means
	// DefaultAfter. Tests use a negative value for "immediately".
	After time.Duration
	// GCGrace is the minimum age of a shard garbage collection may delete;
	// 0 means DefaultGCGrace.
	GCGrace time.Duration
	// ScanEvery is how often Run lists node inventories; 0 means
	// DefaultScanEvery. Pass always lists them.
	ScanEvery time.Duration
	// UpgradeBytes bounds the data re-coded per pass; 0 means
	// DefaultUpgradeBytes, negative disables upgrades.
	UpgradeBytes int64
	Logger       *log.Logger
	Now          func() time.Time

	mu       sync.Mutex
	started  time.Time
	lastSeen map[string]time.Time
	lastScan time.Time
	unref    map[string]time.Time // "node/hash" -> first seen unreferenced
}

// Stats summarises a pass.
type Stats struct {
	Chunks  int // chunks examined
	Rebuilt int // shards written to new nodes
	Lost    int // chunks with fewer than k shards anywhere
	Failed  int // chunks that needed repair but could not get it

	Collected int // unreferenced shards deleted
	Upgraded  int // segments re-coded to the stronger coding more nodes allow
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

func (r *Repairer) gcGrace() time.Duration {
	if r.GCGrace == 0 {
		return DefaultGCGrace
	}
	return r.GCGrace
}

func (r *Repairer) scanEvery() time.Duration {
	if r.ScanEvery == 0 {
		return DefaultScanEvery
	}
	return r.ScanEvery
}

func (r *Repairer) upgradeBytes() int64 {
	if r.UpgradeBytes == 0 {
		return DefaultUpgradeBytes
	}
	return r.UpgradeBytes
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
		scan := r.now().Sub(r.lastScan) >= r.scanEvery()
		if scan {
			r.lastScan = r.now()
		}
		st, err := r.pass(ctx, alive, scan)
		if err != nil {
			r.logf("repair: %v", err)
		}
		if st.Rebuilt > 0 || st.Lost > 0 || st.Failed > 0 {
			r.logf("repair: rebuilt %d shards; %d chunks still need repair, %d lost", st.Rebuilt, st.Failed, st.Lost)
		}
		if st.Upgraded > 0 {
			r.logf("repair: re-coded %d segments written while nodes were down", st.Upgraded)
		}
		if st.Collected > 0 {
			r.logf("repair: deleted %d unreferenced shards", st.Collected)
		}
	}
}

// Pass observes the live nodes and makes one repair pass.
func (r *Repairer) Pass(ctx context.Context) (Stats, error) {
	return r.pass(ctx, r.observe(), true)
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

// inventory is what each live node reported holding, by node ID. A node
// whose listing failed has no entry; its shards are assumed present.
type inventory map[string]map[string]time.Time

// has reports whether node holds hash, as far as is known.
func (inv inventory) has(node, hash string) bool {
	held, ok := inv[node]
	if !ok {
		return true
	}
	_, ok = held[hash]
	return ok
}

func (r *Repairer) pass(ctx context.Context, alive map[string]storage.Node, scan bool) (Stats, error) {
	var st Stats
	ids := make([]string, 0, len(alive))
	for id := range alive {
		ids = append(ids, id)
	}
	// List before reading metadata: a shard recorded after this read was
	// written or refreshed after the listing, so it is never mistaken for
	// old garbage.
	listed := r.now()
	var inv inventory
	if scan {
		inv = r.inventory(ctx, alive)
	}
	objects := r.Meta.AllObjects()
	uploads := r.Meta.AllUploads()
	type candidate struct {
		obj s3meta.Object
		seg s3meta.Segment
	}
	var weak []candidate
	_, wantM := storage.ChooseCoding(len(alive))
	for _, obj := range objects {
		// Shards of an object written while the nodes were being listed
		// may be missing from the lists; don't treat them as lost.
		check := inv
		if !obj.Modified.Before(listed.Add(-time.Minute)) {
			check = nil
		}
		for _, seg := range obj.Segments() {
			if err := ctx.Err(); err != nil {
				return st, err
			}
			if r.segment(ctx, obj, seg, alive, ids, check, &st) && seg.Layout.ParityShards < wantM {
				weak = append(weak, candidate{obj, seg})
			}
		}
	}
	budget := r.upgradeBytes()
	nodes := make([]storage.Node, 0, len(alive))
	for _, n := range alive {
		nodes = append(nodes, n)
	}
	for _, c := range weak {
		if ctx.Err() != nil || budget < c.seg.Layout.Size() {
			break
		}
		budget -= c.seg.Layout.Size()
		if r.upgrade(ctx, c.obj, c.seg, nodes) {
			st.Upgraded++
		}
	}
	if scan {
		st.Collected = r.collect(ctx, alive, inv, objects, uploads)
	}
	return st, ctx.Err()
}

func (r *Repairer) inventory(ctx context.Context, alive map[string]storage.Node) inventory {
	inv := inventory{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range alive {
		wg.Add(1)
		go func() {
			defer wg.Done()
			held, err := r.Store.Client.List(ctx, n)
			if err != nil {
				if ctx.Err() == nil {
					r.logf("repair: listing shards on %s: %v", n.ID, err)
				}
				return
			}
			mu.Lock()
			inv[n.ID] = held
			mu.Unlock()
		}()
	}
	wg.Wait()
	return inv
}

// upgrade re-codes a segment written with fewer parity shards than the
// cluster now allows. The old shards become garbage once the new layout is
// recorded.
func (r *Repairer) upgrade(ctx context.Context, obj s3meta.Object, seg s3meta.Segment, nodes []storage.Node) bool {
	k, m := storage.ChooseCoding(len(nodes))
	layout, err := r.Store.Recode(ctx, seg.ID, seg.Layout, k, m, nodes)
	if err != nil {
		if ctx.Err() == nil {
			r.logf("repair: re-coding %s/%s: %v", obj.Bucket, obj.Key, err)
		}
		return false
	}
	if err := r.Meta.Recode(obj.Bucket, obj.Key, seg.ID, seg.Layout.Sum(), layout); err != nil {
		r.Store.Delete(context.WithoutCancel(ctx), layout)
		return false
	}
	return true
}

// collect deletes shards that nothing refers to and that are older than
// the grace period.
func (r *Repairer) collect(ctx context.Context, alive map[string]storage.Node, inv inventory, objects []s3meta.Object, uploads []s3meta.Segment) int {
	used := map[string]map[string]bool{}
	note := func(seg s3meta.Segment) {
		for _, c := range seg.Layout.Chunks {
			for _, sh := range c.Shards {
				if used[sh.Node] == nil {
					used[sh.Node] = map[string]bool{}
				}
				used[sh.Node][sh.Hash] = true
			}
		}
	}
	for _, obj := range objects {
		for _, seg := range obj.Segments() {
			note(seg)
		}
	}
	for _, seg := range uploads {
		note(seg)
	}
	now := r.now()
	cutoff := now.Add(-r.gcGrace())
	r.mu.Lock()
	unref := map[string]time.Time{}
	for id, held := range inv {
		for hash := range held {
			if !used[id][hash] {
				k := id + "/" + hash
				since, ok := r.unref[k]
				if !ok {
					since = now
				}
				unref[k] = since
			}
		}
	}
	for k, since := range r.unref {
		// Keep what was known about nodes not listed this time.
		if node, _, _ := strings.Cut(k, "/"); inv[node] == nil {
			unref[k] = since
		}
	}
	r.unref = unref
	r.mu.Unlock()
	n := 0
	for id, held := range inv {
		for hash, mod := range held {
			if ctx.Err() != nil {
				return n
			}
			since, ok := unref[id+"/"+hash]
			if !ok || mod.After(cutoff) || now.Sub(since) < GCHold {
				continue
			}
			if err := r.Store.Client.Delete(ctx, alive[id], hash); err == nil {
				n++
			}
		}
	}
	return n
}

// segment repairs one segment's chunks and records the moves in one write.
// It reports whether every shard of the segment was healthy.
func (r *Repairer) segment(ctx context.Context, obj s3meta.Object, seg s3meta.Segment, alive map[string]storage.Node, ids []string, inv inventory, st *Stats) bool {
	complete := true
	l := seg.Layout
	total := l.DataShards + l.ParityShards
	var moves []s3meta.ShardMove
	restoredAll := 0
	var written []storage.ShardRef
	for ci, c := range l.Chunks {
		st.Chunks++
		healthy := map[int]bool{}
		holders := map[string]bool{}
		lost := map[int]storage.Node{} // shards a live node no longer has
		waiting := false
		for _, sh := range c.Shards {
			holders[sh.Node] = true
			switch {
			case alive[sh.Node].ID != "" && !inv.has(sh.Node, sh.Hash):
				lost[sh.Index] = alive[sh.Node]
			case alive[sh.Node].ID != "":
				healthy[sh.Index] = true
			case !r.gone(sh.Node):
				waiting = true // down, but maybe only for a reboot
			}
		}
		if len(healthy) != total {
			complete = false
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
		restored := 0
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
			if n, ok := lost[idx]; ok {
				// Its node is alive: put it back where the layout says.
				if err := r.Store.Client.Put(ctx, n, hash, shards[idx]); err == nil {
					restored++
				}
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
		restoredAll += restored
		if len(healthy)+restored+countChunk(moves, ci) < total {
			st.Failed++ // not enough distinct nodes; try again next pass
		}
	}
	st.Rebuilt += restoredAll
	if len(moves) == 0 {
		return complete
	}
	err := r.Meta.MoveShards(obj.Bucket, obj.Key, seg.ID, moves)
	if err != nil {
		// The object was overwritten or deleted meanwhile: drop the copies.
		r.Store.Delete(context.WithoutCancel(ctx), storage.Layout{Chunks: []storage.ChunkRef{{Shards: written}}})
		if !errors.Is(err, context.Canceled) {
			r.logf("repair: %s/%s: %v", obj.Bucket, obj.Key, err)
		}
		return false
	}
	st.Rebuilt += len(moves)
	return false
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
