package repair

import (
	"context"
	"errors"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// Proof of storage. Listing a node's shards only shows what it claims to
// hold. So every AuditEvery the repairer asks each storage node for one
// shard picked at random from those the metadata places there, and the
// node must send it back whole: a shard's name is the hash of its bytes, so
// a node can't answer without keeping them, and it can't tell an audit
// from a read. The results go to the control plane, which keeps each
// node's reputation and suspends nodes that keep failing. A shard that
// failed is rebuilt like a lost one.

// DefaultAuditEvery is how often each storage node is audited. A shard is
// about 1 MiB, so this costs each node about 6 MiB of upload an hour.
const DefaultAuditEvery = 10 * time.Minute

// auditTimeout is how long a node has to send the audited shard.
const auditTimeout = time.Minute

func (r *Repairer) auditEvery() time.Duration {
	if r.AuditEvery == 0 {
		return DefaultAuditEvery
	}
	return r.AuditEvery
}

// failedAudit reports whether node recently failed an audit on hash, so
// the shard is rebuilt.
func (r *Repairer) failedAudit(node, hash string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.badShards[node+"/"+hash]
	return ok
}

func (r *Repairer) clearAudit(node, hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.badShards, node+"/"+hash)
}

// audit audits each live node due one, and records the results.
func (r *Repairer) audit(ctx context.Context, alive map[string]storage.Node, objects []s3meta.Object) {
	if r.auditEvery() < 0 {
		return
	}
	now := r.now()
	held := map[string][]string{} // node -> shard hashes placed there
	for _, obj := range objects {
		for _, seg := range obj.Segments() {
			for _, c := range seg.Layout.Chunks {
				for _, sh := range c.Shards {
					if _, ok := alive[sh.Node]; ok {
						held[sh.Node] = append(held[sh.Node], sh.Hash)
					}
				}
			}
		}
	}
	type job struct {
		node storage.Node
		hash string
	}
	var jobs []job
	r.mu.Lock()
	if r.lastAudit == nil {
		r.lastAudit = map[string]time.Time{}
	}
	ids := make([]string, 0, len(held))
	for id := range held {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if last, ok := r.lastAudit[id]; ok && now.Sub(last) < r.auditEvery() {
			continue
		}
		r.lastAudit[id] = now
		hashes := held[id]
		jobs = append(jobs, job{alive[id], hashes[rand.IntN(len(hashes))]})
	}
	r.mu.Unlock()
	if len(jobs) == 0 {
		return
	}

	results := make([]storage.AuditResult, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			actx, cancel := context.WithTimeout(ctx, auditTimeout)
			defer cancel()
			_, err := r.Store.Client.Get(actx, j.node, j.hash)
			res := storage.AuditResult{Node: j.node.ID, Hash: j.hash, OK: err == nil}
			if err != nil {
				res.Reason = err.Error()
				if errors.Is(err, storage.ErrNotFound) {
					res.Reason = "shard missing"
				}
			}
			results[i] = res
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return // our own shutdown, not the nodes' fault
	}
	r.mu.Lock()
	if r.badShards == nil {
		r.badShards = map[string]time.Time{}
	}
	for k, at := range r.badShards {
		if now.Sub(at) > 24*time.Hour {
			delete(r.badShards, k) // never rebuilt (too few shards left); stop counting it
		}
	}
	for _, res := range results {
		if !res.OK {
			r.badShards[res.Node+"/"+res.Hash] = now
			r.logf("repair: %s failed an audit of shard %.12s: %s", res.Node, res.Hash, res.Reason)
		}
	}
	r.mu.Unlock()
	if err := r.Meta.RecordAudits(results); err != nil {
		r.logf("repair: recording audits: %v", err)
	}
}
