package repair

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

type cluster struct {
	t       *testing.T
	ca      *pki.CA
	mu      sync.Mutex
	nodes   map[string]storage.Node
	servers map[string]*httptest.Server
	disks   map[string]*storage.ShardStore
	dirs    map[string]string
	liars   map[string]bool // claim shards in listings but never send them
	store   *storage.Store
	n       int
}

func newCluster(t *testing.T, n int) *cluster {
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	c := &cluster{t: t, ca: ca, nodes: map[string]storage.Node{}, servers: map[string]*httptest.Server{},
		disks: map[string]*storage.ShardStore{}, dirs: map[string]string{}}
	cert, key := c.issue(pki.KindControl, "repair")
	c.store = &storage.Store{
		Client: storage.NewShardClient(pki.TLSCertificate(cert.Raw, key, ca.Cert), ca.Cert),
		Nodes: func() []storage.Node {
			c.mu.Lock()
			defer c.mu.Unlock()
			var out []storage.Node
			for _, n := range c.nodes {
				out = append(out, n)
			}
			return out
		},
	}
	for i := 0; i < n; i++ {
		c.add()
	}
	return c
}

func (c *cluster) issue(kind pki.Kind, name string) (*x509.Certificate, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := c.ca.Issue(kind, name, pub, time.Hour, "127.0.0.1")
	if err != nil {
		c.t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, priv
}

func (c *cluster) add() string {
	id := fmt.Sprintf("n-%d", c.n)
	c.n++
	dir := filepath.Join(c.t.TempDir(), "shards")
	st, err := storage.OpenShardStore(dir)
	if err != nil {
		c.t.Fatal(err)
	}
	cert, key := c.issue(pki.KindNode, id)
	ss := &storage.ShardServer{Store: st, Cert: pki.TLSCertificate(cert.Raw, key, c.ca.Cert), CA: c.ca.Cert,
		MayDelete: func(x *x509.Certificate) bool { return pki.KindOf(x) == pki.KindControl }}
	h := ss.Handler()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		liar := c.liars[id]
		c.mu.Unlock()
		if liar && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/shards/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	ts.TLS = ss.TLSConfig()
	ts.StartTLS()
	c.t.Cleanup(ts.Close)
	c.mu.Lock()
	c.nodes[id] = storage.Node{ID: id, Addr: ts.Listener.Addr().String()}
	c.servers[id] = ts
	c.disks[id] = st
	c.dirs[id] = dir
	c.mu.Unlock()
	return id
}

func (c *cluster) kill(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.servers[id].Close()
	delete(c.nodes, id)
}

func newControl(t *testing.T) *control.Server {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	raft, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	raftAddr := raft.Addr().String()
	raft.Close()
	srv, _, err := control.Init(filepath.Join(t.TempDir(), "control"), "test", ln.Addr().String(), raftAddr, nil)
	ln.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	if _, err := srv.CreateTenant("alice"); err != nil {
		t.Fatal(err)
	}
	if err := srv.CreateBucket("alice", "data"); err != nil {
		t.Fatal(err)
	}
	return srv
}

// put stores data as an object and records it.
func put(t *testing.T, c *cluster, srv *control.Server, key string, data []byte) (storage.ObjectKey, s3meta.Object) {
	ok, _ := storage.NewObjectKey()
	id := "obj-" + key
	layout, etag, err := c.store.Put(context.Background(), id, ok, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	obj := s3meta.Object{Bucket: "data", Key: key, ID: id, Size: layout.Size(), ETag: etag, WrappedKey: []byte{1}, Layout: layout}
	if _, err := srv.PutObject("alice", obj); err != nil {
		t.Fatal(err)
	}
	return ok, obj
}

func current(t *testing.T, srv *control.Server, key string) *s3meta.Object {
	o, err := srv.Object("alice", "data", key)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestRepairAfterLosingNodes(t *testing.T) {
	c := newCluster(t, 6) // 4+2
	srv := newControl(t)
	data := make([]byte, 10<<20) // three chunks
	rand.Read(data)
	key, obj := put(t, c, srv, "big", data)
	if obj.Layout.DataShards != 4 || obj.Layout.ParityShards != 2 {
		t.Fatalf("coding %d+%d", obj.Layout.DataShards, obj.Layout.ParityShards)
	}

	c.kill("n-0")
	c.kill("n-1")
	c.add()
	c.add()

	// Within the grace period nothing is copied.
	patient := &Repairer{Meta: srv, Store: c.store, After: time.Hour, Logger: log.New(io.Discard, "", 0)}
	if st, err := patient.Pass(context.Background()); err != nil || st.Rebuilt != 0 {
		t.Fatalf("repaired before grace: %+v %v", st, err)
	}

	r := &Repairer{Meta: srv, Store: c.store, After: -1, Logger: log.New(io.Discard, "", 0)}
	st, err := r.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Lost != 0 || st.Failed != 0 || st.Rebuilt == 0 {
		t.Fatalf("stats %+v", st)
	}
	got := current(t, srv, "big")
	for ci, ch := range got.Layout.Chunks {
		seen := map[string]bool{}
		if len(ch.Shards) != 6 {
			t.Fatalf("chunk %d has %d shards", ci, len(ch.Shards))
		}
		for _, sh := range ch.Shards {
			if sh.Node == "n-0" || sh.Node == "n-1" || seen[sh.Node] {
				t.Fatalf("chunk %d: bad placement %v", ci, ch.Shards)
			}
			seen[sh.Node] = true
		}
	}
	if st, _ := r.Pass(context.Background()); st.Rebuilt != 0 {
		t.Fatalf("second pass rebuilt %d", st.Rebuilt)
	}

	// Two more original nodes go: still readable from what repair wrote.
	c.kill("n-2")
	c.kill("n-3")
	var out bytes.Buffer
	if err := c.store.Get(context.Background(), got.ID, key, got.Layout, 0, -1, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("object changed after repair")
	}
}

func TestRepairFillsShardsAPartialWriteSkipped(t *testing.T) {
	c := newCluster(t, 3) // 2+1
	srv := newControl(t)
	_, obj := put(t, c, srv, "k", []byte("hello"))
	// Pretend one shard never got written.
	obj.Layout.Chunks[0].Shards = obj.Layout.Chunks[0].Shards[:2]
	if _, err := srv.PutObject("alice", obj); err != nil {
		t.Fatal(err)
	}
	r := &Repairer{Meta: srv, Store: c.store, After: -1, Logger: log.New(io.Discard, "", 0)}
	if st, err := r.Pass(context.Background()); err != nil || st.Rebuilt != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	if n := len(current(t, srv, "k").Layout.Chunks[0].Shards); n != 3 {
		t.Fatalf("shards %d", n)
	}
}

func TestMoveShardsRejectsStaleObject(t *testing.T) {
	c := newCluster(t, 3)
	srv := newControl(t)
	_, obj := put(t, c, srv, "k", []byte("hello"))
	sh := obj.Layout.Chunks[0].Shards[0]
	if err := srv.MoveShards("data", "k", "other-object", []s3meta.ShardMove{{Index: sh.Index, Hash: sh.Hash, Node: "n-9"}}); err == nil {
		t.Fatal("move applied to a different object")
	}
	if err := srv.MoveShards("data", "k", obj.ID, []s3meta.ShardMove{{Index: sh.Index, Hash: "wrong", Node: "n-9"}}); err == nil {
		t.Fatal("move applied with a different hash")
	}
	before := current(t, srv, "k") // shares its layout with the stored record
	if err := srv.MoveShards("data", "k", obj.ID, []s3meta.ShardMove{{Index: sh.Index, Hash: sh.Hash, Node: "n-9"}}); err != nil {
		t.Fatal(err)
	}
	if n := current(t, srv, "k").Layout.Chunks[0].Shards[0].Node; n != "n-9" {
		t.Fatalf("node %s", n)
	}
	if before.Layout.Chunks[0].Shards[0].Node == "n-9" {
		t.Fatal("stored record was modified in place")
	}
}

func TestCorruptShardIsScrubbedAndRebuilt(t *testing.T) {
	c := newCluster(t, 3) // 2+1
	srv := newControl(t)
	data := []byte("some bytes worth keeping")
	key, obj := put(t, c, srv, "k", data)
	sh := obj.Layout.Chunks[0].Shards[0]

	// Flip a byte on disk; the scrubber notices and drops the file.
	files, _ := filepath.Glob(filepath.Join(c.dirs[sh.Node], "*", "*", sh.Hash))
	if len(files) != 1 {
		t.Fatalf("shard file not found: %v", files)
	}
	b, _ := os.ReadFile(files[0])
	b[0] ^= 1
	if err := os.WriteFile(files[0], b, 0o600); err != nil {
		t.Fatal(err)
	}
	checked, removed, err := c.disks[sh.Node].Scrub(context.Background(), 0)
	if err != nil || checked == 0 || removed != 1 {
		t.Fatalf("scrub: checked %d removed %d err %v", checked, removed, err)
	}

	// Repair puts it back on the same node; the layout is unchanged.
	later := func() time.Time { return time.Now().Add(time.Hour) }
	r := &Repairer{Meta: srv, Store: c.store, After: -1, Now: later, Logger: log.New(io.Discard, "", 0)}
	st, err := r.Pass(context.Background())
	if err != nil || st.Rebuilt != 1 || st.Collected != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := c.disks[sh.Node].Get(sh.Hash); err != nil {
		t.Fatalf("shard not restored: %v", err)
	}
	got := current(t, srv, "k")
	if got.Layout.Chunks[0].Shards[0] != sh {
		t.Fatalf("layout changed: %v", got.Layout.Chunks[0].Shards)
	}
	var out bytes.Buffer
	if err := c.store.Get(context.Background(), got.ID, key, got.Layout, 0, -1, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("read back: %v", err)
	}
}

func TestUnreferencedShardsAreCollected(t *testing.T) {
	c := newCluster(t, 3)
	srv := newControl(t)
	_, kept := put(t, c, srv, "kept", []byte("keep me"))
	// Shards written but never recorded, as a failed upload leaves them.
	ok, _ := storage.NewObjectKey()
	orphan, _, err := c.store.Put(context.Background(), "orphan", ok, bytes.NewReader([]byte("lost upload")))
	if err != nil {
		t.Fatal(err)
	}
	quiet := log.New(io.Discard, "", 0)

	// Young orphans stay: their object may still be on its way.
	r := &Repairer{Meta: srv, Store: c.store, After: -1, Logger: quiet}
	if st, err := r.Pass(context.Background()); err != nil || st.Collected != 0 {
		t.Fatalf("collected young shards: %+v %v", st, err)
	}

	// Old enough, but first seen unreferenced now: a download may still be
	// reading them, so they are held a while longer.
	at := time.Now().Add(2 * DefaultGCGrace)
	r = &Repairer{Meta: srv, Store: c.store, After: -1, Logger: quiet, Now: func() time.Time { return at }}
	if st, err := r.Pass(context.Background()); err != nil || st.Collected != 0 {
		t.Fatalf("collected without the hold: %+v %v", st, err)
	}
	at = at.Add(GCHold + time.Second)
	st, err := r.Pass(context.Background())
	if err != nil || st.Collected != len(orphan.Chunks[0].Shards) || st.Rebuilt != 0 {
		t.Fatalf("%+v %v (orphan has %d shards)", st, err, len(orphan.Chunks[0].Shards))
	}
	for _, sh := range orphan.Chunks[0].Shards {
		if _, err := c.disks[sh.Node].Get(sh.Hash); err == nil {
			t.Fatalf("orphan shard %s still on %s", sh.Hash, sh.Node)
		}
	}
	for _, sh := range kept.Layout.Chunks[0].Shards {
		if _, err := c.disks[sh.Node].Get(sh.Hash); err != nil {
			t.Fatalf("referenced shard on %s deleted: %v", sh.Node, err)
		}
	}
}

func TestThinCodingIsUpgraded(t *testing.T) {
	c := newCluster(t, 2) // 1+1 while only two PCs are up
	srv := newControl(t)
	data := make([]byte, 9<<20) // three chunks
	rand.Read(data)
	key, obj := put(t, c, srv, "k", data)
	if obj.Layout.DataShards != 1 || obj.Layout.ParityShards != 1 {
		t.Fatalf("coding %d+%d", obj.Layout.DataShards, obj.Layout.ParityShards)
	}
	for i := 0; i < 4; i++ {
		c.add()
	}
	at := time.Now()
	r := &Repairer{Meta: srv, Store: c.store, After: -1, Logger: log.New(io.Discard, "", 0), Now: func() time.Time { return at }}
	st, err := r.Pass(context.Background())
	if err != nil || st.Upgraded != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	got := current(t, srv, "k")
	if got.Layout.DataShards != 4 || got.Layout.ParityShards != 2 || len(got.Layout.Chunks) != 3 {
		t.Fatalf("layout %d+%d, %d chunks", got.Layout.DataShards, got.Layout.ParityShards, len(got.Layout.Chunks))
	}
	// Any two PCs can now go.
	c.kill("n-0")
	c.kill("n-1")
	var out bytes.Buffer
	if err := c.store.Get(context.Background(), got.ID, key, got.Layout, 0, -1, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("read after upgrade: %v", err)
	}
	if st, _ := r.Pass(context.Background()); st.Upgraded != 0 {
		t.Fatalf("upgraded twice: %+v", st)
	}
}

func TestAuditsCatchANodeThatDropsShards(t *testing.T) {
	c := newCluster(t, 3) // 2+1
	srv := newControl(t)
	_, obj := put(t, c, srv, "k", []byte("hello"))
	liar := obj.Layout.Chunks[0].Shards[0].Node
	// It deletes its shards but keeps listing them.
	c.mu.Lock()
	c.liars = map[string]bool{liar: true}
	c.mu.Unlock()

	var logs bytes.Buffer
	r := &Repairer{Meta: srv, Store: c.store, After: -1, Logger: log.New(&logs, "", 0)}
	st, err := r.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), liar+" failed an audit") {
		t.Fatalf("audit missed the liar: %q", logs.String())
	}
	if st.Rebuilt != 1 {
		t.Fatalf("the shard was not rebuilt: %+v", st)
	}
	// Honest nodes pass.
	for id := range c.nodes {
		if id != liar && strings.Contains(logs.String(), id+" failed") {
			t.Fatalf("%s failed: %q", id, logs.String())
		}
	}
	// Audits wait AuditEvery before asking the node again.
	logs.Reset()
	if _, err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "failed an audit") {
		t.Fatalf("audited again at once: %q", logs.String())
	}
}

func TestRepairMovesShardsOffSuspendedNodes(t *testing.T) {
	c := newCluster(t, 4) // 3+1
	srv := newControl(t)
	_, obj := put(t, c, srv, "k", []byte("hello"))
	bad := obj.Layout.Chunks[0].Shards[0].Node
	c.add() // somewhere to move it
	c.mu.Lock()
	n := c.nodes[bad]
	n.Suspended = true
	c.nodes[bad] = n
	c.mu.Unlock()
	r := &Repairer{Meta: srv, Store: c.store, After: -1, AuditEvery: -1, Logger: log.New(io.Discard, "", 0)}
	if st, err := r.Pass(context.Background()); err != nil || st.Rebuilt != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	for _, sh := range current(t, srv, "k").Layout.Chunks[0].Shards {
		if sh.Node == bad {
			t.Fatalf("shard still on the suspended node: %+v", sh)
		}
	}
}
