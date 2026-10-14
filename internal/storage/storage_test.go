package storage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/pki"
)

func TestSealOpen(t *testing.T) {
	k, _ := NewObjectKey()
	sealed, err := SealChunk(k, "obj", 3, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := OpenChunk(k, "obj", 3, sealed); err != nil || string(p) != "hello" {
		t.Fatalf("got %q %v", p, err)
	}
	if _, err := OpenChunk(k, "obj", 4, sealed); err == nil {
		t.Fatal("chunk opened at the wrong index")
	}
	if _, err := OpenChunk(k, "other", 3, sealed); err == nil {
		t.Fatal("chunk opened under another object")
	}
	k2, _ := ObjectKeyFromBytes(k.Bytes())
	if k2 != k {
		t.Fatal("key round trip")
	}
}

func TestEncodeDecodeWithLoss(t *testing.T) {
	data := make([]byte, 1000)
	rand.Read(data)
	shards, err := Encode(data, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	shards[0], shards[5] = nil, nil
	got, err := Decode(shards, 4, 2, len(data))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("decode: %v", err)
	}
}

func TestChooseCoding(t *testing.T) {
	for n, want := range map[int][2]int{1: {1, 0}, 2: {1, 1}, 3: {2, 1}, 4: {2, 2}, 5: {3, 2}, 6: {4, 2}, 20: {4, 2}} {
		k, m := ChooseCoding(n)
		if k != want[0] || m != want[1] {
			t.Errorf("n=%d: %d+%d, want %d+%d", n, k, m, want[0], want[1])
		}
		if k+m > n {
			t.Errorf("n=%d: %d shards on %d nodes", n, k+m, n)
		}
	}
}

func TestPlaceStable(t *testing.T) {
	nodes := []string{"a", "b", "c", "d", "e", "f"}
	p1 := Place("x", nodes, 3)
	p2 := Place("x", []string{"f", "e", "d", "c", "b", "a"}, 3)
	if fmt.Sprint(p1) != fmt.Sprint(p2) {
		t.Fatal("placement depends on input order")
	}
	// Removing a node that wasn't chosen changes nothing.
	var rest []string
	for _, n := range nodes {
		if n != Place("x", nodes, 6)[5] {
			rest = append(rest, n)
		}
	}
	if fmt.Sprint(Place("x", rest, 3)) != fmt.Sprint(p1) {
		t.Fatal("removing an unchosen node moved shards")
	}
}

// testCluster runs n shard servers behind mutual TLS.
type testCluster struct {
	ca      *pki.CA
	store   *Store
	servers []*httptest.Server
	stores  []*ShardStore
	mu      sync.Mutex
	nodes   []Node
}

func newTestCluster(t *testing.T, n int) *testCluster {
	t.Helper()
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	issue := func(name string, kind pki.Kind) (*x509.Certificate, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		der, err := ca.Issue(kind, name, pub, time.Hour, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, priv
	}
	tc := &testCluster{ca: ca}
	for i := 0; i < n; i++ {
		cert, key := issue(fmt.Sprintf("n-%d", i), pki.KindNode)
		st, err := OpenShardStore(filepath.Join(t.TempDir(), "shards"))
		if err != nil {
			t.Fatal(err)
		}
		srv := &ShardServer{
			Store: st, Cert: pki.TLSCertificate(cert.Raw, key, ca.Cert), CA: ca.Cert,
			MayDelete: func(c *x509.Certificate) bool { return pki.KindOf(c) == pki.KindControl },
		}
		ts := httptest.NewUnstartedServer(srv.Handler())
		ts.TLS = srv.TLSConfig()
		ts.StartTLS()
		t.Cleanup(ts.Close)
		tc.servers = append(tc.servers, ts)
		tc.stores = append(tc.stores, st)
		tc.nodes = append(tc.nodes, Node{ID: fmt.Sprintf("n-%d", i), Addr: ts.Listener.Addr().String()})
	}
	gwCert, gwKey := issue("gateway", pki.KindControl)
	tc.store = &Store{
		Client: NewShardClient(pki.TLSCertificate(gwCert.Raw, gwKey, ca.Cert), ca.Cert),
		Nodes: func() []Node {
			tc.mu.Lock()
			defer tc.mu.Unlock()
			return append([]Node(nil), tc.nodes...)
		},
	}
	return tc
}

func (tc *testCluster) stop(i int) { tc.servers[i].Close() }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestPutGetSurvivesTwoLostNodes(t *testing.T) {
	tc := newTestCluster(t, 6)
	ctx := context.Background()
	data := randomBytes(2*ChunkSize + 12345)
	key, _ := NewObjectKey()
	layout, etag, err := tc.store.Put(ctx, "o1", key, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if layout.DataShards != 4 || layout.ParityShards != 2 || len(layout.Chunks) != 3 || layout.Size() != int64(len(data)) {
		t.Fatalf("layout %d+%d, %d chunks, size %d", layout.DataShards, layout.ParityShards, len(layout.Chunks), layout.Size())
	}
	if len(etag) != 32 {
		t.Fatalf("etag %q", etag)
	}
	// Each chunk's shards sit on 6 distinct nodes.
	for _, c := range layout.Chunks {
		seen := map[string]bool{}
		for _, s := range c.Shards {
			if seen[s.Node] {
				t.Fatalf("two shards of a chunk on %s", s.Node)
			}
			seen[s.Node] = true
		}
	}

	tc.stop(1)
	tc.stop(4)
	var out bytes.Buffer
	if err := tc.store.Get(ctx, "o1", key, layout, 0, -1, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("data differs after losing 2 nodes")
	}

	// Range across a chunk boundary.
	out.Reset()
	off := int64(ChunkSize - 10)
	if err := tc.store.Get(ctx, "o1", key, layout, off, 30, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data[off:off+30]) {
		t.Fatal("range read wrong")
	}

	tc.stop(0)
	if err := tc.store.Get(ctx, "o1", key, layout, 0, -1, &bytes.Buffer{}); err == nil {
		t.Fatal("read succeeded with 3 of 6 nodes gone")
	}
}

func TestStorageNodesSeeOnlyCiphertext(t *testing.T) {
	tc := newTestCluster(t, 3)
	marker := bytes.Repeat([]byte("SECRET-PLAINTEXT"), 1000)
	key, _ := NewObjectKey()
	if _, _, err := tc.store.Put(context.Background(), "o", key, bytes.NewReader(marker)); err != nil {
		t.Fatal(err)
	}
	for _, st := range tc.stores {
		filepath.Walk(st.dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			b, _ := os.ReadFile(path)
			if bytes.Contains(b, []byte("SECRET-PLAINTEXT")) {
				t.Fatalf("plaintext found in shard %s", path)
			}
			return nil
		})
	}
}

func TestSmallClustersAndEmptyObject(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		tc := newTestCluster(t, n)
		for _, size := range []int{0, 1, 100000} {
			data := randomBytes(size)
			key, _ := NewObjectKey()
			layout, _, err := tc.store.Put(context.Background(), "o", key, bytes.NewReader(data))
			if err != nil {
				t.Fatalf("n=%d size=%d: %v", n, size, err)
			}
			var out bytes.Buffer
			if err := tc.store.Get(context.Background(), "o", key, layout, 0, -1, &out); err != nil {
				t.Fatalf("n=%d size=%d get: %v", n, size, err)
			}
			if !bytes.Equal(out.Bytes(), data) {
				t.Fatalf("n=%d size=%d: data differs", n, size)
			}
		}
	}
}

func TestTamperedShardIsRejected(t *testing.T) {
	st, _ := OpenShardStore(t.TempDir())
	data := []byte("shard bytes")
	h := ShardHash(data)
	if err := st.Put(h, data); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(h, []byte("other")); err == nil {
		t.Fatal("stored data under the wrong hash")
	}
	os.WriteFile(st.path(h), []byte("rotted"), 0o600)
	if _, err := st.Get(h); err == nil {
		t.Fatal("served a corrupted shard")
	}
}

func TestOnlyAllowedCallersDelete(t *testing.T) {
	tc := newTestCluster(t, 1)
	data := []byte("x")
	h := ShardHash(data)
	tc.stores[0].Put(h, data)
	addr := tc.nodes[0].Addr

	// A stranger's node certificate may read but not delete.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := tc.ca.Issue(pki.KindNode, "n-stranger", pub, time.Hour)
	stranger := NewShardClient(pki.TLSCertificate(der, priv, tc.ca.Cert), tc.ca.Cert)
	if _, err := stranger.Get(context.Background(), addr, h); err != nil {
		t.Fatalf("stranger read: %v", err)
	}
	if err := stranger.Delete(context.Background(), addr, h); err == nil {
		t.Fatal("stranger deleted a shard")
	}
	if err := tc.store.Client.Delete(context.Background(), addr, h); err != nil {
		t.Fatalf("control delete: %v", err)
	}
	if _, err := tc.stores[0].Get(h); !errors.Is(err, ErrNotFound) {
		t.Fatalf("shard still there: %v", err)
	}
}
