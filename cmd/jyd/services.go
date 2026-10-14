package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/agent"
	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/compute"
	"github.com/jibzmat/JunkyardServers/internal/node"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3gw"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// mayDelete lets control nodes and owner-trusted gateways delete shards.
func mayDelete(a *agent.Agent) func(*x509.Certificate) bool {
	return func(c *x509.Certificate) bool {
		switch pki.KindOf(c) {
		case pki.KindControl:
			return true
		case pki.KindNode:
			for _, m := range a.Registry() {
				if m.NodeID == c.Subject.CommonName {
					return m.Tier == cluster.TierTrusted && m.Has(cluster.RoleGateway)
				}
			}
		}
		return false
	}
}

// startStorage serves this node's shards to the cluster.
func startStorage(dir string, n *node.Node, a *agent.Agent, logger *log.Logger) (*http.Server, error) {
	st, err := storage.OpenShardStore(filepath.Join(dir, "shards"))
	if err != nil {
		return nil, err
	}
	ss := &storage.ShardServer{Store: st, Cert: n.TLSCertificate(), CA: n.CA, MayDelete: mayDelete(a)}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(n.Config.StoragePort))
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: ss.Handler(), TLSConfig: ss.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		logger.Printf("storage: serving shards on %s", ln.Addr())
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("storage: %v", err)
		}
	}()
	go scrub(st, logger)
	return srv, nil
}

// scrub re-reads every local shard once a day and drops any that rotted;
// the control leader's repair pass then rebuilds them from other nodes.
func scrub(st *storage.ShardStore, logger *log.Logger) {
	time.Sleep(10 * time.Minute) // let the node settle after a restart
	for {
		checked, removed, err := st.Scrub(context.Background(), 20*time.Millisecond)
		switch {
		case err != nil:
			logger.Printf("storage: scrub: %v", err)
		case removed > 0:
			logger.Printf("storage: scrub checked %d shards and removed %d corrupt ones", checked, removed)
		}
		time.Sleep(24 * time.Hour)
	}
}

// startGateway serves the S3 API.
func startGateway(n *node.Node, a *agent.Agent, logger *log.Logger) (*http.Server, *s3gw.Gateway, error) {
	gw := &s3gw.Gateway{
		Meta: a.Client(), // follows control nodes being added and removed
		EC2:  a.Client(),
		Store: &storage.Store{
			Client: storage.NewShardClient(n.TLSCertificate(), n.CA),
			Nodes:  func() []storage.Node { return storageNodes(a) },
		},
		Logger: logger,
	}
	ln, err := net.Listen("tcp", n.Config.S3Listen)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{Handler: gw, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		logger.Printf("gateway: S3 API on http://%s", ln.Addr())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("gateway: %v", err)
		}
	}()
	return srv, gw, nil
}

// storageNodes lists live storage nodes with their shard server addresses.
// Before gossip has seen anyone, every registered storage node counts.
func storageNodes(a *agent.Agent) []storage.Node {
	alive := a.Alive()
	var out []storage.Node
	for _, m := range a.Registry() {
		if !m.Has(cluster.RoleStorage) || (len(alive) > 0 && !alive[m.NodeID]) {
			continue
		}
		if addr := a.StorageAddr(m); addr != "" {
			out = append(out, storage.Node{ID: m.NodeID, Addr: addr, Name: m.MeshIP})
		}
	}
	return out
}

// startCompute runs this PC's instances, if it has what that takes.
func startCompute(ctx context.Context, dir string, a *agent.Agent, emulate bool, logger *log.Logger) {
	q := &compute.QEMU{Emulate: emulate}
	if err := q.Check(); err != nil {
		logger.Printf("compute: not running instances: %v", err)
		return
	}
	h := &compute.Host{Control: a.Client(), Driver: q, Dir: filepath.Join(dir, "compute"), Logger: logger, Metadata: true}
	logger.Printf("compute: running instances (emulated: %v)", emulate)
	go h.Run(ctx, 3*time.Second)
}
