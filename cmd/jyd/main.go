// Command jyd is the Junkyard node daemon. It runs on every PC, serves the
// control plane API on PCs that are control nodes, gossips liveness, and
// keeps the WireGuard mesh in sync.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/agent"
	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/node"
)

func main() {
	dir := flag.String("dir", envOr("JY_DIR", "/var/lib/junkyard"), "state directory")
	wg := flag.Bool("wireguard", true, "bring up the kernel WireGuard mesh (needs root)")
	iface := flag.String("interface", "jy0", "mesh interface name")
	verbose := flag.Bool("v", false, "log Raft internals")
	flag.Parse()

	logger := log.New(os.Stderr, "jyd: ", log.LstdFlags|log.Lmsgprefix)

	n, err := node.Load(*dir)
	if err != nil {
		logger.Fatalf("load node (run jyctl init or jyctl join first): %v", err)
	}
	logger.Printf("node %s, mesh %s, tier %s, roles %v", n.Config.NodeID, n.Config.MeshIP, n.Config.Tier, n.Config.Roles)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	controlDir := filepath.Join(*dir, "control")
	if _, err := os.Stat(filepath.Join(controlDir, "control.json")); err == nil {
		var raftLog *log.Logger
		if *verbose {
			raftLog = log.New(os.Stderr, "raft: ", log.LstdFlags|log.Lmsgprefix)
		}
		srv, err := control.Open(controlDir, raftLog)
		if err != nil {
			logger.Fatalf("control plane: %v", err)
		}
		defer srv.Close()
		go func() {
			logger.Printf("control node %s serving on %s", srv.ID(), srv.APIAddr())
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatalf("control plane: %v", err)
			}
		}()
		go activate(ctx, srv, logger)
	}

	a := agent.New(n, agent.Options{WireGuard: *wg, Interface: *iface, Logger: logger})
	if err := a.Run(ctx); err != nil {
		logger.Fatal(err)
	}
}

// activate asks the leader to add a freshly enrolled control node to the
// Raft group, retrying until it is a voter.
func activate(ctx context.Context, srv *control.Server, logger *log.Logger) {
	// Give Raft a moment to load its configuration before deciding.
	time.Sleep(time.Second)
	if srv.IsVoter() {
		return
	}
	c := control.NewClient(srv.Peers(), srv.ClientCertificate(), srv.CA())
	for {
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := c.ActivateControl(rctx)
		cancel()
		if err == nil {
			logger.Printf("control node %s joined the Raft group", srv.ID())
			return
		}
		logger.Printf("control: activation pending: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
