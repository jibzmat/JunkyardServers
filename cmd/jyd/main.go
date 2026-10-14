// Command jyd is the Junkyard node daemon. It runs on every PC, serves the
// control plane API on PCs that hold the control role, gossips liveness, and
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

	"github.com/jibzmat/JunkyardServers/internal/agent"
	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/node"
)

func main() {
	dir := flag.String("dir", envOr("JY_DIR", "/var/lib/junkyard"), "state directory")
	listen := flag.String("listen", "", "control plane listen address (default: the address from init)")
	wg := flag.Bool("wireguard", true, "bring up the kernel WireGuard mesh (needs root)")
	iface := flag.String("interface", "jy0", "mesh interface name")
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
	if _, err := os.Stat(filepath.Join(controlDir, "state.json")); err == nil {
		srv, err := control.Open(controlDir)
		if err != nil {
			logger.Fatalf("control plane: %v", err)
		}
		addr := *listen
		if addr == "" {
			addr = srv.Address()
		}
		go func() {
			logger.Printf("control plane listening on %s", addr)
			if err := srv.ListenAndServe(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatalf("control plane: %v", err)
			}
		}()
	}

	a := agent.New(n, agent.Options{WireGuard: *wg, Interface: *iface, Logger: logger})
	if err := a.Run(ctx); err != nil {
		logger.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
