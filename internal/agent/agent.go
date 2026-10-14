// Package agent is the node daemon's main loop: it keeps the registry from
// the control plane, liveness from gossip, and the WireGuard mesh in sync.
package agent

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/membership"
	"github.com/jibzmat/JunkyardServers/internal/mesh"
	"github.com/jibzmat/JunkyardServers/internal/node"
)

// RefreshInterval is how often the registry is re-read from the control plane.
const RefreshInterval = 30 * time.Second

// Options configures an Agent.
type Options struct {
	// WireGuard brings up the kernel mesh interface. Without it the agent
	// only gossips and logs the mesh config it would apply.
	WireGuard bool
	Interface string
	Logger    *log.Logger
}

// Agent runs one node.
type Agent struct {
	node   *node.Node
	client *control.Client
	opts   Options
	log    *log.Logger

	gossip *membership.Membership
	dev    *mesh.Device

	mu       sync.Mutex
	registry []cluster.Member
	kick     chan struct{}
}

// New prepares an agent for a joined node.
func New(n *node.Node, opts Options) *Agent {
	if opts.Interface == "" {
		opts.Interface = mesh.DefaultInterface
	}
	lg := opts.Logger
	if lg == nil {
		lg = log.Default()
	}
	return &Agent{
		node:   n,
		client: control.NewClient(n.Config.ControlAddrs(), n.TLSCertificate(), n.CA),
		opts:   opts,
		log:    lg,
		kick:   make(chan struct{}, 1),
	}
}

// Run gossips and syncs the mesh until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	cfg := a.node.Config
	g, err := membership.Start(membership.Config{
		NodeID:    cfg.NodeID,
		BindAddr:  cfg.GossipAddr,
		SecretKey: cfg.GossipKey,
		Meta:      membership.Meta{NodeID: cfg.NodeID, WGEndpoint: cfg.WGEndpoint},
		OnChange:  a.trigger,
	})
	if err != nil {
		return err
	}
	a.gossip = g
	defer g.Leave(5 * time.Second)

	if n, err := g.Join(cfg.Seeds); err != nil && n == 0 {
		a.log.Printf("gossip: no seed answered yet: %v", err)
	}

	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	a.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			if a.dev != nil {
				a.dev.Close()
			}
			return nil
		case <-t.C:
			a.refresh(ctx)
		case <-a.kick:
			// A gossip change may be a node the registry copy doesn't
			// know yet, so re-read it before resyncing.
			a.refresh(ctx)
		}
	}
}

func (a *Agent) trigger() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// refresh re-reads the registry, joins any gossip addresses not yet seen,
// and resyncs the mesh.
func (a *Agent) refresh(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Pick up control nodes added or removed since this node joined.
	if controls, err := a.client.Controls(rctx); err == nil && len(controls) > 0 {
		addrs := make([]string, 0, len(controls))
		for _, c := range controls {
			addrs = append(addrs, c.APIAddr)
		}
		a.client = control.NewClient(addrs, a.node.TLSCertificate(), a.node.CA)
	}
	members, err := a.client.Members(rctx)
	if err != nil {
		a.log.Printf("registry: %v", err)
	} else {
		a.mu.Lock()
		a.registry = members
		a.mu.Unlock()
		var seeds []string
		for _, m := range members {
			if m.NodeID != a.node.Config.NodeID && m.GossipAddr != "" {
				seeds = append(seeds, m.GossipAddr)
			}
		}
		if len(seeds) > 0 {
			_, _ = a.gossip.Join(seeds)
		}
	}
	a.sync()
}

func (a *Agent) sync() {
	a.mu.Lock()
	registry := append([]cluster.Member(nil), a.registry...)
	a.mu.Unlock()
	peers := Peers(registry, a.gossip.Alive(), a.node.Config.NodeID)

	if !a.opts.WireGuard {
		a.log.Printf("mesh: %d peers known (wireguard disabled)", len(peers))
		return
	}
	if a.dev == nil {
		cfg := a.node.Config
		dev, err := mesh.Up(a.opts.Interface, mesh.Config{
			PrivateKey: a.node.Keys.WireGuard,
			ListenPort: cfg.WGPort,
			MeshIP:     cfg.MeshIP,
			MeshCIDR:   cfg.MeshCIDR,
			Peers:      peers,
		})
		if err != nil {
			a.log.Printf("mesh: %v", err)
			return
		}
		a.dev = dev
		a.log.Printf("mesh: %s up as %s with %d peers", a.opts.Interface, cfg.MeshIP, len(peers))
		return
	}
	if err := a.dev.SetPeers(peers); err != nil {
		a.log.Printf("mesh: %v", err)
	}
}

// Peers builds the WireGuard peer list: every registered node except self,
// with keys and addresses from the registry and the endpoint from gossip
// when the node is alive and advertises one. Gossip never adds a node the
// registry does not know.
func Peers(registry []cluster.Member, alive []membership.Meta, self string) []mesh.Peer {
	endpoints := map[string]string{}
	for _, m := range alive {
		if m.WGEndpoint != "" {
			endpoints[m.NodeID] = m.WGEndpoint
		}
	}
	var out []mesh.Peer
	for _, m := range registry {
		if m.NodeID == self {
			continue
		}
		ep := m.WGEndpoint
		if live, ok := endpoints[m.NodeID]; ok {
			ep = live
		}
		out = append(out, mesh.Peer{NodeID: m.NodeID, PublicKey: m.WGPublic, Endpoint: ep, MeshIP: m.MeshIP})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}
