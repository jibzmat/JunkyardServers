// Package agent is the node daemon's main loop: it keeps the registry from
// the control plane, liveness from gossip, and the WireGuard mesh in sync.
package agent

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/membership"
	"github.com/jibzmat/JunkyardServers/internal/mesh"
	"github.com/jibzmat/JunkyardServers/internal/nat"
	"github.com/jibzmat/JunkyardServers/internal/node"
)

const (
	// RefreshInterval is how often the registry is re-read from the control plane.
	RefreshInterval = 30 * time.Second
	// PathInterval is how often handshakes are checked and routes replanned.
	PathInterval = 10 * time.Second
)

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

	reflector  *nat.Reflector
	planner    *nat.Planner
	advertised string // the WireGuard endpoint currently in our gossip meta
	forwarding bool

	lastPeerCount int
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

		reflector:     nat.NewReflector(),
		planner:       nat.NewPlanner(),
		advertised:    n.Config.WGEndpoint,
		lastPeerCount: -1,
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
		OnMessage: a.onMessage,
	})
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.gossip = g
	a.mu.Unlock()
	defer g.Leave(5 * time.Second)

	if n, err := g.Join(cfg.Seeds); err != nil && n == 0 {
		a.log.Printf("gossip: no seed answered yet: %v", err)
	}

	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	pt := time.NewTicker(PathInterval)
	defer pt.Stop()
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
		case <-pt.C:
			a.sync()
		case <-a.kick:
			// A gossip change may be a node the registry copy doesn't
			// know yet, so re-read it before resyncing.
			a.refresh(ctx)
		}
	}
}

// Registry returns the latest member list from the control plane.
func (a *Agent) Registry() []cluster.Member {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]cluster.Member(nil), a.registry...)
}

// Alive returns the IDs of members gossip currently sees, or nil before
// gossip has started.
func (a *Agent) Alive() map[string]bool {
	a.mu.Lock()
	g := a.gossip
	a.mu.Unlock()
	if g == nil {
		return nil
	}
	out := map[string]bool{}
	for _, m := range g.Alive() {
		out[m.NodeID] = true
	}
	return out
}

// StorageAddr is where a member's shard server is reached: on its mesh IP
// when the mesh is up, otherwise on the host it gossips from.
func (a *Agent) StorageAddr(m cluster.Member) string {
	if m.StoragePort == 0 {
		return ""
	}
	host := m.MeshIP
	if !a.opts.WireGuard {
		h, _, err := net.SplitHostPort(m.GossipAddr)
		if err != nil {
			return ""
		}
		host = h
	}
	return net.JoinHostPort(host, strconv.Itoa(m.StoragePort))
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
		if !slices.Equal(addrs, a.client.Addrs()) {
			a.client.SetAddrs(addrs)
			a.saveControls(addrs)
		}
	}
	members, err := a.client.Members(rctx)
	if err != nil || !containsNode(members, a.node.Config.NodeID) {
		// A control node that just restarted may still be replaying its
		// log; retry soon rather than at the next refresh.
		if err != nil {
			a.log.Printf("registry: %v", err)
		}
		time.AfterFunc(2*time.Second, a.trigger)
	}
	if err == nil {
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

// Client is the agent's control-plane client. Its addresses follow control
// nodes being added and removed, so other services on this node share it.
func (a *Agent) Client() *control.Client {
	return a.client
}

// saveControls records the control addresses so a restart reaches the
// current control plane even if every node it joined through has left.
func (a *Agent) saveControls(addrs []string) {
	if a.node.Dir == "" {
		return
	}
	cfg := a.node.Config
	cfg.Controls = addrs
	cfg.Control = addrs[0]
	if err := node.SaveConfig(a.node.Dir, cfg); err != nil {
		a.log.Printf("saving control addresses: %v", err)
	}
}

func (a *Agent) sync() {
	a.mu.Lock()
	registry := append([]cluster.Member(nil), a.registry...)
	a.mu.Unlock()
	self := a.node.Config.NodeID
	alive := a.gossip.Alive()
	peers := Peers(registry, alive, self)
	a.updateAdvertised(registry)

	if !a.opts.WireGuard {
		if len(peers) != a.lastPeerCount {
			a.lastPeerCount = len(peers)
			a.log.Printf("mesh: %d peers known (wireguard disabled)", len(peers))
		}
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
	}

	status, err := a.dev.Status()
	if err != nil {
		a.log.Printf("mesh: %v", err)
		return
	}
	now := time.Now()
	handshakes := map[string]time.Time{}
	for _, p := range peers {
		st, ok := status[p.PublicKey]
		if !ok {
			continue
		}
		handshakes[p.NodeID] = st.LastHandshake
		// Tell the peer where its packets come from (endpoint reflection).
		if st.Endpoint != "" && now.Sub(st.LastHandshake) < nat.HandshakeFresh {
			if b, err := json.Marshal(seenMsg{Seen: st.Endpoint}); err == nil {
				_ = a.gossip.SendTo(p.NodeID, b)
			}
		}
	}

	relays := Relays(registry, alive, self)
	if !a.forwarding && a.isRelay(registry) {
		if err := mesh.EnableForwarding(a.opts.Interface); err != nil {
			a.log.Printf("relay: %v", err)
		} else {
			a.forwarding = true
			a.log.Printf("relay: forwarding enabled; this node relays for peers behind strict NATs")
		}
	}
	ids := make([]string, len(peers))
	for i, p := range peers {
		ids[i] = p.NodeID
	}
	routes := a.planner.Plan(ids, relays, handshakes, now)
	if err := a.dev.SetPeers(ApplyRoutes(peers, routes)); err != nil {
		a.log.Printf("mesh: %v", err)
	}
}

// seenMsg is the endpoint-reflection message: "your packets reach me from".
type seenMsg struct {
	Seen string `json:"seen"`
}

// onMessage handles direct gossip messages. Only registered nodes count.
func (a *Agent) onMessage(from string, payload []byte) {
	var m seenMsg
	if json.Unmarshal(payload, &m) != nil || m.Seen == "" {
		return
	}
	a.mu.Lock()
	known := false
	for _, mem := range a.registry {
		if mem.NodeID == from {
			known = true
			break
		}
	}
	a.mu.Unlock()
	if known {
		a.reflector.Observe(from, m.Seen, time.Now())
	}
}

// updateAdvertised publishes our reflected public endpoint in gossip, unless
// the operator set one explicitly with -wg-endpoint.
func (a *Agent) updateAdvertised(registry []cluster.Member) {
	if a.node.Config.WGEndpoint != "" {
		return
	}
	trusted := map[string]bool{}
	for _, m := range registry {
		trusted[m.NodeID] = m.Tier == cluster.TierTrusted
	}
	ep, ok := a.reflector.Endpoint(time.Now(), func(id string) bool { return trusted[id] })
	if !ok || ep == a.advertised {
		return
	}
	if err := a.gossip.SetMeta(membership.Meta{NodeID: a.node.Config.NodeID, WGEndpoint: ep}); err != nil {
		a.log.Printf("nat: advertise %s: %v", ep, err)
		return
	}
	a.log.Printf("nat: peers see this node at %s; advertising it", ep)
	a.advertised = ep
}

func (a *Agent) isRelay(registry []cluster.Member) bool {
	for _, m := range registry {
		if m.NodeID == a.node.Config.NodeID {
			return m.Tier == cluster.TierTrusted && publicEndpoint(a.advertised)
		}
	}
	return false
}

// Relays lists nodes that may relay for others: owner-trusted (relayed
// mesh traffic passes through them), alive in gossip, and advertising a
// public WireGuard endpoint. Sorted by node ID.
func Relays(registry []cluster.Member, alive []membership.Meta, self string) []string {
	live := map[string]string{}
	for _, m := range alive {
		live[m.NodeID] = m.WGEndpoint
	}
	var out []string
	for _, m := range registry {
		ep, ok := live[m.NodeID]
		if !ok || m.NodeID == self || m.Tier != cluster.TierTrusted {
			continue
		}
		if ep == "" {
			ep = m.WGEndpoint
		}
		if publicEndpoint(ep) {
			out = append(out, m.NodeID)
		}
	}
	sort.Strings(out)
	return out
}

// ApplyRoutes turns routes into the WireGuard peer list: a relayed node gets
// no peer entry of its own; its mesh address is routed through the relay.
func ApplyRoutes(peers []mesh.Peer, routes []nat.Route) []mesh.Peer {
	byID := map[string]int{}
	out := make([]mesh.Peer, 0, len(peers))
	relayed := map[string]bool{}
	for _, r := range routes {
		if r.Mode == nat.Relayed {
			relayed[r.NodeID] = true
		}
	}
	for _, p := range peers {
		if relayed[p.NodeID] {
			continue
		}
		p.Relayed = nil
		byID[p.NodeID] = len(out)
		out = append(out, p)
	}
	ips := map[string]string{}
	for _, p := range peers {
		ips[p.NodeID] = p.MeshIP
	}
	for _, r := range routes {
		if r.Mode != nat.Relayed {
			continue
		}
		if i, ok := byID[r.Via]; ok {
			out[i].Relayed = append(out[i].Relayed, ips[r.NodeID])
		}
	}
	return out
}

func containsNode(members []cluster.Member, id string) bool {
	for _, m := range members {
		if m.NodeID == id {
			return true
		}
	}
	return false
}

func publicEndpoint(ep string) bool {
	ap, err := netip.ParseAddrPort(ep)
	return err == nil && ap.Port() != 0 && nat.IsPublic(ap.Addr())
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
