// Package membership tracks which nodes are alive using encrypted SWIM gossip
// (hashicorp/memberlist).
//
// Gossip is only trusted for liveness and current endpoints. Strangers' PCs
// hold the gossip key too, so anything security-relevant (tier, roles, keys,
// mesh address) comes from the control plane's signed registry, never from
// gossip metadata. Nodes that gossip but are not in the registry are ignored.
package membership

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

// Meta is what a node advertises in gossip.
type Meta struct {
	NodeID     string `json:"id"`
	WGEndpoint string `json:"wg,omitempty"` // current public WireGuard host:port
}

// Config configures a Membership.
type Config struct {
	NodeID    string
	BindAddr  string // host:port to listen on
	Advertise string // host:port others should use; empty means BindAddr
	SecretKey []byte // 16, 24 or 32 bytes; gossip is AES-GCM encrypted
	Meta      Meta
	// OnChange is called (from a gossip goroutine) when a node joins, leaves
	// or updates. It must not block.
	OnChange func()
	// OnMessage receives direct messages from other members. The sender ID
	// is whatever the sender claimed, so treat the content as a hint. It
	// must not block.
	OnMessage func(from string, payload []byte)
	Logger    *log.Logger
}

// Membership is a running gossip member.
type Membership struct {
	list *memberlist.Memberlist
	del  *delegate
}

// Start begins gossiping. Call Join to contact other nodes.
func Start(cfg Config) (*Membership, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("membership: empty node id")
	}
	switch len(cfg.SecretKey) {
	case 16, 24, 32:
	default:
		return nil, errors.New("membership: gossip key must be 16, 24 or 32 bytes")
	}
	host, port, err := splitHostPort(cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("membership: bind address: %w", err)
	}

	// WAN defaults: home links have higher latency and loss than a LAN.
	mc := memberlist.DefaultWANConfig()
	mc.Name = cfg.NodeID
	mc.BindAddr = host
	mc.BindPort = port
	if host != "0.0.0.0" && host != "::" {
		mc.AdvertiseAddr = host
	}
	if cfg.Advertise != "" {
		ah, ap, err := splitHostPort(cfg.Advertise)
		if err != nil {
			return nil, fmt.Errorf("membership: advertise address: %w", err)
		}
		mc.AdvertiseAddr, mc.AdvertisePort = ah, ap
	}
	mc.SecretKey = cfg.SecretKey
	mc.GossipVerifyIncoming = true
	mc.GossipVerifyOutgoing = true
	if cfg.Logger != nil {
		mc.Logger = cfg.Logger
	} else {
		mc.LogOutput = io.Discard
	}

	meta, err := json.Marshal(cfg.Meta)
	if err != nil {
		return nil, err
	}
	d := &delegate{meta: meta, onChange: cfg.OnChange, onMessage: cfg.OnMessage}
	mc.Delegate = d
	mc.Events = d

	list, err := memberlist.Create(mc)
	if err != nil {
		return nil, err
	}
	return &Membership{list: list, del: d}, nil
}

// Join contacts the given gossip addresses and returns how many answered.
func (m *Membership) Join(seeds []string) (int, error) {
	if len(seeds) == 0 {
		return 0, nil
	}
	return m.list.Join(seeds)
}

// Addr returns this member's gossip address.
func (m *Membership) Addr() string {
	n := m.list.LocalNode()
	return net.JoinHostPort(n.Addr.String(), strconv.Itoa(int(n.Port)))
}

// Alive returns the metadata of every live member, including this one.
// Members whose metadata cannot be parsed or whose ID differs from their
// gossip name are dropped.
func (m *Membership) Alive() []Meta {
	var out []Meta
	for _, n := range m.list.Members() {
		var meta Meta
		if json.Unmarshal(n.Meta, &meta) != nil || meta.NodeID != n.Name {
			continue
		}
		out = append(out, meta)
	}
	return out
}

// SendTo sends a small direct message to one member.
func (m *Membership) SendTo(nodeID string, payload []byte) error {
	for _, n := range m.list.Members() {
		if n.Name == nodeID {
			b, err := json.Marshal(envelope{From: m.list.LocalNode().Name, Payload: payload})
			if err != nil {
				return err
			}
			return m.list.SendReliable(n, b)
		}
	}
	return fmt.Errorf("membership: %s is not a live member", nodeID)
}

// SetMeta replaces this node's advertised metadata and spreads it.
func (m *Membership) SetMeta(meta Meta) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	m.del.mu.Lock()
	m.del.meta = b
	m.del.mu.Unlock()
	return m.list.UpdateNode(5 * time.Second)
}

type envelope struct {
	From    string `json:"f"`
	Payload []byte `json:"p"`
}

// Leave announces departure and stops gossiping.
func (m *Membership) Leave(timeout time.Duration) error {
	err := m.list.Leave(timeout)
	return errors.Join(err, m.list.Shutdown())
}

type delegate struct {
	mu        sync.Mutex
	meta      []byte
	onChange  func()
	onMessage func(from string, payload []byte)
}

func (d *delegate) NodeMeta(limit int) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.meta) > limit {
		return nil
	}
	return d.meta
}

func (d *delegate) NotifyMsg(b []byte) {
	if d.onMessage == nil {
		return
	}
	var e envelope
	if json.Unmarshal(b, &e) != nil || e.From == "" {
		return
	}
	d.onMessage(e.From, e.Payload)
}

func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte { return nil }
func (d *delegate) LocalState(join bool) []byte                { return nil }
func (d *delegate) MergeRemoteState(buf []byte, join bool)     {}

func (d *delegate) NotifyJoin(*memberlist.Node)   { d.changed() }
func (d *delegate) NotifyLeave(*memberlist.Node)  { d.changed() }
func (d *delegate) NotifyUpdate(*memberlist.Node) { d.changed() }

func (d *delegate) changed() {
	if d.onChange != nil {
		d.onChange()
	}
}

func splitHostPort(addr string) (string, int, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", ps)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, port, nil
}
