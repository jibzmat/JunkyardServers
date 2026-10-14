// Package mesh runs the WireGuard node mesh. Every node gets one interface
// (jy0 by default) with its mesh address, and one WireGuard peer per other
// node, so every node-to-node packet is authenticated and encrypted.
package mesh

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultInterface is the mesh interface name.
const DefaultInterface = "jy0"

// Keepalive keeps NAT mappings open between peers behind home routers.
const Keepalive = 25 * time.Second

// Peer is another node on the mesh.
type Peer struct {
	NodeID    string
	PublicKey string // base64 WireGuard public key
	Endpoint  string // host:port, empty if the peer is not directly reachable
	MeshIP    string
	// Relayed lists other nodes' mesh IPs routed through this peer, when it
	// acts as a relay for nodes we can't reach directly.
	Relayed []string
}

// Config is the full mesh configuration for one node.
type Config struct {
	PrivateKey wgtypes.Key
	ListenPort int
	MeshIP     string // this node's address
	MeshCIDR   string // the whole mesh, e.g. 100.64.0.0/10
	Peers      []Peer
}

// Validate checks addresses and keys before anything touches the kernel.
func (c Config) Validate() error {
	if _, err := netip.ParseAddr(c.MeshIP); err != nil {
		return fmt.Errorf("mesh ip: %w", err)
	}
	if _, err := netip.ParsePrefix(c.MeshCIDR); err != nil {
		return fmt.Errorf("mesh cidr: %w", err)
	}
	if c.ListenPort <= 0 || c.ListenPort > 65535 {
		return fmt.Errorf("mesh: listen port %d out of range", c.ListenPort)
	}
	for _, p := range c.Peers {
		if _, err := p.peerConfig(); err != nil {
			return fmt.Errorf("peer %s: %w", p.NodeID, err)
		}
	}
	return nil
}

// WGQuick renders the configuration in wg-quick format, for debugging or for
// bringing the mesh up by hand on a machine where jyd lacks privileges.
func (c Config) WGQuick() string {
	prefixBits := 10
	if p, err := netip.ParsePrefix(c.MeshCIDR); err == nil {
		prefixBits = p.Bits()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/%d\nListenPort = %d\n", c.PrivateKey, c.MeshIP, prefixBits, c.ListenPort)
	for _, p := range sortedPeers(c.Peers) {
		allowed := p.MeshIP + "/32"
		for _, r := range p.Relayed {
			allowed += ", " + r + "/32"
		}
		fmt.Fprintf(&b, "\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", p.NodeID, p.PublicKey, allowed)
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", int(Keepalive/time.Second))
	}
	return b.String()
}

func (p Peer) peerConfig() (wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, err
	}
	ip, err := netip.ParseAddr(p.MeshIP)
	if err != nil {
		return wgtypes.PeerConfig{}, err
	}
	allowed := []net.IPNet{hostNet(ip)}
	for _, r := range p.Relayed {
		rip, err := netip.ParseAddr(r)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("relayed ip: %w", err)
		}
		allowed = append(allowed, hostNet(rip))
	}
	ka := Keepalive
	pc := wgtypes.PeerConfig{
		PublicKey:                   key,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  allowed,
		PersistentKeepaliveInterval: &ka,
	}
	if p.Endpoint != "" {
		ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("endpoint: %w", err)
		}
		pc.Endpoint = ep
	}
	return pc, nil
}

func hostNet(ip netip.Addr) net.IPNet {
	return net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(ip.BitLen(), ip.BitLen())}
}

func sortedPeers(peers []Peer) []Peer {
	out := append([]Peer(nil), peers...)
	sort.Slice(out, func(i, j int) bool { return out[i].MeshIP < out[j].MeshIP })
	return out
}

// Device is a live WireGuard interface. Creating it needs root (or
// CAP_NET_ADMIN) and the kernel WireGuard module.
type Device struct {
	Name string
	wg   *wgctrl.Client
}

// Up creates (if needed) and configures the interface, assigns the mesh
// address and brings it up.
func Up(name string, cfg Config) (*Device, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if _, err := net.InterfaceByName(name); err != nil {
		if err := run("ip", "link", "add", "dev", name, "type", "wireguard"); err != nil {
			return nil, fmt.Errorf("mesh: create %s (needs root and the wireguard module): %w", name, err)
		}
	}
	prefix := netip.MustParsePrefix(cfg.MeshCIDR)
	addr := fmt.Sprintf("%s/%d", cfg.MeshIP, prefix.Bits())
	if err := run("ip", "address", "replace", addr, "dev", name); err != nil {
		return nil, err
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	d := &Device{Name: name, wg: wg}
	port := cfg.ListenPort
	key := cfg.PrivateKey
	if err := wg.ConfigureDevice(name, wgtypes.Config{PrivateKey: &key, ListenPort: &port}); err != nil {
		wg.Close()
		return nil, err
	}
	if err := d.SetPeers(cfg.Peers); err != nil {
		wg.Close()
		return nil, err
	}
	if err := run("ip", "link", "set", "up", "dev", name); err != nil {
		wg.Close()
		return nil, err
	}
	return d, nil
}

// SetPeers replaces the interface's peer list.
func (d *Device) SetPeers(peers []Peer) error {
	var pcs []wgtypes.PeerConfig
	var errs []error
	for _, p := range peers {
		pc, err := p.peerConfig()
		if err != nil {
			errs = append(errs, fmt.Errorf("peer %s: %w", p.NodeID, err))
			continue
		}
		pcs = append(pcs, pc)
	}
	if err := d.wg.ConfigureDevice(d.Name, wgtypes.Config{ReplacePeers: true, Peers: pcs}); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// PeerStatus is what the kernel knows about one peer.
type PeerStatus struct {
	Endpoint      string    // where its packets currently come from
	LastHandshake time.Time // zero if never
}

// Status returns the live state of every peer, keyed by public key.
func (d *Device) Status() (map[string]PeerStatus, error) {
	dev, err := d.wg.Device(d.Name)
	if err != nil {
		return nil, err
	}
	out := make(map[string]PeerStatus, len(dev.Peers))
	for _, p := range dev.Peers {
		ps := PeerStatus{LastHandshake: p.LastHandshakeTime}
		if p.Endpoint != nil {
			ps.Endpoint = p.Endpoint.String()
		}
		out[p.PublicKey.String()] = ps
	}
	return out, nil
}

// EnableForwarding lets this node relay packets between its WireGuard peers.
// A host firewall that drops forwarded traffic (some Docker setups do) must
// also allow forwarding from the mesh interface back to itself.
func EnableForwarding(name string) error {
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/" + name + "/forwarding",
	} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("mesh: enable forwarding: %w", err)
		}
	}
	return nil
}

// Close releases the control socket. The interface stays up so traffic is
// not interrupted by a daemon restart.
func (d *Device) Close() error { return d.wg.Close() }

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
