// Package vnet runs a compute PC's side of VPC networking: one network
// namespace per VPC with instances here, routed taps, VXLAN to the VPC's
// other PCs over the mesh, NAT to the internet, and security groups. See
// docs/design.md, "Networking (M3)".
package vnet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

const (
	nsPrefix   = "jy-"
	vxlanPort  = "4789"
	uplink     = "up0" // the namespace's end of its veth to the PC
	vxlanDev   = "vx0"
	MetadataIP = "169.254.169.254"
)

// transit is where each namespace's veth pair gets a /31.
var transit = netip.MustParsePrefix("198.18.0.0/15")

// NSName is the network namespace of a VPC.
func NSName(vpcID string) string { return nsPrefix + vpcID }

// TapName is an instance's tap device (at most 15 characters).
func TapName(instanceID string) string {
	id := strings.TrimPrefix(instanceID, "i-")
	if len(id) > 13 {
		id = id[:13]
	}
	return "jy" + id
}

// Manager keeps this PC's VPC namespaces in line with the host view.
type Manager struct {
	// Dir holds the transit index of each VPC.
	Dir    string
	Logger *log.Logger

	mu      sync.Mutex
	index   map[string]int    // VPC -> transit index
	ready   map[string]bool   // namespaces set up by this process
	applied map[string]string // what was last applied, by key, as a hash
	root    bool
}

func (m *Manager) logf(format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func output(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(ee.Stderr))
		}
		return nil, err
	}
	return out, nil
}

// inNS runs a command in a namespace.
func inNS(ctx context.Context, ns, name string, args ...string) error {
	return run(ctx, "ip", append([]string{"netns", "exec", ns, name}, args...)...)
}

func hash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// changed reports whether v differs from what was applied under key.
func (m *Manager) changed(key string, v any) (string, bool) {
	h := hash(v)
	m.mu.Lock()
	defer m.mu.Unlock()
	return h, m.applied[key] != h
}

func (m *Manager) done(key, h string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applied == nil {
		m.applied = map[string]string{}
	}
	m.applied[key] = h
}

// Check reports what's missing to run VPC networking.
func Check() error {
	var missing []string
	for _, b := range []string{"ip", "iptables", "iptables-restore", "bridge"} {
		if _, err := exec.LookPath(b); err != nil {
			missing = append(missing, b)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("vnet: missing %s", strings.Join(missing, ", "))
	}
	return nil
}

// Sync makes this PC's namespaces match nets: node is this PC, meshIP its
// VXLAN underlay address.
func (m *Manager) Sync(ctx context.Context, node, meshIP string, nets []ec2meta.VPCNet) error {
	if err := m.rootSetup(ctx); err != nil {
		return err
	}
	want := map[string]bool{}
	var errs []error
	for _, n := range nets {
		want[NSName(n.VPC.ID)] = true
		if err := m.syncVPC(ctx, node, meshIP, n); err != nil {
			errs = append(errs, fmt.Errorf("vpc %s: %w", n.VPC.ID, err))
		}
	}
	if err := m.syncVXLANFilter(ctx, node, nets); err != nil {
		errs = append(errs, err)
	}
	if err := m.syncPublic(ctx, node, nets); err != nil {
		errs = append(errs, err)
	}
	// Namespaces of VPCs with no instances here any more.
	entries, _ := os.ReadDir("/run/netns")
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, nsPrefix+"vpc-") || want[name] {
			continue
		}
		vpc := strings.TrimPrefix(name, nsPrefix)
		if err := run(ctx, "ip", "netns", "del", name); err != nil {
			errs = append(errs, err)
			continue
		}
		m.mu.Lock()
		delete(m.ready, vpc)
		for k := range m.applied {
			if strings.HasSuffix(k, "/"+vpc) {
				delete(m.applied, k)
			}
		}
		m.mu.Unlock()
		m.freeIndex(vpc)
	}
	return errors.Join(errs...)
}

// rootSetup is the PC's own side, once per process: forwarding, NAT for
// the namespaces' traffic, and keeping instances off the mesh, the PC's
// LAN and the PC itself.
func (m *Manager) rootSetup(ctx context.Context) error {
	m.mu.Lock()
	ok := m.root
	m.mu.Unlock()
	if ok {
		return nil
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("vnet: enabling forwarding: %w", err)
	}
	t := transit.String()
	var fwd [][]string
	for _, d := range []string{"100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", t} {
		fwd = append(fwd, []string{"-i", "jyv+", "-d", d, "-j", "DROP"})
	}
	fwd = append(fwd,
		[]string{"-i", "jyv+", "-j", "ACCEPT"},
		[]string{"-o", "jyv+", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		[]string{"-o", "jyv+", "-j", "DROP"},
	)
	chains := []struct {
		table, chain, hook string
		rules              [][]string
	}{
		{"nat", "JY-NAT", "POSTROUTING", [][]string{{"-s", t, "!", "-d", t, "-j", "MASQUERADE"}}},
		{"filter", "JY-FORWARD", "FORWARD", fwd},
		{"filter", "JY-INPUT", "INPUT", [][]string{
			{"-i", "jyv+", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			{"-i", "jyv+", "-j", "DROP"},
		}},
	}
	for _, c := range chains {
		if err := chain(ctx, c.table, c.chain, c.hook, c.rules); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.root = true
	m.mu.Unlock()
	return nil
}

// chain rebuilds one of our iptables chains in the PC's namespace and
// hooks it in first.
func chain(ctx context.Context, table, name, hook string, rules [][]string) error {
	_ = run(ctx, "iptables", "-t", table, "-N", name)
	if err := run(ctx, "iptables", "-t", table, "-F", name); err != nil {
		return err
	}
	for _, r := range rules {
		if err := run(ctx, "iptables", append([]string{"-t", table, "-A", name}, r...)...); err != nil {
			return err
		}
	}
	if run(ctx, "iptables", "-t", table, "-C", hook, "-j", name) != nil {
		return run(ctx, "iptables", "-t", table, "-I", hook, "-j", name)
	}
	return nil
}

// --- transit addresses ---

func (m *Manager) indexFile() string { return filepath.Join(m.Dir, "vpc-index.json") }

func (m *Manager) loadIndex() {
	if m.index != nil {
		return
	}
	m.index = map[string]int{}
	if b, err := os.ReadFile(m.indexFile()); err == nil {
		_ = json.Unmarshal(b, &m.index)
	}
}

func (m *Manager) saveIndex() error {
	b, _ := json.Marshal(m.index)
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	tmp := m.indexFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.indexFile())
}

// indexFor returns a VPC's transit index, allocating one if needed.
func (m *Manager) indexFor(vpc string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadIndex()
	if i, ok := m.index[vpc]; ok {
		return i, nil
	}
	used := map[int]bool{}
	for _, i := range m.index {
		used[i] = true
	}
	max := 1 << (32 - transit.Bits() - 1)
	for i := 0; i < max; i++ {
		if !used[i] {
			m.index[vpc] = i
			return i, m.saveIndex()
		}
	}
	return 0, errors.New("vnet: no transit addresses left")
}

func (m *Manager) freeIndex(vpc string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadIndex()
	delete(m.index, vpc)
	_ = m.saveIndex()
}

// transitAddrs are the PC's and the namespace's ends of veth i.
func transitAddrs(i int) (root, ns netip.Addr) {
	b := transit.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) + uint32(2*i)
	root = netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	return root, root.Next()
}

// vxlanMAC is the MAC of a PC's VXLAN device in every VPC, derived from its
// mesh address so other PCs know it without asking.
func vxlanMAC(meshIP string) string {
	a, err := netip.ParseAddr(meshIP)
	if err != nil || !a.Is4() {
		return ""
	}
	b := a.As4()
	return fmt.Sprintf("02:6a:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3])
}

// --- one VPC ---

func (m *Manager) syncVPC(ctx context.Context, node, meshIP string, n ec2meta.VPCNet) error {
	vpc := n.VPC.ID
	ns := NSName(vpc)
	m.mu.Lock()
	ready := m.ready[vpc]
	m.mu.Unlock()
	if !ready {
		if err := m.setupNS(ctx, n, meshIP); err != nil {
			return err
		}
		m.mu.Lock()
		if m.ready == nil {
			m.ready = map[string]bool{}
		}
		m.ready[vpc] = true
		m.mu.Unlock()
	}
	var errs []error
	if err := m.syncGateways(ctx, ns, n); err != nil {
		errs = append(errs, err)
	}
	if err := m.syncRemote(ctx, ns, node, meshIP, n); err != nil {
		errs = append(errs, err)
	}
	if err := m.syncSourceRoutes(ctx, ns, node, meshIP, n); err != nil {
		errs = append(errs, err)
	}
	for _, ep := range n.Endpoints {
		if ep.Host != node {
			continue
		}
		if err := m.plug(ctx, ns, TapName(ep.Instance), ep.IP, false); err != nil && !errors.Is(err, errNoTap) {
			errs = append(errs, err)
		}
	}
	if err := m.syncFirewall(ctx, ns, node, n); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// setupNS creates (or re-checks) a VPC's namespace: loopback with the
// metadata address, the veth to the PC, the VXLAN device and routes.
func (m *Manager) setupNS(ctx context.Context, n ec2meta.VPCNet, meshIP string) error {
	vpc, ns := n.VPC.ID, NSName(n.VPC.ID)
	if _, err := os.Stat(filepath.Join("/run/netns", ns)); err != nil {
		if err := run(ctx, "ip", "netns", "add", ns); err != nil {
			return err
		}
	}
	steps := [][]string{
		{"ip", "-n", ns, "link", "set", "lo", "up"},
		{"ip", "-n", ns, "addr", "replace", MetadataIP + "/32", "dev", "lo"},
	}
	for _, s := range steps {
		if err := run(ctx, s[0], s[1:]...); err != nil {
			return err
		}
	}
	for _, kv := range []string{"net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"} {
		if err := inNS(ctx, ns, "sysctl", "-qw", kv); err != nil {
			return err
		}
	}
	idx, err := m.indexFor(vpc)
	if err != nil {
		return err
	}
	rootIP, nsIP := transitAddrs(idx)
	veth := fmt.Sprintf("jyv%x", idx)
	if _, err := net.InterfaceByName(veth); err != nil {
		if err := run(ctx, "ip", "link", "add", veth, "type", "veth", "peer", "name", uplink, "netns", ns); err != nil {
			return err
		}
	}
	steps = [][]string{
		{"ip", "addr", "replace", rootIP.String() + "/31", "dev", veth},
		{"ip", "link", "set", veth, "up"},
		{"ip", "-n", ns, "addr", "replace", nsIP.String() + "/31", "dev", uplink},
		{"ip", "-n", ns, "link", "set", uplink, "up"},
		{"ip", "-n", ns, "route", "replace", "default", "via", rootIP.String(), "dev", uplink},
		// Addresses of the VPC with no instance are dropped here rather
		// than sent to the PC.
		{"ip", "-n", ns, "route", "replace", "unreachable", n.VPC.CIDR},
	}
	for _, s := range steps {
		if err := run(ctx, s[0], s[1:]...); err != nil {
			return err
		}
	}
	if meshIP == "" {
		return nil // no mesh: instances of this VPC reach only this PC's
	}
	if run(ctx, "ip", "-n", ns, "link", "show", vxlanDev) != nil {
		tmp := fmt.Sprintf("jyx%x", idx)
		_ = run(ctx, "ip", "link", "del", tmp)
		steps = [][]string{
			{"ip", "link", "add", tmp, "type", "vxlan", "id", fmt.Sprint(n.VPC.VNI), "local", meshIP, "dstport", vxlanPort, "nolearning"},
			{"ip", "link", "set", tmp, "netns", ns},
			{"ip", "-n", ns, "link", "set", tmp, "name", vxlanDev},
		}
		for _, s := range steps {
			if err := run(ctx, s[0], s[1:]...); err != nil {
				return err
			}
		}
	}
	steps = [][]string{
		{"ip", "-n", ns, "link", "set", vxlanDev, "address", vxlanMAC(meshIP), "mtu", fmt.Sprint(ec2meta.GuestMTU), "up"},
	}
	for _, s := range steps {
		if err := run(ctx, s[0], s[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// syncRemote routes the VPC's instances on other PCs over VXLAN: a /32
// route via the PC's mesh address, and static neighbour and FDB entries
// for that PC.
func (m *Manager) syncRemote(ctx context.Context, ns, node, meshIP string, n ec2meta.VPCNet) error {
	if meshIP == "" {
		return nil
	}
	routes := map[string]string{} // instance IP -> PC mesh IP
	hosts := map[string]bool{}
	for _, ep := range n.Endpoints {
		if ep.Host == node || ep.HostIP == "" || ep.IP == "" {
			continue
		}
		routes[ep.IP] = ep.HostIP
		hosts[ep.HostIP] = true
	}
	key := "remote/" + n.VPC.ID
	h, changed := m.changed(key, routes)
	if !changed {
		return nil
	}
	for hip := range hosts {
		mac := vxlanMAC(hip)
		if err := run(ctx, "ip", "-n", ns, "neigh", "replace", hip, "lladdr", mac, "dev", vxlanDev, "nud", "permanent"); err != nil {
			return err
		}
		if err := run(ctx, "bridge", "-n", ns, "fdb", "replace", mac, "dev", vxlanDev, "dst", hip, "self", "permanent"); err != nil {
			return err
		}
	}
	// What is routed now, to remove what's gone.
	out, err := output(ctx, "ip", "-n", ns, "-j", "route", "show", "dev", vxlanDev)
	if err != nil {
		return err
	}
	var cur []struct {
		Dst     string `json:"dst"`
		Gateway string `json:"gateway"`
	}
	_ = json.Unmarshal(out, &cur)
	for _, r := range cur {
		dst := strings.TrimSuffix(r.Dst, "/32")
		if routes[dst] == r.Gateway {
			continue
		}
		if _, ok := routes[dst]; !ok {
			_ = run(ctx, "ip", "-n", ns, "route", "del", r.Dst, "dev", vxlanDev)
		}
	}
	for ip, hip := range routes {
		if err := run(ctx, "ip", "-n", ns, "route", "replace", ip+"/32", "via", hip, "dev", vxlanDev, "onlink"); err != nil {
			return err
		}
	}
	m.done(key, h)
	return nil
}

// syncGateways puts each subnet's router address (.1) on the namespace's
// loopback. Guests ARP for it on their tap and proxy ARP only answers for
// addresses the namespace can route, which a local address is.
func (m *Manager) syncGateways(ctx context.Context, ns string, n ec2meta.VPCNet) error {
	want := map[string]bool{}
	for _, sn := range n.Subnets {
		p, err := netip.ParsePrefix(sn.CIDR)
		if err != nil {
			continue
		}
		want[p.Masked().Addr().Next().String()] = true
	}
	key := "gw/" + n.VPC.ID
	h, changed := m.changed(key, want)
	if !changed {
		return nil
	}
	vpcNet, err := netip.ParsePrefix(n.VPC.CIDR)
	if err != nil {
		return err
	}
	out, err := output(ctx, "ip", "-n", ns, "-j", "addr", "show", "dev", "lo")
	if err != nil {
		return err
	}
	var cur []struct {
		Addrs []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	_ = json.Unmarshal(out, &cur)
	for _, l := range cur {
		for _, a := range l.Addrs {
			ip, err := netip.ParseAddr(a.Local)
			if err == nil && vpcNet.Contains(ip) && !want[a.Local] {
				_ = run(ctx, "ip", "-n", ns, "addr", "del", a.Local+"/32", "dev", "lo")
			}
		}
	}
	for ip := range want {
		if err := run(ctx, "ip", "-n", ns, "addr", "replace", ip+"/32", "dev", "lo"); err != nil {
			return err
		}
	}
	m.done(key, h)
	return nil
}

var errNoTap = errors.New("vnet: no such tap")

// Plug connects a started instance's tap (in the VPC's namespace) to the
// VPC: up, proxy ARP for its gateway, strict reverse-path filtering and a
// route to the instance.
func (m *Manager) Plug(ctx context.Context, vpcID, tap, ip string) error {
	return m.plug(ctx, NSName(vpcID), tap, ip, true)
}

func (m *Manager) plug(ctx context.Context, ns, tap, ip string, force bool) error {
	key := "tap/" + tap
	h, changed := m.changed(key, ip)
	if !changed && !force {
		return nil
	}
	if run(ctx, "ip", "-n", ns, "link", "show", tap) != nil {
		return errNoTap
	}
	if err := run(ctx, "ip", "-n", ns, "link", "set", tap, "mtu", fmt.Sprint(ec2meta.GuestMTU), "up"); err != nil {
		return err
	}
	for _, kv := range []string{"proxy_arp=1", "rp_filter=1", "forwarding=1"} {
		if err := inNS(ctx, ns, "sysctl", "-qw", "net.ipv4.conf."+tap+"."+kv); err != nil {
			return err
		}
	}
	if err := run(ctx, "ip", "-n", ns, "route", "replace", ip+"/32", "dev", tap); err != nil {
		return err
	}
	m.done(key, h)
	return nil
}

// Unplug forgets a tap the driver deleted.
func (m *Manager) Unplug(tap string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.applied, "tap/"+tap)
}

// Listen opens a TCP listener inside a VPC's namespace. The socket stays
// in that namespace whichever goroutine serves it.
func (m *Manager) Listen(vpcID, addr string) (net.Listener, error) {
	var l net.Listener
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		// This thread switches namespace and is never unlocked, so Go
		// discards it rather than reusing it elsewhere.
		runtime.LockOSThread()
		var f *os.File
		if f, err = os.Open(filepath.Join("/run/netns", NSName(vpcID))); err != nil {
			return
		}
		defer f.Close()
		if err = unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			return
		}
		l, err = net.Listen("tcp", addr)
	}()
	<-done
	return l, err
}

// --- VXLAN filter ---

// syncVXLANFilter accepts VXLAN only from PCs running instances of the
// same VPC, so a PC can't inject traffic into a VPC it has no part in.
func (m *Manager) syncVXLANFilter(ctx context.Context, node string, nets []ec2meta.VPCNet) error {
	type pair struct {
		Host string
		VNI  uint32
	}
	var allow []pair
	for _, n := range nets {
		seen := map[string]bool{}
		for _, ep := range n.Endpoints {
			if ep.Host != node && ep.HostIP != "" && !seen[ep.HostIP] {
				seen[ep.HostIP] = true
				allow = append(allow, pair{ep.HostIP, n.VPC.VNI})
			}
		}
		for _, r := range sourceRoutes(node, n) {
			if !seen[r.Via] {
				seen[r.Via] = true
				allow = append(allow, pair{r.Via, n.VPC.VNI})
			}
		}
	}
	sort.Slice(allow, func(i, j int) bool {
		if allow[i].VNI != allow[j].VNI {
			return allow[i].VNI < allow[j].VNI
		}
		return allow[i].Host < allow[j].Host
	})
	h, changed := m.changed("vxlan", allow)
	if !changed {
		return nil
	}
	var rules [][]string
	for _, a := range allow {
		// u32: skip the IP header, then the VNI is bytes 12-14 of the UDP
		// payload's start (8 UDP + 4 VXLAN flag bytes).
		rules = append(rules, []string{"-s", a.Host, "-p", "udp", "--dport", vxlanPort,
			"-m", "u32", "--u32", fmt.Sprintf("0>>22&0x3C@12>>8=%d", a.VNI), "-j", "ACCEPT"})
	}
	rules = append(rules, []string{"-p", "udp", "--dport", vxlanPort, "-j", "DROP"})
	if err := chain(ctx, "filter", "JY-VXLAN", "INPUT", rules); err != nil {
		return err
	}
	m.done("vxlan", h)
	return nil
}
