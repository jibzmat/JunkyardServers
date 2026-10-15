package vnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// Elastic IPs. The PC holding a public address (its gateway) routes it
// into the VPC's namespace, where it is translated to the instance's
// private address and sent on, over VXLAN when the instance runs on
// another PC. That PC sends the instance's traffic to the internet back
// through the gateway, so replies and new connections leave from the
// public address:
//
//	internet -> gateway PC (route, proxy ARP) -> namespace (DNAT) -> vx0
//	  -> instance's PC namespace -> tap
//	tap -> namespace (source rule: via the gateway) -> vx0
//	  -> gateway namespace (SNAT) -> gateway PC -> internet

// eipProto marks the routes this package adds for public addresses.
const eipProto = "77"

// Source rules on an instance's PC: the main table first, except for its
// default route, then a table per elastic IP, then one per subnet routed
// to a NAT gateway on another PC, each sending the rest to that gateway.
// An instance's own elastic IP wins over its subnet's NAT gateway.
const (
	prefMain = "100"
	prefEIP  = "200"
	prefNAT  = "300"
	eipTable = 1000
)

// gatewayEIPs are the elastic IPs of n that node is the gateway of.
func gatewayEIPs(node string, n ec2meta.VPCNet) []ec2meta.ElasticIP {
	var out []ec2meta.ElasticIP
	for _, e := range n.EIPs {
		if e.Gateway == node {
			out = append(out, e)
		}
	}
	return out
}

// gatewayNATs are the subnets of n whose NAT gateway's address node holds.
func gatewayNATs(node string, n ec2meta.VPCNet) []ec2meta.SubnetEgress {
	var out []ec2meta.SubnetEgress
	for _, e := range n.Egress {
		if !e.None && e.Gateway == node {
			out = append(out, e)
		}
	}
	return out
}

// sourceRoute sends traffic from From to the internet through Via.
type sourceRoute struct{ Pref, From, Via string }

// sourceRoutes are this PC's source rules for n.
func sourceRoutes(node string, n ec2meta.VPCNet) []sourceRoute {
	local := map[string]bool{}
	for _, ep := range n.Endpoints {
		if ep.Host == node {
			local[ep.Instance] = true
		}
	}
	var want []sourceRoute
	for _, e := range n.EIPs {
		if local[e.Instance] && e.Gateway != node && e.GatewayIP != "" {
			want = append(want, sourceRoute{prefEIP, e.PrivateIP + "/32", e.GatewayIP})
		}
	}
	for _, e := range n.Egress {
		if !e.None && e.Gateway != node && e.GatewayIP != "" {
			want = append(want, sourceRoute{prefNAT, e.CIDR, e.GatewayIP})
		}
	}
	sort.Slice(want, func(i, j int) bool {
		if want[i].Pref != want[j].Pref {
			return want[i].Pref < want[j].Pref
		}
		return want[i].From < want[j].From
	})
	return want
}

// syncSourceRoutes sends the internet traffic of this PC's instances that
// have an elastic IP, or whose subnet has a NAT gateway, held by another
// PC to that PC.
func (m *Manager) syncSourceRoutes(ctx context.Context, ns, node, meshIP string, n ec2meta.VPCNet) error {
	if meshIP == "" {
		return nil
	}
	want := sourceRoutes(node, n)
	key := "eip/" + n.VPC.ID
	h, changed := m.changed(key, want)
	if !changed {
		return nil
	}
	// Start over: drop our rules and their tables.
	out, err := output(ctx, "ip", "-n", ns, "-j", "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Priority int    `json:"priority"`
		Table    string `json:"table"`
	}
	_ = json.Unmarshal(out, &rules)
	for _, r := range rules {
		p := fmt.Sprint(r.Priority)
		if p != prefMain && p != prefEIP && p != prefNAT {
			continue
		}
		_ = run(ctx, "ip", "-n", ns, "rule", "del", "pref", p)
		if p != prefMain {
			_ = run(ctx, "ip", "-n", ns, "route", "flush", "table", r.Table)
		}
	}
	if len(want) > 0 {
		if err := run(ctx, "ip", "-n", ns, "rule", "add", "pref", prefMain, "lookup", "main", "suppress_prefixlength", "0"); err != nil {
			return err
		}
	}
	for i, r := range want {
		table := fmt.Sprint(eipTable + i)
		mac := vxlanMAC(r.Via)
		steps := [][]string{
			{"ip", "-n", ns, "neigh", "replace", r.Via, "lladdr", mac, "dev", vxlanDev, "nud", "permanent"},
			{"bridge", "-n", ns, "fdb", "replace", mac, "dev", vxlanDev, "dst", r.Via, "self", "permanent"},
			{"ip", "-n", ns, "route", "replace", "default", "via", r.Via, "dev", vxlanDev, "onlink", "table", table},
			{"ip", "-n", ns, "rule", "add", "pref", r.Pref, "from", r.From, "lookup", table},
		}
		for _, s := range steps {
			if err := run(ctx, s[0], s[1:]...); err != nil {
				return err
			}
		}
	}
	m.done(key, h)
	return nil
}

// syncPublic is the gateway PC's own side: each public address it holds
// for an elastic IP or a NAT gateway is routed to its VPC's namespace, answered for on the LAN it belongs to
// (proxy ARP), and let through to the namespace.
func (m *Manager) syncPublic(ctx context.Context, node string, nets []ec2meta.VPCNet) error {
	type pub struct{ IP, Veth, Via, Dev string }
	var want []pub
	for _, n := range nets {
		var ips []string
		for _, e := range gatewayEIPs(node, n) {
			ips = append(ips, e.PublicIP)
		}
		for _, e := range gatewayNATs(node, n) {
			ips = append(ips, e.PublicIP)
		}
		if len(ips) == 0 {
			continue
		}
		idx, err := m.indexFor(n.VPC.ID)
		if err != nil {
			return err
		}
		_, nsIP := transitAddrs(idx)
		seen := map[string]bool{}
		for _, ip := range ips {
			a, err := netip.ParseAddr(ip)
			if err != nil || seen[ip] {
				continue
			}
			seen[ip] = true
			dev, local := lanFor(a)
			if local {
				m.logf("vnet: %s is this PC's own address, so it can't be an elastic IP here", ip)
				continue
			}
			want = append(want, pub{ip, fmt.Sprintf("jyv%x", idx), nsIP.String(), dev})
		}
	}
	sort.Slice(want, func(i, j int) bool { return want[i].IP < want[j].IP })
	h, changed := m.changed("public", want)
	if !changed {
		return nil
	}
	wanted := map[string]bool{}
	for _, p := range want {
		wanted[p.IP] = true
	}
	// Routes and proxy entries for addresses no longer held.
	out, err := output(ctx, "ip", "-j", "route", "show", "proto", eipProto)
	if err != nil {
		return err
	}
	var cur []struct {
		Dst string `json:"dst"`
	}
	_ = json.Unmarshal(out, &cur)
	for _, r := range cur {
		ip := strings.TrimSuffix(r.Dst, "/32")
		if wanted[ip] {
			continue
		}
		_ = run(ctx, "ip", "route", "del", r.Dst, "proto", eipProto)
		if a, err := netip.ParseAddr(ip); err == nil {
			if dev, _ := lanFor(a); dev != "" {
				_ = run(ctx, "ip", "neigh", "del", "proxy", ip, "dev", dev)
			}
		}
	}
	var accept [][]string
	for _, p := range want {
		if err := run(ctx, "ip", "route", "replace", p.IP+"/32", "via", p.Via, "dev", p.Veth, "proto", eipProto); err != nil {
			return err
		}
		if p.Dev != "" {
			if err := run(ctx, "ip", "neigh", "replace", "proxy", p.IP, "dev", p.Dev); err != nil {
				return err
			}
		}
		accept = append(accept, []string{"-o", p.Veth, "-d", p.IP + "/32", "-j", "ACCEPT"})
	}
	if err := chain(ctx, "filter", "JY-EIP", "FORWARD", accept); err != nil {
		return err
	}
	m.done("public", h)
	return nil
}

// lanFor finds the interface whose network contains a, for proxy ARP,
// and whether a is already one of this PC's addresses.
func lanFor(a netip.Addr) (dev string, local bool) {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if strings.HasPrefix(i.Name, "jy") || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			p, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			p = p.Unmap()
			if p == a {
				return "", true
			}
			ones, _ := ipn.Mask.Size()
			if pfx := netip.PrefixFrom(p, ones); ones < 32 && pfx.Masked().Contains(a) && dev == "" {
				dev = i.Name
			}
		}
	}
	return dev, false
}
