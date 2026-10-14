package vnet

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
)

// syncFirewall applies a VPC namespace's NAT and security groups with one
// iptables-restore, when they change.
func (m *Manager) syncFirewall(ctx context.Context, ns, node string, n ec2meta.VPCNet) error {
	rules := Rules(node, n)
	key := "fw/" + n.VPC.ID
	h, changed := m.changed(key, rules)
	if !changed {
		return nil
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "iptables-restore")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables-restore in %s: %v: %s", ns, err, strings.TrimSpace(string(out)))
	}
	m.done(key, h)
	return nil
}

// Rules is the iptables-restore input for a VPC namespace on node.
//
// Packets from an instance go through its egress chain (which returns if
// allowed); packets to an instance go through its ingress chain (which
// accepts if allowed). All egress checks come before any ingress check, so
// traffic between two instances on this PC passes both. Replies are let
// through by conntrack, which makes the groups stateful.
func Rules(node string, n ec2meta.VPCNet) string {
	groups := map[string]ec2meta.SecurityGroup{}
	for _, g := range n.Groups {
		groups[g.ID] = g
	}
	var local []ec2meta.Endpoint
	for _, ep := range n.Endpoints {
		if ep.Host == node {
			local = append(local, ep)
		}
	}
	sort.Slice(local, func(i, j int) bool { return local[i].Instance < local[j].Instance })

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("*nat")
	w(":PREROUTING ACCEPT [0:0]")
	w(":INPUT ACCEPT [0:0]")
	w(":OUTPUT ACCEPT [0:0]")
	w(":POSTROUTING ACCEPT [0:0]")
	w("-A POSTROUTING -o %s -j MASQUERADE", uplink)
	w("COMMIT")

	w("*filter")
	w(":INPUT DROP [0:0]")
	w(":FORWARD DROP [0:0]")
	w(":OUTPUT ACCEPT [0:0]")
	for _, ep := range local {
		w(":%s - [0:0]", chainName("E", ep.Instance))
		w(":%s - [0:0]", chainName("I", ep.Instance))
	}
	w("-A INPUT -i lo -j ACCEPT")
	w("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	w("-A INPUT -i jy+ -d %s/32 -p tcp --dport 80 -j ACCEPT", MetadataIP)
	w("-A FORWARD -m conntrack --ctstate INVALID -j DROP")
	w("-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	for _, ep := range local {
		tap := TapName(ep.Instance)
		w("-A FORWARD -i %s ! -s %s/32 -j DROP", tap, ep.IP)
		w("-A FORWARD -i %s -j %s", tap, chainName("E", ep.Instance))
	}
	for _, ep := range local {
		w("-A FORWARD -o %s -j %s", TapName(ep.Instance), chainName("I", ep.Instance))
	}
	// Past its egress check: to an instance on another PC, or out.
	w("-A FORWARD -i jy+ -j ACCEPT")

	for _, ep := range local {
		var in, out []ec2meta.Permission
		for _, gid := range ep.Groups {
			g := groups[gid]
			in = append(in, g.Ingress...)
			out = append(out, g.Egress...)
		}
		e, i := chainName("E", ep.Instance), chainName("I", ep.Instance)
		for _, p := range out {
			for _, peer := range peers(p, n.Members) {
				w("-A %s -d %s%s -j RETURN", e, peer, match(p))
			}
		}
		w("-A %s -j DROP", e)
		for _, p := range in {
			for _, peer := range peers(p, n.Members) {
				w("-A %s -s %s%s -j ACCEPT", i, peer, match(p))
			}
		}
		w("-A %s -j DROP", i)
	}
	w("COMMIT")
	return b.String()
}

// chainName is an instance's egress (E) or ingress (I) chain, within
// iptables' 28 characters.
func chainName(kind, instance string) string {
	return "JY-" + kind + "-" + strings.TrimPrefix(instance, "i-")
}

// peers lists a permission's address ranges, with groups expanded to their
// members' addresses.
func peers(p ec2meta.Permission, members map[string][]string) []string {
	out := append([]string(nil), p.CIDRs...)
	for _, g := range p.Groups {
		for _, ip := range members[g] {
			out = append(out, ip+"/32")
		}
	}
	return out
}

// match is the protocol and port part of a rule.
func match(p ec2meta.Permission) string {
	switch p.Protocol {
	case "tcp", "udp":
		if p.FromPort == p.ToPort {
			return fmt.Sprintf(" -p %s --dport %d", p.Protocol, p.FromPort)
		}
		return fmt.Sprintf(" -p %s --dport %d:%d", p.Protocol, p.FromPort, p.ToPort)
	case "icmp":
		switch {
		case p.FromPort < 0:
			return " -p icmp"
		case p.ToPort < 0:
			return fmt.Sprintf(" -p icmp --icmp-type %d", p.FromPort)
		default:
			return fmt.Sprintf(" -p icmp --icmp-type %d/%d", p.FromPort, p.ToPort)
		}
	}
	return ""
}
