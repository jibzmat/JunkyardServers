// Command jyctl creates a Junkyard cluster, issues join tokens, joins nodes
// and inspects the member list.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/agent"
	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/hw"
	"github.com/jibzmat/JunkyardServers/internal/mesh"
	"github.com/jibzmat/JunkyardServers/internal/node"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

const usage = `jyctl manages a Junkyard Servers cluster.

Commands:
  init      create a new cluster on this PC (control plane + first node)
  token     issue a join token (run on the PC that ran init)
  join      join this PC to a cluster with a token
  members   list the cluster's nodes
  wg-config print this node's WireGuard config in wg-quick format

Run "jyctl <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "join":
		err = cmdJoin(os.Args[2:])
	case "members":
		err = cmdMembers(os.Args[2:])
	case "wg-config":
		err = cmdWGConfig(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "jyctl:", err)
		os.Exit(1)
	}
}

func defaultDir() string {
	if d := os.Getenv("JY_DIR"); d != "" {
		return d
	}
	return "/var/lib/junkyard"
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory")
	name := fs.String("cluster", "junkyard", "cluster name")
	addr := fs.String("control", "", "control plane address other PCs can reach, host:port (required)")
	gossip := fs.String("gossip", ":7946", "gossip listen address")
	wgPort := fs.Int("wg-port", 51820, "WireGuard listen port")
	wgEndpoint := fs.String("wg-endpoint", "", "public WireGuard host:port, if this PC is reachable from outside")
	roles := fs.String("roles", "control,gateway,compute,storage", "roles for this PC")
	fs.Parse(args)
	if *addr == "" {
		return errors.New("init: -control is required (for example 192.168.1.10:7443)")
	}
	rs, err := cluster.ParseRoles(*roles)
	if err != nil {
		return err
	}

	controlDir := filepath.Join(*dir, "control")
	admin, err := control.Init(controlDir, *name, *addr)
	if err != nil {
		return err
	}
	if err := pki.WriteCertPEM(filepath.Join(*dir, "admin.crt"), admin.CertDER); err != nil {
		return err
	}
	if err := pki.WriteKeyPEM(filepath.Join(*dir, "admin.key"), admin.Key); err != nil {
		return err
	}

	srv, err := control.Open(controlDir)
	if err != nil {
		return err
	}
	keys, err := node.NewKeys()
	if err != nil {
		return err
	}
	gossipAddr := advertisable(*gossip, *addr)
	resp, err := srv.EnrollLocal(cluster.JoinRequest{
		SigningKey: keys.SigningPublic(),
		WGPublic:   keys.WireGuard.PublicKey().String(),
		WGEndpoint: *wgEndpoint,
		GossipAddr: gossipAddr,
		Roles:      rs,
		Hardware:   hw.Detect(),
	})
	if err != nil {
		return err
	}
	if err := saveJoined(*dir, *addr, gossipAddr, *wgPort, *wgEndpoint, keys, resp); err != nil {
		return err
	}
	fmt.Printf("Created cluster %q. This PC is %s at %s (%s).\n", *name, resp.NodeID, resp.MeshIP, resp.Tier)
	fmt.Printf("Start it with:  jyd -dir %s\n", *dir)
	fmt.Printf("Add a PC with:  jyctl token -dir %s [-trusted]   then   jyctl join <token>\n", *dir)
	return nil
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory with admin.crt")
	trusted := fs.Bool("trusted", false, "the PC is yours: it may also run the control plane and gateways, and private instances")
	ttl := fs.Duration("ttl", 24*time.Hour, "how long the token is valid")
	uses := fs.Int("uses", 1, "how many PCs may join with it (0 = unlimited)")
	fs.Parse(args)

	c, err := adminClient(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := c.IssueToken(ctx, cluster.TokenRequest{Trusted: *trusted, TTLSeconds: int(ttl.Seconds()), MaxUses: *uses})
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory")
	gossip := fs.String("gossip", ":7946", "gossip listen address")
	advertise := fs.String("advertise", "", "this PC's address other nodes can reach (default: auto)")
	wgPort := fs.Int("wg-port", 51820, "WireGuard listen port")
	wgEndpoint := fs.String("wg-endpoint", "", "public WireGuard host:port, if this PC is reachable from outside")
	roles := fs.String("roles", "storage,compute", "roles to request; the control plane may grant fewer")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("join: usage: jyctl join [flags] <token>")
	}
	if _, err := os.Stat(filepath.Join(*dir, "node.json")); err == nil {
		return fmt.Errorf("join: %s already holds a node", *dir)
	}
	tok, err := token.Parse(fs.Arg(0))
	if err != nil {
		return err
	}
	rs, err := cluster.ParseRoles(*roles)
	if err != nil {
		return err
	}
	keys, err := node.NewKeys()
	if err != nil {
		return err
	}
	gossipAddr := *gossip
	if *advertise != "" {
		_, p, err := net.SplitHostPort(*gossip)
		if err != nil {
			return err
		}
		gossipAddr = net.JoinHostPort(*advertise, p)
	} else {
		gossipAddr = advertisable(*gossip, tok.Control)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := control.Join(ctx, tok, cluster.JoinRequest{
		SigningKey: keys.SigningPublic(),
		WGPublic:   keys.WireGuard.PublicKey().String(),
		WGEndpoint: *wgEndpoint,
		GossipAddr: gossipAddr,
		Roles:      rs,
		Hardware:   hw.Detect(),
	})
	if err != nil {
		return err
	}
	if err := saveJoined(*dir, tok.Control, gossipAddr, *wgPort, *wgEndpoint, keys, resp); err != nil {
		return err
	}
	fmt.Printf("Joined cluster %q as %s at %s.\n", resp.Cluster, resp.NodeID, resp.MeshIP)
	fmt.Printf("Tier: %s. Roles granted: %v.\n", resp.Tier, resp.Roles)
	if resp.Tier == cluster.TierUntrusted {
		fmt.Println("This PC stores encrypted shards and runs instances whose owners chose placement \"any\".")
		fmt.Println("It never holds cluster keys. Without SEV-SNP/TDX its guests' RAM is not hidden from you.")
	}
	fmt.Printf("Start it with:  jyd -dir %s\n", *dir)
	return nil
}

func cmdMembers(args []string) error {
	fs := flag.NewFlagSet("members", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory")
	fs.Parse(args)
	n, err := node.Load(*dir)
	if err != nil {
		return err
	}
	c := control.NewClient(n.Config.Control, n.TLSCertificate(), n.CA)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	members, err := c.Members(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tMESH IP\tTIER\tROLES\tCORES\tRAM\tSEV-SNP/TDX")
	for _, m := range members {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%d\t%s\t%v\n", m.NodeID, m.MeshIP, m.Tier, m.Roles,
			m.Hardware.Cores, gib(m.Hardware.MemBytes), m.Hardware.Confidential())
	}
	return tw.Flush()
}

func cmdWGConfig(args []string) error {
	fs := flag.NewFlagSet("wg-config", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory")
	fs.Parse(args)
	n, err := node.Load(*dir)
	if err != nil {
		return err
	}
	c := control.NewClient(n.Config.Control, n.TLSCertificate(), n.CA)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	members, err := c.Members(ctx)
	if err != nil {
		return err
	}
	cfg := mesh.Config{
		PrivateKey: n.Keys.WireGuard,
		ListenPort: n.Config.WGPort,
		MeshIP:     n.Config.MeshIP,
		MeshCIDR:   n.Config.MeshCIDR,
		Peers:      agent.Peers(members, nil, n.Config.NodeID),
	}
	fmt.Print(cfg.WGQuick())
	return nil
}

func saveJoined(dir, controlAddr, gossipAddr string, wgPort int, wgEndpoint string, keys *node.Keys, resp *cluster.JoinResponse) error {
	var seeds []string
	for _, p := range resp.Peers {
		if p.GossipAddr != "" {
			seeds = append(seeds, p.GossipAddr)
		}
	}
	return node.Save(dir, node.Config{
		NodeID:     resp.NodeID,
		Cluster:    resp.Cluster,
		Control:    controlAddr,
		Tier:       resp.Tier,
		Roles:      resp.Roles,
		MeshIP:     resp.MeshIP,
		MeshCIDR:   resp.MeshCIDR,
		GossipKey:  resp.GossipKey,
		GossipAddr: gossipAddr,
		WGPort:     wgPort,
		WGEndpoint: wgEndpoint,
		Seeds:      seeds,
	}, keys, resp.CertPEM, resp.CAPEM)
}

func adminClient(dir string) (*control.Client, error) {
	n, err := node.Load(dir)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key"))
	if err != nil {
		return nil, fmt.Errorf("admin credentials (run token on the PC that ran init): %w", err)
	}
	cert.Certificate = append(cert.Certificate, n.CA.Raw)
	return control.NewClient(n.Config.Control, cert, n.CA), nil
}

// advertisable turns a listen address like ":7946" into one other PCs can
// dial, using the local address that routes towards the control plane.
func advertisable(listen, controlAddr string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || (host != "" && host != "0.0.0.0" && host != "::") {
		return listen
	}
	conn, err := net.Dial("udp", controlAddr)
	if err != nil {
		return listen
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr).IP.String()
	return net.JoinHostPort(local, port)
}

func gib(b uint64) string {
	if b == 0 {
		return "?"
	}
	return strconv.FormatFloat(float64(b)/(1<<30), 'f', 1, 64) + " GiB"
}
