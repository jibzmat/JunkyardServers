// Command jyctl creates a Junkyard cluster, issues join tokens, joins nodes
// and inspects the member list.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/agent"
	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/ec2meta"
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
  control   add or remove control nodes (control add | control list | control remove <id>)
  wg-config print this node's WireGuard config in wg-quick format
  tenant    create an S3 tenant and its access key (tenant create <name>)
  migrate   live-migrate a running instance to another PC (migrate [-to NODE] <instance-id>)
  drain     move every instance off a PC, live, and give it no new ones (drain <node>)
  undrain   let a drained PC take instances again (undrain <node>)
  reinstate lift a node's suspension for failed storage audits (reinstate <node>)
  public-ip list the public addresses tenants can allocate as elastic IPs, or change them
            (public-ip add <node> <ip>... | public-ip list | public-ip remove <ip>...)

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
	case "control":
		err = cmdControl(os.Args[2:])
	case "wg-config":
		err = cmdWGConfig(os.Args[2:])
	case "tenant":
		err = cmdTenant(os.Args[2:])
	case "public-ip":
		err = cmdPublicIP(os.Args[2:])
	case "migrate":
		err = cmdMigrate(os.Args[2:])
	case "drain", "undrain", "reinstate":
		err = cmdDrain(os.Args[1], os.Args[2:])
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
	raftPort := fs.Int("raft-port", 7444, "Raft port for control-plane replication")
	wgPort := fs.Int("wg-port", 51820, "WireGuard listen port")
	wgEndpoint := fs.String("wg-endpoint", "", "public WireGuard host:port, if this PC is reachable from outside")
	roles := fs.String("roles", "control,gateway,compute,storage", "roles for this PC")
	storagePort := fs.Int("storage-port", 7445, "shard server port (storage role)")
	s3Listen := fs.String("s3", ":9000", "S3 API listen address (gateway role)")
	fs.Parse(args)
	if *addr == "" {
		return errors.New("init: -control is required (for example 192.168.1.10:7443)")
	}
	rs, err := cluster.ParseRoles(*roles)
	if err != nil {
		return err
	}

	controlDir := filepath.Join(*dir, "control")
	srv, admin, err := control.Init(controlDir, *name, *addr, raftAddrFor(*addr, *raftPort), nil)
	if err != nil {
		return err
	}
	defer srv.Close()
	if err := pki.WriteCertPEM(filepath.Join(*dir, "admin.crt"), admin.CertDER); err != nil {
		return err
	}
	if err := pki.WriteKeyPEM(filepath.Join(*dir, "admin.key"), admin.Key); err != nil {
		return err
	}

	keys, err := node.NewKeys()
	if err != nil {
		return err
	}
	gossipAddr := advertisable(*gossip, *addr)
	resp, err := srv.EnrollLocal(cluster.JoinRequest{
		SigningKey:  keys.SigningPublic(),
		WGPublic:    keys.WireGuard.PublicKey().String(),
		WGEndpoint:  *wgEndpoint,
		GossipAddr:  gossipAddr,
		StoragePort: *storagePort,
		Roles:       rs,
		Hardware:    hw.Detect(),
	})
	if err != nil {
		return err
	}
	if err := saveJoined(*dir, *addr, gossipAddr, *wgPort, *wgEndpoint, *storagePort, *s3Listen, keys, resp); err != nil {
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
	storagePort := fs.Int("storage-port", 7445, "shard server port (storage role)")
	s3Listen := fs.String("s3", ":9000", "S3 API listen address (gateway role)")
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
		SigningKey:  keys.SigningPublic(),
		WGPublic:    keys.WireGuard.PublicKey().String(),
		WGEndpoint:  *wgEndpoint,
		GossipAddr:  gossipAddr,
		StoragePort: *storagePort,
		Roles:       rs,
		Hardware:    hw.Detect(),
	})
	if err != nil {
		return err
	}
	if err := saveJoined(*dir, tok.Control, gossipAddr, *wgPort, *wgEndpoint, *storagePort, *s3Listen, keys, resp); err != nil {
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
	c := control.NewClient(n.Config.ControlAddrs(), n.TLSCertificate(), n.CA)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	members, err := c.Members(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tMESH IP\tTIER\tROLES\tSHARD PORT\tCORES\tRAM\tSEV-SNP/TDX\tAUDITS")
	for _, m := range members {
		port := "-"
		if m.StoragePort != 0 {
			port = strconv.Itoa(m.StoragePort)
		}
		tier := string(m.Tier)
		if m.Drained {
			tier += " (drained)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%d\t%s\t%v\t%s\n", m.NodeID, m.MeshIP, tier, m.Roles, port,
			m.Hardware.Cores, gib(m.Hardware.MemBytes), m.Hardware.Confidential(), audits(m.Audits))
	}
	return tw.Flush()
}

// audits summarises a node's storage audits: passed/failed and its score.
func audits(a cluster.AuditRecord) string {
	if a.Passed == 0 && a.Failed == 0 {
		return "-"
	}
	out := fmt.Sprintf("%d ok, %d failed, score %.2f", a.Passed, a.Failed, a.Score)
	if a.Suspended {
		out += " (suspended)"
	}
	return out
}

func cmdWGConfig(args []string) error {
	fs := flag.NewFlagSet("wg-config", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory")
	fs.Parse(args)
	n, err := node.Load(*dir)
	if err != nil {
		return err
	}
	c := control.NewClient(n.Config.ControlAddrs(), n.TLSCertificate(), n.CA)
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

func cmdControl(args []string) error {
	if len(args) == 0 {
		return errors.New("control: usage: jyctl control add|list|remove")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("control add", flag.ExitOnError)
		dir := fs.String("dir", defaultDir(), "state directory of this (owner-trusted) node")
		api := fs.String("api", "", "API address other PCs can reach, host:port (required)")
		raftPort := fs.Int("raft-port", 7444, "Raft port")
		fs.Parse(args[1:])
		if *api == "" {
			return errors.New("control add: -api is required (for example 192.168.1.11:7443)")
		}
		n, err := node.Load(*dir)
		if err != nil {
			return err
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		c := control.NewClient(n.Config.ControlAddrs(), n.TLSCertificate(), n.CA)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, err := c.EnrollControl(ctx, cluster.ControlEnrollRequest{PublicKey: pub, APIAddr: *api, RaftAddr: raftAddrFor(*api, *raftPort)})
		if err != nil {
			return err
		}
		if err := control.WriteEnrollment(filepath.Join(*dir, "control"), resp, priv); err != nil {
			return err
		}
		fmt.Printf("Enrolled as control node %s. Restart jyd -dir %s to join the Raft group.\n", resp.ID, *dir)
		return nil
	case "list":
		fs := flag.NewFlagSet("control list", flag.ExitOnError)
		dir := fs.String("dir", defaultDir(), "state directory")
		fs.Parse(args[1:])
		n, err := node.Load(*dir)
		if err != nil {
			return err
		}
		c := control.NewClient(n.Config.ControlAddrs(), n.TLSCertificate(), n.CA)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		controls, err := c.Controls(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "CONTROL\tAPI\tRAFT")
		for _, ci := range controls {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", ci.ID, ci.APIAddr, ci.RaftAddr)
		}
		return tw.Flush()
	case "remove":
		fs := flag.NewFlagSet("control remove", flag.ExitOnError)
		dir := fs.String("dir", defaultDir(), "state directory with admin.crt")
		fs.Parse(args[1:])
		if fs.NArg() != 1 {
			return errors.New("control remove: usage: jyctl control remove [flags] <control-id>")
		}
		c, err := adminClient(*dir)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return c.RemoveControl(ctx, fs.Arg(0))
	}
	return fmt.Errorf("control: unknown subcommand %q", args[0])
}

func cmdTenant(args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return errors.New("tenant: usage: jyctl tenant create [-dir DIR] <name>")
	}
	fs := flag.NewFlagSet("tenant create", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory with admin.crt")
	fs.Parse(args[1:])
	if fs.NArg() != 1 {
		return errors.New("tenant: usage: jyctl tenant create [-dir DIR] <name>")
	}
	c, err := adminClient(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t, err := c.CreateTenant(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Printf("Created tenant %q. Its S3 credentials (shown once):\n\n", t.Tenant)
	fmt.Printf("  aws_access_key_id = %s\n  aws_secret_access_key = %s\n\n", t.AccessKeyID, t.SecretAccessKey)
	fmt.Println("Use them with any S3 client pointed at a gateway, for example:")
	fmt.Println("  aws --endpoint-url http://<gateway>:9000 s3 ls")
	return nil
}

func cmdPublicIP(args []string) error {
	const use = "public-ip: usage: jyctl public-ip add [-dir DIR] <node> <ip>... | list [-dir DIR] | remove [-dir DIR] <ip>..."
	if len(args) < 1 {
		return errors.New(use)
	}
	fs := flag.NewFlagSet("public-ip "+args[0], flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory with admin.crt")
	fs.Parse(args[1:])
	c, err := adminClient(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch args[0] {
	case "add":
		if fs.NArg() < 2 {
			return errors.New(use)
		}
		if err := c.Pool(ctx, ec2meta.PoolRequest{Node: fs.Arg(0), IPs: fs.Args()[1:]}); err != nil {
			return err
		}
		fmt.Printf("%s can now take traffic for %s as elastic IPs.\n", fs.Arg(0), strings.Join(fs.Args()[1:], ", "))
		fmt.Println("They must reach that PC: extra addresses its provider routes to it, or spare ones on its LAN.")
		return nil
	case "remove":
		if fs.NArg() < 1 {
			return errors.New(use)
		}
		return c.Pool(ctx, ec2meta.PoolRequest{IPs: fs.Args(), Remove: true})
	case "list":
		list, err := c.PublicIPs(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ADDRESS\tPC\tTENANT\tALLOCATION\tINSTANCE")
		for _, p := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.IP, p.Node, dash(p.Tenant), dash(p.AllocationID), dash(p.Instance))
		}
		return tw.Flush()
	}
	return errors.New(use)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory with admin.crt")
	to := fs.String("to", "", "PC to move to (default: the instance's replica PC, which already has its disks)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("migrate: usage: jyctl migrate [-to NODE] <instance-id>")
	}
	c, err := adminClient(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	in, err := c.Migrate(ctx, ec2meta.MigrateRequest{Instance: fs.Arg(0), To: *to})
	if err != nil {
		return err
	}
	if in.Replica == in.MigrateTo && in.ReplicaSynced {
		fmt.Printf("Migrating %s from %s to %s.\n", in.ID, in.Host, in.MigrateTo)
	} else {
		fmt.Printf("Copying %s's disks to %s; it migrates there from %s once the copy is in step.\n", in.ID, in.MigrateTo, in.Host)
	}
	return nil
}

func cmdDrain(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", defaultDir(), "state directory with admin.crt")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("%s: usage: jyctl %s <node>", cmd, cmd)
	}
	c, err := adminClient(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch cmd {
	case "drain":
		_, err = c.Migrate(ctx, ec2meta.MigrateRequest{Drain: fs.Arg(0)})
		if err == nil {
			fmt.Printf("Draining %s: its running instances migrate to their replica PCs.\n", fs.Arg(0))
		}
	case "undrain":
		_, err = c.Migrate(ctx, ec2meta.MigrateRequest{Undrain: fs.Arg(0)})
		if err == nil {
			fmt.Printf("%s takes instances again.\n", fs.Arg(0))
		}
	case "reinstate":
		err = c.Reinstate(ctx, fs.Arg(0))
		if err == nil {
			fmt.Printf("%s is reinstated, on probation: a failed audit suspends it again.\n", fs.Arg(0))
		}
	}
	return err
}

// raftAddrFor puts the Raft port on the API address's host.
func raftAddrFor(apiAddr string, port int) string {
	host, _, err := net.SplitHostPort(apiAddr)
	if err != nil {
		return apiAddr
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func saveJoined(dir, controlAddr, gossipAddr string, wgPort int, wgEndpoint string, storagePort int, s3Listen string, keys *node.Keys, resp *cluster.JoinResponse) error {
	granted := cluster.Member{Roles: resp.Roles}
	if !granted.Has(cluster.RoleStorage) {
		storagePort = 0
	}
	if !granted.Has(cluster.RoleGateway) {
		s3Listen = ""
	}
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
		Controls:   resp.ControlAddrs,
		Tier:       resp.Tier,
		Roles:      resp.Roles,
		MeshIP:     resp.MeshIP,
		MeshCIDR:   resp.MeshCIDR,
		GossipKey:  resp.GossipKey,
		GossipAddr: gossipAddr,
		WGPort:     wgPort,
		WGEndpoint: wgEndpoint,
		Seeds:      seeds,

		StoragePort: storagePort,
		S3Listen:    s3Listen,
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
	return control.NewClient(n.Config.ControlAddrs(), cert, n.CA), nil
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
