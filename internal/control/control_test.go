package control

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/node"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

type testCluster struct {
	srv   *Server
	admin *Client
	addr  string
	creds *AdminCredentials
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// serve starts the API for srv on its API address.
func serve(t *testing.T, srv *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", srv.APIAddr())
	if err != nil {
		t.Fatal(err)
	}
	serveOn(t, srv, ln)
}

// listen reserves a port and keeps it, so parallel tests can't take it.
func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func serveOn(t *testing.T, srv *Server, ln net.Listener) {
	t.Helper()
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Listener.Close()
	ts.Listener = ln
	ts.TLS = srv.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
}

func newTestCluster(t *testing.T) *testCluster {
	t.Helper()
	ln := listen(t)
	addr := ln.Addr().String()
	dir := filepath.Join(t.TempDir(), "control")
	srv, creds, err := Init(dir, "test", addr, freeAddr(t), nil)
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	serveOn(t, srv, ln)
	adminCert := pki.TLSCertificate(creds.CertDER, creds.Key, srv.CA())
	return &testCluster{srv: srv, admin: NewClient([]string{addr}, adminCert, srv.CA()), addr: addr, creds: creds}
}

func joinReq(t *testing.T, roles ...cluster.Role) (cluster.JoinRequest, *node.Keys) {
	t.Helper()
	keys, err := node.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	return cluster.JoinRequest{
		SigningKey: keys.SigningPublic(),
		WGPublic:   keys.WireGuard.PublicKey().String(),
		Roles:      roles,
	}, keys
}

func (c *testCluster) token(t *testing.T, trusted bool) token.Token {
	t.Helper()
	s, err := c.admin.IssueToken(context.Background(), cluster.TokenRequest{Trusted: trusted, TTLSeconds: 600, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := token.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestStrangerJoinsUntrusted(t *testing.T) {
	c := newTestCluster(t)
	tok := c.token(t, false)
	req, _ := joinReq(t, cluster.RoleCompute, cluster.RoleStorage, cluster.RoleControl)
	resp, err := Join(context.Background(), tok, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Tier != cluster.TierUntrusted {
		t.Fatalf("tier = %s, want untrusted", resp.Tier)
	}
	// Compute and storage are granted; the control plane is not.
	if len(resp.Roles) != 2 || resp.Roles[0] != cluster.RoleCompute || resp.Roles[1] != cluster.RoleStorage {
		t.Fatalf("roles = %v, want compute and storage", resp.Roles)
	}
	cert, err := pki.ParseCertPEM(resp.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.VerifyAgainst(c.srv.CA(), cert.Raw); err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != resp.NodeID {
		t.Fatalf("cert CN %q, node %q", cert.Subject.CommonName, resp.NodeID)
	}
}

func TestTrustedJoinGetsRequestedRoles(t *testing.T) {
	c := newTestCluster(t)
	req, _ := joinReq(t, cluster.RoleCompute, cluster.RoleStorage)
	resp, err := Join(context.Background(), c.token(t, true), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Tier != cluster.TierTrusted || len(resp.Roles) != 2 {
		t.Fatalf("tier %s roles %v", resp.Tier, resp.Roles)
	}
}

func TestTokenSingleUse(t *testing.T) {
	c := newTestCluster(t)
	tok := c.token(t, false)
	req, _ := joinReq(t, cluster.RoleStorage)
	if _, err := Join(context.Background(), tok, req); err != nil {
		t.Fatal(err)
	}
	req2, _ := joinReq(t, cluster.RoleStorage)
	if _, err := Join(context.Background(), tok, req2); err == nil {
		t.Fatal("second join with a single-use token succeeded")
	}
}

func TestJoinRejectsWrongSecretAndWrongCA(t *testing.T) {
	c := newTestCluster(t)
	tok := c.token(t, false)
	req, _ := joinReq(t, cluster.RoleStorage)

	bad := tok
	bad.Secret = strings.Repeat("0", len(tok.Secret))
	if _, err := Join(context.Background(), bad, req); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong secret: %v", err)
	}

	pinned := tok
	pinned.CAFingerprint = strings.Repeat("ab", 32)
	if _, err := Join(context.Background(), pinned, req); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong CA pin: %v", err)
	}
}

func TestMembersAndAccessControl(t *testing.T) {
	c := newTestCluster(t)
	var ips []string
	var lastKeys *node.Keys
	var lastResp *cluster.JoinResponse
	for i := 0; i < 3; i++ {
		req, keys := joinReq(t, cluster.RoleStorage)
		resp, err := Join(context.Background(), c.token(t, false), req)
		if err != nil {
			t.Fatal(err)
		}
		ips = append(ips, resp.MeshIP)
		lastKeys, lastResp = keys, resp
	}
	want := []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("mesh IPs %v, want %v", ips, want)
		}
	}
	if len(lastResp.Peers) != 2 {
		t.Fatalf("third node got %d peers, want 2", len(lastResp.Peers))
	}

	cert, _ := pki.ParseCertPEM(lastResp.CertPEM)
	nodeClient := NewClient([]string{c.addr}, pki.TLSCertificate(cert.Raw, lastKeys.Signing, c.srv.CA()), c.srv.CA())
	members, err := nodeClient.Members(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 3 {
		t.Fatalf("members = %d, want 3", len(members))
	}

	// A node certificate cannot mint tokens.
	if _, err := nodeClient.IssueToken(context.Background(), cluster.TokenRequest{TTLSeconds: 60}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("node minted a token: %v", err)
	}

	// No client certificate: members is refused.
	anon := NewClient([]string{c.addr}, tls.Certificate{}, c.srv.CA())
	if _, err := anon.Members(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("anonymous members: %v", err)
	}
}

func TestStateSurvivesReopen(t *testing.T) {
	c := newTestCluster(t)
	req, _ := joinReq(t, cluster.RoleStorage)
	if _, err := Join(context.Background(), c.token(t, false), req); err != nil {
		t.Fatal(err)
	}
	dir := c.srv.dir
	if err := c.srv.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.waitLeader(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	// Raft replays the log into the state machine after restart.
	deadline := time.Now().Add(5 * time.Second)
	for len(again.Members()) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("members after reopen = %d", len(again.Members()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTokenTTLBounds(t *testing.T) {
	c := newTestCluster(t)
	if _, err := c.srv.IssueToken(false, 0, 1); err == nil {
		t.Fatal("zero ttl accepted")
	}
	if _, err := c.srv.IssueToken(false, 30*24*time.Hour, 1); err == nil {
		t.Fatal("30 day ttl accepted")
	}
}

func TestAllocateIP(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/30")
	a, err := allocateIP(p, map[string]bool{})
	if err != nil || a.String() != "10.0.0.1" {
		t.Fatalf("got %v %v", a, err)
	}
	a, err = allocateIP(p, map[string]bool{"10.0.0.1": true})
	if err != nil || a.String() != "10.0.0.2" {
		t.Fatalf("got %v %v", a, err)
	}
	if _, err := allocateIP(p, map[string]bool{"10.0.0.1": true, "10.0.0.2": true}); err == nil {
		t.Fatal("exhausted /30 still allocated")
	}
}
