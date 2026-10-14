package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
)

// addControl joins a trusted node with the control role, enrolls it as a
// control node, starts it and waits until it is a Raft voter.
func addControl(t *testing.T, c *testCluster) *Server {
	t.Helper()
	req, keys := joinReq(t, cluster.RoleControl, cluster.RoleStorage)
	resp, err := Join(context.Background(), c.token(t, true), req)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.CertPEM)
	nodeClient := NewClient(resp.ControlAddrs, pki.TLSCertificate(cert.Raw, keys.Signing, c.srv.CA()), c.srv.CA())

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	enr, err := nodeClient.EnrollControl(context.Background(), cluster.ControlEnrollRequest{
		PublicKey: pub, APIAddr: freeAddr(t), RaftAddr: freeAddr(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "control")
	if err := WriteEnrollment(dir, enr, priv); err != nil {
		t.Fatal(err)
	}
	srv, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	serve(t, srv)

	ctl := NewClient(srv.Peers(), srv.ClientCertificate(), srv.CA())
	if err := ctl.ActivateControl(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "voter", srv.IsVoter)
	return srv
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestThreeControlNodesSurviveLeaderLoss(t *testing.T) {
	c := newTestCluster(t)
	b := addControl(t, c)
	d := addControl(t, c)
	if n := len(c.srv.Controls()); n != 3 {
		t.Fatalf("controls = %d, want 3", n)
	}

	// A join sent to a follower is redirected to the leader.
	tok := c.token(t, false)
	tok.Control = b.APIAddr()
	req, _ := joinReq(t, cluster.RoleStorage)
	if _, err := Join(context.Background(), tok, req); err != nil {
		t.Fatalf("join via follower: %v", err)
	}
	waitFor(t, "replication to followers", func() bool { return len(b.Members()) == 3 && len(d.Members()) == 3 })

	// Lose the original leader. The other two elect a new one.
	if err := c.srv.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "new leader", func() bool { return b.IsLeader() || d.IsLeader() })

	// The admin client still works, trying each control address in turn.
	adminCert := pki.TLSCertificate(c.creds.CertDER, c.creds.Key, c.srv.CA())
	admin := NewClient([]string{c.addr, b.APIAddr(), d.APIAddr()}, adminCert, c.srv.CA())
	s, err := admin.IssueToken(context.Background(), cluster.TokenRequest{TTLSeconds: 600, MaxUses: 1})
	if err != nil {
		t.Fatalf("token after leader loss: %v", err)
	}
	if !strings.Contains(s, "jy1.") {
		t.Fatalf("bad token %q", s)
	}
}

func TestUntrustedNodeCannotBecomeControl(t *testing.T) {
	c := newTestCluster(t)
	req, keys := joinReq(t, cluster.RoleControl, cluster.RoleStorage)
	resp, err := Join(context.Background(), c.token(t, false), req)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.CertPEM)
	nodeClient := NewClient([]string{c.addr}, pki.TLSCertificate(cert.Raw, keys.Signing, c.srv.CA()), c.srv.CA())
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err = nodeClient.EnrollControl(context.Background(), cluster.ControlEnrollRequest{
		PublicKey: pub, APIAddr: freeAddr(t), RaftAddr: freeAddr(t),
	})
	if err == nil || !strings.Contains(err.Error(), "owner-trusted") {
		t.Fatalf("untrusted node enrolled as control: %v", err)
	}
}
