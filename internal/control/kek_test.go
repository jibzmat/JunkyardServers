package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

func kekOf(s *Server) *kekState {
	var out *kekState
	s.fsm.view(func(st *state) {
		if st.KEK != nil {
			cp := *st.KEK
			out = &cp
		}
	})
	return out
}

func TestTenantKeysAreSealed(t *testing.T) {
	c := newTestCluster(t)
	if _, err := c.srv.CreateTenant("alice"); err != nil {
		t.Fatal(err)
	}
	wrapped, err := c.srv.WrapKey("alice", []byte("data key"))
	if err != nil {
		t.Fatal(err)
	}
	st := kekOf(c.srv)
	if st == nil || st.Epoch != 1 || st.Threshold != 1 || len(st.Shares) != 1 {
		t.Fatalf("kek state %+v", st)
	}
	// The replicated state never holds the master key or the KEK in clear.
	mk, _ := c.srv.tenantKey("alice")
	snap, _ := json.Marshal(c.srv.fsm.st)
	if bytes.Contains(snap, mk) || bytes.Contains(snap, c.srv.currentKEK()) {
		t.Fatal("state contains a key in the clear")
	}
	var tn *s3meta.Tenant
	c.srv.fsm.view(func(x *state) { tn = x.Tenants["alice"] })
	if tn.MasterKey != nil || tn.SealedKey == nil {
		t.Fatalf("tenant %+v", tn)
	}

	// After a restart the node rebuilds the KEK from its own share.
	dir := c.srv.dir
	c.srv.Close()
	again, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	waitFor(t, "unlock after restart", again.KeysUnlocked)
	if got, err := again.UnwrapKey("alice", wrapped); err != nil || string(got) != "data key" {
		t.Fatalf("unwrap after restart: %q %v", got, err)
	}
}

func TestKEKSplitAcrossControlNodes(t *testing.T) {
	c := newTestCluster(t)
	if _, err := c.srv.CreateTenant("alice"); err != nil {
		t.Fatal(err)
	}
	wrapped, err := c.srv.WrapKey("alice", []byte("data key"))
	if err != nil {
		t.Fatal(err)
	}
	b := addControl(t, c)
	d, dts := addControlServer(t, c)

	// The leader re-splits for three nodes, two needed; all three unlock.
	waitFor(t, "2-of-3 split", func() bool {
		st := kekOf(c.srv)
		return st != nil && st.Threshold == 2 && len(st.Shares) == 3
	})
	for _, s := range []*Server{c.srv, b, d} {
		waitFor(t, "unlock on "+s.ID(), s.KeysUnlocked)
		if got, err := s.UnwrapKey("alice", wrapped); err != nil || string(got) != "data key" {
			t.Fatalf("%s unwrap: %q %v", s.ID(), got, err)
		}
	}
	// No one node's share is enough on its own.
	st := kekOf(d)
	share, err := d.ownShare(st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openSealed(share[1:], st.Check, checkAD(st.Epoch)); err == nil {
		t.Fatal("a single share opened the check value")
	}

	// A restarted follower gets the other shares from its peers.
	dir := d.dir
	dts.Close()
	d.Close()
	d2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d2.Close() })
	serve(t, d2)
	waitFor(t, "restarted follower unlocks", d2.KeysUnlocked)
	if got, err := d2.UnwrapKey("alice", wrapped); err != nil || string(got) != "data key" {
		t.Fatalf("restarted unwrap: %q %v", got, err)
	}

	// Removing a control node rotates the KEK so its old share is useless.
	epoch := kekOf(c.srv).Epoch
	if err := c.srv.RemoveControl(b.ID()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "rotation after removal", func() bool {
		st := kekOf(c.srv)
		_, kept := st.Shares[b.ID()]
		return st.Epoch > epoch && !kept && len(st.Shares) == 2
	})
	waitFor(t, "unlock after rotation", func() bool { return c.srv.KeysUnlocked() && d2.KeysUnlocked() })
	if got, err := d2.UnwrapKey("alice", wrapped); err != nil || string(got) != "data key" {
		t.Fatalf("unwrap after rotation: %q %v", got, err)
	}
}

func TestLegacyTenantKeyGetsSealed(t *testing.T) {
	c := newTestCluster(t)
	mk := bytes.Repeat([]byte{7}, 32)
	err := c.srv.apply(command{Op: opPutTenant, KEKEpoch: kekOf(c.srv).Epoch,
		Tenant:    &s3meta.Tenant{Name: "old", MasterKey: mk},
		AccessKey: &s3meta.AccessKey{ID: "JYOLD", Secret: "s", Tenant: "old"}})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "legacy key sealed", func() bool {
		var tn *s3meta.Tenant
		c.srv.fsm.view(func(x *state) { tn = x.Tenants["old"] })
		return tn.MasterKey == nil && tn.SealedKey != nil
	})
	waitFor(t, "unlocked", c.srv.KeysUnlocked)
	if got, err := c.srv.tenantKey("old"); err != nil || !bytes.Equal(got, mk) {
		t.Fatalf("migrated key: %v", err)
	}
}
