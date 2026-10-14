package node

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
)

func TestSaveLoad(t *testing.T) {
	ca, _ := pki.NewCA("test")
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.Issue(pki.KindNode, "n-1", keys.SigningPublic(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := Config{NodeID: "n-1", Tier: cluster.TierStorageOnly, MeshIP: "100.64.0.1", GossipKey: []byte("k")}
	if err := Save(dir, cfg, keys, pki.CertPEM(der), pki.CertPEM(ca.Cert.Raw)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{keyFile, wgKeyFile, configFile} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", f, st.Mode().Perm())
		}
	}
	n, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n.Config.NodeID != "n-1" || n.Keys.WireGuard != keys.WireGuard || !n.Keys.Signing.Equal(keys.Signing) {
		t.Fatal("loaded node differs")
	}
}

func TestLoadRejectsForeignCert(t *testing.T) {
	ca, _ := pki.NewCA("test")
	other, _ := pki.NewCA("other")
	keys, _ := NewKeys()
	der, _ := other.Issue(pki.KindNode, "n-1", keys.SigningPublic(), time.Hour)
	dir := t.TempDir()
	if err := Save(dir, Config{NodeID: "n-1"}, keys, pki.CertPEM(der), pki.CertPEM(ca.Cert.Raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("loaded a node whose certificate is from another CA")
	}
}
