package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestIssueAndVerify(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, err := ca.Issue(KindNode, "n-1", pub, time.Hour, "100.64.0.1", "node1")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Verify(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "n-1" || KindOf(cert) != KindNode {
		t.Fatalf("got CN %q kind %q", cert.Subject.CommonName, KindOf(cert))
	}
	if len(cert.IPAddresses) != 1 || len(cert.DNSNames) != 1 {
		t.Fatalf("SANs not set: %v %v", cert.IPAddresses, cert.DNSNames)
	}

	other, _ := NewCA("other")
	if _, err := other.Verify(der); err == nil {
		t.Fatal("certificate verified against the wrong CA")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA("test")
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint() != ca.Fingerprint() || got.Cluster() != "test" {
		t.Fatal("loaded CA differs")
	}
	if !got.Key.Equal(ca.Key) {
		t.Fatal("loaded key differs")
	}
}
