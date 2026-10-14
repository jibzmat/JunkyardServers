package mesh

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func peerKey(t *testing.T) string {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func TestWGQuickAndValidate(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	cfg := Config{
		PrivateKey: priv,
		ListenPort: 51820,
		MeshIP:     "100.64.0.1",
		MeshCIDR:   "100.64.0.0/10",
		Peers: []Peer{
			{NodeID: "n-b", PublicKey: peerKey(t), MeshIP: "100.64.0.3"},
			{NodeID: "n-a", PublicKey: peerKey(t), MeshIP: "100.64.0.2", Endpoint: "203.0.113.5:51820", Relayed: []string{"100.64.0.9"}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	out := cfg.WGQuick()
	for _, want := range []string{"Address = 100.64.0.1/10", "ListenPort = 51820", "AllowedIPs = 100.64.0.2/32, 100.64.0.9/32", "Endpoint = 203.0.113.5:51820", "PersistentKeepalive = 25"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "n-a") > strings.Index(out, "n-b") {
		t.Error("peers not sorted by mesh IP")
	}
}

func TestValidateRejectsBadPeer(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	cfg := Config{PrivateKey: priv, ListenPort: 51820, MeshIP: "100.64.0.1", MeshCIDR: "100.64.0.0/10",
		Peers: []Peer{{NodeID: "n-x", PublicKey: "not-a-key", MeshIP: "100.64.0.2"}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("bad peer key accepted")
	}
}
