package agent

import (
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/membership"
)

func TestPeers(t *testing.T) {
	registry := []cluster.Member{
		{NodeID: "n-self", MeshIP: "100.64.0.1", WGPublic: "self"},
		{NodeID: "n-b", MeshIP: "100.64.0.3", WGPublic: "kb", WGEndpoint: "198.51.100.2:51820"},
		{NodeID: "n-a", MeshIP: "100.64.0.2", WGPublic: "ka"},
	}
	alive := []membership.Meta{
		{NodeID: "n-a", WGEndpoint: "203.0.113.9:40000"}, // live endpoint learned from gossip
		{NodeID: "n-evil", WGEndpoint: "192.0.2.1:1"},    // not in the registry
	}
	peers := Peers(registry, alive, "n-self")
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2: %+v", len(peers), peers)
	}
	if peers[0].NodeID != "n-a" || peers[0].Endpoint != "203.0.113.9:40000" {
		t.Fatalf("gossip endpoint not used: %+v", peers[0])
	}
	if peers[1].NodeID != "n-b" || peers[1].Endpoint != "198.51.100.2:51820" {
		t.Fatalf("registry endpoint not kept: %+v", peers[1])
	}
	for _, p := range peers {
		if p.NodeID == "n-evil" || p.NodeID == "n-self" {
			t.Fatalf("unexpected peer %s", p.NodeID)
		}
	}
}
