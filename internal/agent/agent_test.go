package agent

import (
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/membership"
	"github.com/jibzmat/JunkyardServers/internal/mesh"
	"github.com/jibzmat/JunkyardServers/internal/nat"
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

func TestRelays(t *testing.T) {
	registry := []cluster.Member{
		{NodeID: "self", Tier: cluster.TierTrusted, WGEndpoint: "203.0.113.1:51820"},
		{NodeID: "mine-public", Tier: cluster.TierTrusted},
		{NodeID: "mine-natted", Tier: cluster.TierTrusted},
		{NodeID: "stranger-public", Tier: cluster.TierUntrusted, WGEndpoint: "203.0.113.3:51820"},
		{NodeID: "mine-down", Tier: cluster.TierTrusted, WGEndpoint: "203.0.113.4:51820"},
	}
	alive := []membership.Meta{
		{NodeID: "self"},
		{NodeID: "mine-public", WGEndpoint: "203.0.113.2:51820"},
		{NodeID: "mine-natted", WGEndpoint: "192.168.1.9:51820"},
		{NodeID: "stranger-public", WGEndpoint: "203.0.113.3:51820"},
	}
	got := Relays(registry, alive, "self")
	if len(got) != 1 || got[0] != "mine-public" {
		t.Fatalf("relays = %v, want [mine-public]", got)
	}
}

func TestApplyRoutes(t *testing.T) {
	peers := []mesh.Peer{
		{NodeID: "a", MeshIP: "100.64.0.2"},
		{NodeID: "r", MeshIP: "100.64.0.3"},
		{NodeID: "c", MeshIP: "100.64.0.4"},
	}
	routes := []nat.Route{
		{NodeID: "a", Mode: nat.Relayed, Via: "r"},
		{NodeID: "r", Mode: nat.Direct},
		{NodeID: "c", Mode: nat.Relayed, Via: "r"},
	}
	out := ApplyRoutes(peers, routes)
	if len(out) != 1 || out[0].NodeID != "r" {
		t.Fatalf("peers = %+v, want only the relay", out)
	}
	if len(out[0].Relayed) != 2 || out[0].Relayed[0] != "100.64.0.2" || out[0].Relayed[1] != "100.64.0.4" {
		t.Fatalf("relayed = %v", out[0].Relayed)
	}
}
