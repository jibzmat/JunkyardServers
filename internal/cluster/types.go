// Package cluster holds the types shared by the control plane, the node
// daemon and the admin CLI.
package cluster

import (
	"fmt"
	"strings"

	"github.com/jibzmat/JunkyardServers/internal/hw"
)

// Role is a job a node does for the cluster. One PC can hold several.
type Role string

const (
	RoleControl Role = "control"
	RoleGateway Role = "gateway"
	RoleCompute Role = "compute"
	RoleStorage Role = "storage"
)

// AllRoles lists every role in a stable order.
var AllRoles = []Role{RoleControl, RoleGateway, RoleCompute, RoleStorage}

// ParseRoles parses a comma-separated role list such as "storage,compute".
func ParseRoles(s string) ([]Role, error) {
	var out []Role
	seen := map[Role]bool{}
	for _, part := range strings.Split(s, ",") {
		r := Role(strings.TrimSpace(part))
		if r == "" {
			continue
		}
		valid := false
		for _, known := range AllRoles {
			if r == known {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("unknown role %q", r)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// Tier says how far the cluster trusts a node's owner.
type Tier string

const (
	// TierTrusted: the owner vouched for this PC (it is one of yours).
	TierTrusted Tier = "trusted"
	// TierConfidential: a stranger's PC with attested SEV-SNP or TDX, so
	// guest RAM is encrypted by the CPU and hidden from the host owner.
	TierConfidential Tier = "confidential"
	// TierUntrusted: a stranger's PC without memory encryption. It offers
	// the same storage and compute features; only encrypted RAM is missing,
	// so its owner could read the memory of guests it runs.
	TierUntrusted Tier = "untrusted"
)

// AllowedRoles filters requested roles down to the ones the tier permits.
// Storage and compute are open to every tier: storage only ever holds
// ciphertext, and where a guest may run is the tenant's choice (Placement).
// The control plane and gateways hold the CA key, key-service shares and
// every tenant's data keys, so they run only on owner-trusted PCs. SEV-SNP
// and TDX protect guests, not host processes, so confidential PCs don't
// qualify either.
func (t Tier) AllowedRoles(requested []Role) []Role {
	var out []Role
	for _, r := range requested {
		switch r {
		case RoleStorage, RoleCompute:
			out = append(out, r)
		case RoleControl, RoleGateway:
			if t == TierTrusted {
				out = append(out, r)
			}
		}
	}
	return out
}

// Placement is a tenant's choice of which hosts may run an instance. It
// trades the size of the compute pool against who could see guest RAM.
type Placement string

const (
	// PlacementConfidential: only hosts whose CPU encrypts guest RAM.
	PlacementConfidential Placement = "confidential"
	// PlacementPrivate (default): the owner's PCs or confidential hosts;
	// no stranger can read guest memory.
	PlacementPrivate Placement = "private"
	// PlacementAny: every compute host, including untrusted PCs. For
	// workloads whose memory may be visible to the host owner.
	PlacementAny Placement = "any"
)

// ParsePlacement parses a placement name; empty means PlacementPrivate.
func ParsePlacement(s string) (Placement, error) {
	switch p := Placement(s); p {
	case "":
		return PlacementPrivate, nil
	case PlacementConfidential, PlacementPrivate, PlacementAny:
		return p, nil
	default:
		return "", fmt.Errorf("unknown placement %q", s)
	}
}

// Allows reports whether an instance with this placement may run on a host
// of the given tier. Confidential placement needs hardware memory
// encryption, which owner-trusted PCs only have if attested as such.
func (p Placement) Allows(host Tier, hostConfidential bool) bool {
	switch p {
	case PlacementConfidential:
		return hostConfidential
	case PlacementPrivate:
		return host == TierTrusted || host == TierConfidential || hostConfidential
	case PlacementAny:
		return true
	}
	return false
}

// Member is the control plane's record of a node.
type Member struct {
	NodeID     string `json:"node_id"`
	Roles      []Role `json:"roles"`
	Tier       Tier   `json:"tier"`
	MeshIP     string `json:"mesh_ip"`
	WGPublic   string `json:"wg_public"`             // base64 WireGuard public key
	WGEndpoint string `json:"wg_endpoint,omitempty"` // public host:port, if reachable
	GossipAddr string `json:"gossip_addr,omitempty"` // host:port for memberlist
	// StoragePort is the shard server's port on storage nodes. It is
	// reached on the mesh IP, or on the gossip host without a mesh.
	StoragePort int     `json:"storage_port,omitempty"`
	Hardware    hw.Info `json:"hardware"`
	JoinedAt    string  `json:"joined_at"`

	// Reputation from storage audits (see control's audit.go).
	Audits AuditRecord `json:"audits,omitempty"`
	// Drained nodes get no new instances or replicas; their running
	// instances are live-migrated away (jyctl drain).
	Drained bool `json:"drained,omitempty"`
}

// AuditRecord is a storage node's audit history and standing.
type AuditRecord struct {
	Passed int `json:"passed,omitempty"`
	Failed int `json:"failed,omitempty"`
	// Score is 0 to 1: it rises a little with each audit passed and halves
	// with each one failed.
	Score    float64 `json:"score,omitempty"`
	LastFail string  `json:"last_fail,omitempty"` // RFC 3339
	// Suspended nodes get no new shards or instances, and their shards
	// are rebuilt elsewhere, until their score recovers.
	Suspended bool `json:"suspended,omitempty"`
}

// Has reports whether the member holds a role.
func (m Member) Has(r Role) bool {
	for _, x := range m.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// JoinRequest is sent by a new node to the control plane.
type JoinRequest struct {
	TokenID     string  `json:"token_id"`
	TokenSecret string  `json:"token_secret"`
	SigningKey  []byte  `json:"signing_key"` // Ed25519 public key for the node certificate
	WGPublic    string  `json:"wg_public"`
	WGEndpoint  string  `json:"wg_endpoint,omitempty"`
	GossipAddr  string  `json:"gossip_addr,omitempty"`
	StoragePort int     `json:"storage_port,omitempty"`
	Roles       []Role  `json:"roles"`
	Hardware    hw.Info `json:"hardware"`
}

// JoinResponse returns everything the node needs to take part.
type JoinResponse struct {
	NodeID    string   `json:"node_id"`
	Cluster   string   `json:"cluster"`
	CertPEM   []byte   `json:"cert_pem"`
	CAPEM     []byte   `json:"ca_pem"`
	Tier      Tier     `json:"tier"`
	Roles     []Role   `json:"roles"` // the roles actually granted
	MeshIP    string   `json:"mesh_ip"`
	MeshCIDR  string   `json:"mesh_cidr"`
	GossipKey []byte   `json:"gossip_key"` // AES-256 key for encrypted gossip
	Peers     []Member `json:"peers"`
	// ControlAddrs lists every control node's API address, so the node can
	// reach the control plane when any one of them is down.
	ControlAddrs []string `json:"control_addrs"`
}

// TokenRequest asks the control plane for a new join token (admin only).
type TokenRequest struct {
	Trusted    bool `json:"trusted"`
	TTLSeconds int  `json:"ttl_seconds"`
	MaxUses    int  `json:"max_uses"`
}

// TokenResponse carries the encoded token.
type TokenResponse struct {
	Token string `json:"token"`
}

// ControlEnrollRequest asks to turn an owner-trusted node into a control node.
type ControlEnrollRequest struct {
	PublicKey []byte `json:"public_key"` // Ed25519 key for the control certificate
	APIAddr   string `json:"api_addr"`
	RaftAddr  string `json:"raft_addr"`
}

// ControlEnrollResponse hands over the control certificate and the CA key.
type ControlEnrollResponse struct {
	ID       string   `json:"id"`
	CertPEM  []byte   `json:"cert_pem"`
	CAPEM    []byte   `json:"ca_pem"`
	CAKeyDER []byte   `json:"ca_key_der"`
	APIAddr  string   `json:"api_addr"`
	RaftAddr string   `json:"raft_addr"`
	Peers    []string `json:"peers"`
}
