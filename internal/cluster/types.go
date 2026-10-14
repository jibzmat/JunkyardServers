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

// Tier says how far the cluster trusts a node with plaintext.
type Tier string

const (
	// TierConfidential: attested SEV-SNP or TDX; any tenant's guests may run here.
	TierConfidential Tier = "confidential"
	// TierTrusted: the owner vouched for this PC; plaintext allowed.
	TierTrusted Tier = "trusted"
	// TierStorageOnly: a stranger's PC; holds ciphertext and relays only.
	TierStorageOnly Tier = "storage-only"
)

// MayDecrypt reports whether a node in this tier may ever hold plaintext
// tenant data or keys.
func (t Tier) MayDecrypt() bool { return t == TierConfidential || t == TierTrusted }

// AllowedRoles filters requested roles down to the ones the tier permits.
// Untrusted nodes never run guests, gateways or the control plane, because
// all of those see keys or plaintext.
func (t Tier) AllowedRoles(requested []Role) []Role {
	var out []Role
	for _, r := range requested {
		if r == RoleStorage || t.MayDecrypt() {
			out = append(out, r)
		}
	}
	return out
}

// Member is the control plane's record of a node.
type Member struct {
	NodeID     string  `json:"node_id"`
	Roles      []Role  `json:"roles"`
	Tier       Tier    `json:"tier"`
	MeshIP     string  `json:"mesh_ip"`
	WGPublic   string  `json:"wg_public"`             // base64 WireGuard public key
	WGEndpoint string  `json:"wg_endpoint,omitempty"` // public host:port, if reachable
	GossipAddr string  `json:"gossip_addr,omitempty"` // host:port for memberlist
	Hardware   hw.Info `json:"hardware"`
	JoinedAt   string  `json:"joined_at"`
}

// JoinRequest is sent by a new node to the control plane.
type JoinRequest struct {
	TokenID     string  `json:"token_id"`
	TokenSecret string  `json:"token_secret"`
	SigningKey  []byte  `json:"signing_key"` // Ed25519 public key for the node certificate
	WGPublic    string  `json:"wg_public"`
	WGEndpoint  string  `json:"wg_endpoint,omitempty"`
	GossipAddr  string  `json:"gossip_addr,omitempty"`
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
