// Package node keeps a node's identity and configuration on disk: its signing
// key and certificate, its WireGuard key, the pinned cluster CA and what the
// control plane assigned it at join time.
package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
)

const (
	keyFile    = "node.key"
	certFile   = "node.crt"
	caFile     = "ca.crt"
	wgKeyFile  = "wg.key"
	configFile = "node.json"
)

// Config is what a node needs to run, saved as node.json.
type Config struct {
	NodeID     string         `json:"node_id"`
	Cluster    string         `json:"cluster"`
	Control    string         `json:"control"`            // control plane host:port used to join
	Controls   []string       `json:"controls,omitempty"` // every control node's API address
	Tier       cluster.Tier   `json:"tier"`
	Roles      []cluster.Role `json:"roles"`
	MeshIP     string         `json:"mesh_ip"`
	MeshCIDR   string         `json:"mesh_cidr"`
	GossipKey  []byte         `json:"gossip_key"`
	GossipAddr string         `json:"gossip_addr"` // host:port this node gossips on
	WGPort     int            `json:"wg_port"`
	WGEndpoint string         `json:"wg_endpoint,omitempty"` // public host:port, if reachable
	Seeds      []string       `json:"seeds"`                 // gossip addresses known at join
	// StoragePort is where the shard server listens (storage role).
	StoragePort int `json:"storage_port,omitempty"`
	// S3Listen is where the S3 gateway listens (gateway role).
	S3Listen string `json:"s3_listen,omitempty"`
}

// ControlAddrs returns the control plane addresses to try, in order.
func (c Config) ControlAddrs() []string {
	out := append([]string(nil), c.Controls...)
	for _, a := range out {
		if a == c.Control {
			return out
		}
	}
	return append(out, c.Control)
}

// Keys are a node's private keys, generated before it joins.
type Keys struct {
	Signing   ed25519.PrivateKey
	WireGuard wgtypes.Key
}

// NewKeys generates fresh keys.
func NewKeys() (*Keys, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	wg, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &Keys{Signing: priv, WireGuard: wg}, nil
}

// SigningPublic returns the Ed25519 public key.
func (k *Keys) SigningPublic() ed25519.PublicKey {
	return k.Signing.Public().(ed25519.PublicKey)
}

// Node is a loaded node directory.
type Node struct {
	Dir    string
	Config Config
	Keys   *Keys
	Cert   *x509.Certificate
	CA     *x509.Certificate
}

// Save writes keys, certificates and config into dir. Private keys are 0600.
func Save(dir string, cfg Config, keys *Keys, certPEM, caPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if _, err := pki.ParseCertPEM(certPEM); err != nil {
		return fmt.Errorf("node certificate: %w", err)
	}
	if _, err := pki.ParseCertPEM(caPEM); err != nil {
		return fmt.Errorf("CA certificate: %w", err)
	}
	if err := pki.WriteKeyPEM(filepath.Join(dir, keyFile), keys.Signing); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, wgKeyFile), []byte(keys.WireGuard.String()+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, caFile), caPEM, 0o644); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// The gossip key is a cluster secret, so the config is private too.
	return os.WriteFile(filepath.Join(dir, configFile), b, 0o600)
}

// Load reads a node directory and checks the certificate chains to the CA.
func Load(dir string) (*Node, error) {
	b, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", configFile, err)
	}
	signing, err := pki.ReadKeyPEM(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	wgb, err := os.ReadFile(filepath.Join(dir, wgKeyFile))
	if err != nil {
		return nil, err
	}
	wg, err := wgtypes.ParseKey(string(trimNL(wgb)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", wgKeyFile, err)
	}
	ca, err := pki.ReadCertPEM(filepath.Join(dir, caFile))
	if err != nil {
		return nil, err
	}
	certRaw, err := pki.ReadCertPEM(filepath.Join(dir, certFile))
	if err != nil {
		return nil, err
	}
	cert, err := pki.VerifyAgainst(ca, certRaw.Raw)
	if err != nil {
		return nil, fmt.Errorf("node certificate: %w", err)
	}
	return &Node{
		Dir:    dir,
		Config: cfg,
		Keys:   &Keys{Signing: signing, WireGuard: wg},
		Cert:   cert,
		CA:     ca,
	}, nil
}

// TLSCertificate returns the node's certificate for mutual TLS.
func (n *Node) TLSCertificate() tls.Certificate {
	return pki.TLSCertificate(n.Cert.Raw, n.Keys.Signing, n.CA)
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
