// Package pki holds the cluster certificate authority. Every node, the control
// plane and admin clients get an Ed25519 certificate signed by the cluster CA,
// and every connection between them is mutually authenticated against it.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"

	caLifetime = 10 * 365 * 24 * time.Hour
)

// Kind is stored in a certificate's OrganizationalUnit and says what the
// holder is allowed to do.
type Kind string

const (
	KindNode    Kind = "node"
	KindControl Kind = "control"
	KindAdmin   Kind = "admin"
)

// CA is the cluster certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  ed25519.PrivateKey
}

// NewCA creates a self-signed CA for the named cluster.
func NewCA(cluster string) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "junkyard-ca", Organization: []string{cluster}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: priv}, nil
}

// Cluster returns the cluster name the CA was created for.
func (ca *CA) Cluster() string {
	if len(ca.Cert.Subject.Organization) == 0 {
		return ""
	}
	return ca.Cert.Subject.Organization[0]
}

// Fingerprint is the hex SHA-256 of the CA certificate. Join tokens carry it
// so a new node can pin the CA before it trusts anything the server says.
func (ca *CA) Fingerprint() string { return Fingerprint(ca.Cert.Raw) }

// Fingerprint returns the hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// Issue signs a certificate for pub. name becomes the CommonName (a node ID,
// "control" or an admin name). hosts are added as DNS or IP SANs so the
// certificate can also serve TLS.
func (ca *CA) Issue(kind Kind, name string, pub ed25519.PublicKey, ttl time.Duration, hosts ...string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("pki: empty certificate name")
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         name,
			Organization:       []string{ca.Cluster()},
			OrganizationalUnit: []string{string(kind)},
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
}

// Verify checks that der was issued by this CA and is currently valid, and
// returns the parsed certificate.
func (ca *CA) Verify(der []byte) (*x509.Certificate, error) {
	return VerifyAgainst(ca.Cert, der)
}

// VerifyAgainst checks der against a CA certificate.
func VerifyAgainst(caCert *x509.Certificate, der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// KindOf returns the Kind recorded in a certificate.
func KindOf(cert *x509.Certificate) Kind {
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return ""
	}
	return Kind(cert.Subject.OrganizationalUnit[0])
}

// Save writes the CA certificate and key into dir. The key file is 0600.
func (ca *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := WriteCertPEM(filepath.Join(dir, caCertFile), ca.Cert.Raw); err != nil {
		return err
	}
	return WriteKeyPEM(filepath.Join(dir, caKeyFile), ca.Key)
}

// LoadCA reads a CA saved with Save.
func LoadCA(dir string) (*CA, error) {
	cert, err := ReadCertPEM(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, err
	}
	key, err := ReadKeyPEM(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// TLSCertificate bundles a leaf certificate, its key and the CA into a
// tls.Certificate that sends the full chain.
func TLSCertificate(leafDER []byte, key ed25519.PrivateKey, caCert *x509.Certificate) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{leafDER, caCert.Raw},
		PrivateKey:  key,
	}
}

// CertPEM encodes a DER certificate as PEM.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ParseCertPEM decodes one PEM certificate.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("pki: no CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// WriteCertPEM writes a DER certificate as PEM.
func WriteCertPEM(path string, der []byte) error {
	return os.WriteFile(path, CertPEM(der), 0o644)
}

// ReadCertPEM reads a PEM certificate file.
func ReadCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCertPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

// WriteKeyPEM writes an Ed25519 private key as PKCS#8 PEM with mode 0600.
func WriteKeyPEM(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// ReadKeyPEM reads an Ed25519 PKCS#8 PEM key file.
func ReadKeyPEM(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: no PRIVATE KEY block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return key, nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
