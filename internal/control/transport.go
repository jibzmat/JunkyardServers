package control

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/hashicorp/raft"

	"github.com/jibzmat/JunkyardServers/internal/pki"
)

// tlsStream is a Raft stream layer over mutual TLS. Both ends must present a
// control-plane certificate from the cluster CA, so only control nodes (which
// run on owner-trusted PCs) can take part in consensus.
type tlsStream struct {
	net.Listener
	advertise net.Addr
	client    *tls.Config
}

func newTLSStream(bind, advertise string, cert tls.Certificate, ca *x509.Certificate) (*tlsStream, error) {
	adv, err := net.ResolveTCPAddr("tcp", advertise)
	if err != nil {
		return nil, err
	}
	if adv.IP == nil || adv.IP.IsUnspecified() {
		return nil, errors.New("control: raft address must name a reachable IP")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || pki.KindOf(cs.PeerCertificates[0]) != pki.KindControl {
			return errors.New("control: raft peer is not a control node")
		}
		return nil
	}
	server := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        pool,
		VerifyConnection: verify,
	}
	ln, err := tls.Listen("tcp", bind, server)
	if err != nil {
		return nil, err
	}
	if adv.Port == 0 {
		adv.Port = ln.Addr().(*net.TCPAddr).Port
	}
	client := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		VerifyConnection: verify,
	}
	return &tlsStream{Listener: ln, advertise: adv, client: client}, nil
}

func (s *tlsStream) Addr() net.Addr { return s.advertise }

func (s *tlsStream) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	cfg := s.client.Clone()
	host, _, err := net.SplitHostPort(string(address))
	if err != nil {
		return nil, err
	}
	cfg.ServerName = host
	d := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(d, "tcp", string(address), cfg)
}
