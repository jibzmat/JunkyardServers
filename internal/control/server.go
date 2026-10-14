// Package control is the M0 control plane: it owns the cluster CA, issues join
// tokens, admits nodes, assigns mesh addresses and trust tiers, and serves the
// member list over mutually authenticated TLS.
package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

const (
	controlCertFile = "control.crt"
	controlKeyFile  = "control.key"

	nodeCertLifetime  = 365 * 24 * time.Hour
	adminCertLifetime = 365 * 24 * time.Hour
	maxTokenTTL       = 7 * 24 * time.Hour
	maxBodyBytes      = 64 << 10
)

// Server is the control plane.
type Server struct {
	dir     string
	ca      *pki.CA
	tlsCert tls.Certificate
	prefix  netip.Prefix

	mu sync.Mutex
	st *state

	now func() time.Time
}

// AdminCredentials is the certificate an operator's jyctl uses.
type AdminCredentials struct {
	CertDER []byte
	Key     ed25519.PrivateKey
}

// Init creates a new cluster in dir: the CA, the control plane's TLS
// certificate for addr, a gossip key, empty state, and one admin credential.
func Init(dir, clusterName, addr string) (*AdminCredentials, error) {
	if _, err := os.Stat(filepath.Join(dir, stateFile)); err == nil {
		return nil, fmt.Errorf("control: %s already holds a cluster", dir)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("control: address %q: %w", addr, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ca, err := pki.NewCA(clusterName)
	if err != nil {
		return nil, err
	}
	if err := ca.Save(dir); err != nil {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := ca.Issue(pki.KindControl, "control", pub, nodeCertLifetime, host, "localhost", "127.0.0.1")
	if err != nil {
		return nil, err
	}
	if err := pki.WriteCertPEM(filepath.Join(dir, controlCertFile), der); err != nil {
		return nil, err
	}
	if err := pki.WriteKeyPEM(filepath.Join(dir, controlKeyFile), priv); err != nil {
		return nil, err
	}

	gossipKey := make([]byte, 32)
	if _, err := rand.Read(gossipKey); err != nil {
		return nil, err
	}
	st := &state{
		Cluster:   clusterName,
		Address:   addr,
		GossipKey: gossipKey,
		Tokens:    map[string]*token.Record{},
		Members:   map[string]*cluster.Member{},
	}
	if err := st.save(dir); err != nil {
		return nil, err
	}

	apub, apriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	aderr, err := ca.Issue(pki.KindAdmin, "admin", apub, adminCertLifetime)
	if err != nil {
		return nil, err
	}
	return &AdminCredentials{CertDER: aderr, Key: apriv}, nil
}

// Open loads an initialised control plane from dir.
func Open(dir string) (*Server, error) {
	ca, err := pki.LoadCA(dir)
	if err != nil {
		return nil, err
	}
	certDER, err := pki.ReadCertPEM(filepath.Join(dir, controlCertFile))
	if err != nil {
		return nil, err
	}
	key, err := pki.ReadKeyPEM(filepath.Join(dir, controlKeyFile))
	if err != nil {
		return nil, err
	}
	st, err := loadState(dir)
	if err != nil {
		return nil, err
	}
	return &Server{
		dir:     dir,
		ca:      ca,
		tlsCert: pki.TLSCertificate(certDER.Raw, key, ca.Cert),
		prefix:  netip.MustParsePrefix(MeshCIDR),
		st:      st,
		now:     time.Now,
	}, nil
}

// CA returns the cluster CA certificate.
func (s *Server) CA() *x509.Certificate { return s.ca.Cert }

// Address returns the control plane address recorded at Init.
func (s *Server) Address() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Address
}

// TLSConfig is the server-side TLS configuration. Client certificates are
// optional at the TLS layer (a joining node has none yet) and required per
// endpoint by the handlers.
func (s *Server) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Cert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.tlsCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
}

// Handler returns the HTTP API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/join", s.handleJoin)
	mux.HandleFunc("POST /v1/tokens", s.requireKind(s.handleToken, pki.KindAdmin))
	mux.HandleFunc("GET /v1/members", s.requireKind(s.handleMembers, pki.KindAdmin, pki.KindNode, pki.KindControl))
	return mux
}

// ListenAndServe serves the API on addr until it fails.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		TLSConfig:         s.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServeTLS("", "")
}

// IssueToken creates a join token. trusted marks nodes joining with it as
// owner-trusted; otherwise they join as untrusted.
func (s *Server) IssueToken(trusted bool, ttl time.Duration, maxUses int) (string, error) {
	if ttl <= 0 || ttl > maxTokenTTL {
		return "", fmt.Errorf("control: token ttl must be between 1s and %s", maxTokenTTL)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, rec, err := token.New(s.st.Address, s.ca.Fingerprint(), trusted, ttl, maxUses)
	if err != nil {
		return "", err
	}
	s.st.Tokens[rec.ID] = &rec
	s.pruneTokens()
	if err := s.st.save(s.dir); err != nil {
		delete(s.st.Tokens, rec.ID)
		return "", err
	}
	return t.String(), nil
}

// ErrUnauthorized is returned for a bad token.
var ErrUnauthorized = errors.New("control: join not authorised")

// Join admits a node. Validation of the token, tier assignment, certificate
// issue and address allocation happen under one lock so two joins can never
// share a token use or an address.
func (s *Server) Join(req cluster.JoinRequest) (*cluster.JoinResponse, error) {
	if err := validateKeys(req); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.st.Tokens[req.TokenID]
	if !ok {
		return nil, ErrUnauthorized
	}
	if err := rec.Check(req.TokenSecret, s.now()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return s.admit(req, rec)
}

// EnrollLocal admits the control node itself at init time, as an
// owner-trusted node, without a token.
func (s *Server) EnrollLocal(req cluster.JoinRequest) (*cluster.JoinResponse, error) {
	if err := validateKeys(req); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admit(req, &token.Record{Trusted: true})
}

func validateKeys(req cluster.JoinRequest) error {
	if len(req.SigningKey) != ed25519.PublicKeySize {
		return errors.New("control: signing key must be an Ed25519 public key")
	}
	if _, err := wgtypes.ParseKey(req.WGPublic); err != nil {
		return fmt.Errorf("control: wireguard key: %w", err)
	}
	return nil
}

// admit must be called with s.mu held.
func (s *Server) admit(req cluster.JoinRequest, rec *token.Record) (*cluster.JoinResponse, error) {
	// Hardware memory encryption is only a claim until attestation (M2), so
	// a stranger's PC joins as untrusted even if it reports SEV-SNP or TDX.
	tier := cluster.TierUntrusted
	if rec.Trusted {
		tier = cluster.TierTrusted
	}
	roles := tier.AllowedRoles(req.Roles)
	if len(roles) == 0 {
		roles = []cluster.Role{cluster.RoleStorage}
	}

	nodeID, err := newNodeID()
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, m := range s.st.Members {
		used[m.MeshIP] = true
	}
	ip, err := allocateIP(s.prefix, used)
	if err != nil {
		return nil, err
	}
	certDER, err := s.ca.Issue(pki.KindNode, nodeID, ed25519.PublicKey(req.SigningKey), nodeCertLifetime, ip.String())
	if err != nil {
		return nil, err
	}

	m := &cluster.Member{
		NodeID:     nodeID,
		Roles:      roles,
		Tier:       tier,
		MeshIP:     ip.String(),
		WGPublic:   req.WGPublic,
		WGEndpoint: req.WGEndpoint,
		GossipAddr: req.GossipAddr,
		Hardware:   req.Hardware,
		JoinedAt:   s.now().UTC().Format(time.RFC3339),
	}
	s.st.Members[nodeID] = m
	rec.Uses++
	if err := s.st.save(s.dir); err != nil {
		delete(s.st.Members, nodeID)
		rec.Uses--
		return nil, err
	}

	return &cluster.JoinResponse{
		NodeID:    nodeID,
		Cluster:   s.st.Cluster,
		CertPEM:   pki.CertPEM(certDER),
		CAPEM:     pki.CertPEM(s.ca.Cert.Raw),
		Tier:      tier,
		Roles:     roles,
		MeshIP:    ip.String(),
		MeshCIDR:  s.prefix.String(),
		GossipKey: append([]byte(nil), s.st.GossipKey...),
		Peers:     s.membersLocked(nodeID),
	}, nil
}

// Members returns every admitted node, sorted by mesh address.
func (s *Server) Members() []cluster.Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.membersLocked("")
}

func (s *Server) membersLocked(except string) []cluster.Member {
	out := make([]cluster.Member, 0, len(s.st.Members))
	for id, m := range s.st.Members {
		if id != except {
			out = append(out, *m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].MeshIP)
		b, _ := netip.ParseAddr(out[j].MeshIP)
		return a.Less(b)
	})
	return out
}

func (s *Server) pruneTokens() {
	now := s.now()
	for id, r := range s.st.Tokens {
		if now.After(r.Expires) || (r.MaxUses > 0 && r.Uses >= r.MaxUses) {
			delete(s.st.Tokens, id)
		}
	}
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req cluster.JoinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad join request")
		return
	}
	resp, err := s.Join(req)
	switch {
	case errors.Is(err, ErrUnauthorized):
		httpError(w, http.StatusUnauthorized, "join token rejected")
		return
	case err != nil:
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var req cluster.TokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad token request")
		return
	}
	tok, err := s.IssueToken(req.Trusted, time.Duration(req.TTLSeconds)*time.Second, req.MaxUses)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, cluster.TokenResponse{Token: tok})
}

func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Members())
}

// requireKind rejects requests without a verified client certificate of one
// of the given kinds.
func (s *Server) requireKind(next http.HandlerFunc, kinds ...pki.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			httpError(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		got := pki.KindOf(r.TLS.VerifiedChains[0][0])
		for _, k := range kinds {
			if got == k {
				next(w, r)
				return
			}
		}
		httpError(w, http.StatusForbidden, "certificate not allowed here")
	}
}

func newNodeID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "n-" + hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
