// Package control is the control plane: it owns the cluster CA, issues join
// tokens, admits nodes, assigns mesh addresses and trust tiers, and serves the
// member list over mutually authenticated TLS.
//
// Its state is replicated with Raft across every control node. Control nodes
// run only on owner-trusted PCs, because each holds the CA key. Any control
// node answers reads; writes are redirected to the current leader.
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
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/token"
)

const (
	controlCertFile = "control.crt"
	controlKeyFile  = "control.key"
	controlInfoFile = "control.json"
	raftDirName     = "raft"

	nodeCertLifetime  = 365 * 24 * time.Hour
	adminCertLifetime = 365 * 24 * time.Hour
	maxTokenTTL       = 7 * 24 * time.Hour
	maxBodyBytes      = 64 << 10
	applyTimeout      = 10 * time.Second
)

// localInfo is this control node's own identity, saved as control.json.
type localInfo struct {
	ControlInfo
	// Peers are other control API addresses, used by a newly enrolled control
	// node to ask the leader to add it to the Raft group.
	Peers []string `json:"peers,omitempty"`
}

// Server is one control node.
type Server struct {
	dir     string
	info    localInfo
	ca      *pki.CA
	tlsCert tls.Certificate
	prefix  netip.Prefix
	logger  *log.Logger

	fsm    *fsm
	raft   *raft.Raft
	store  *boltStore
	stream *tlsStream

	// writeMu serialises leader-side read-validate-apply sequences so two
	// joins can't pick the same mesh address.
	writeMu sync.Mutex

	now func() time.Time

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}

	// Key protection (kek.go).
	sharePub, sharePriv *[32]byte
	kekMu               sync.Mutex
	kek                 []byte
	kekEpoch            int
}

// AdminCredentials is the certificate an operator's jyctl uses.
type AdminCredentials struct {
	CertDER []byte
	Key     ed25519.PrivateKey
}

// Errors returned by write operations.
var (
	ErrUnauthorized = errors.New("control: join not authorised")
	ErrNotLeader    = errors.New("control: not the leader")
)

// Init creates a new cluster in dir and starts its first control node: the
// CA, this node's control certificate, an admin credential, and a one-node
// Raft group holding the cluster name and gossip key. apiAddr and raftAddr
// must be addresses other PCs can reach.
func Init(dir, clusterName, apiAddr, raftAddr string, logger *log.Logger) (*Server, *AdminCredentials, error) {
	if _, err := os.Stat(filepath.Join(dir, controlInfoFile)); err == nil {
		return nil, nil, fmt.Errorf("control: %s already holds a control node", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	ca, err := pki.NewCA(clusterName)
	if err != nil {
		return nil, nil, err
	}
	if err := ca.Save(dir); err != nil {
		return nil, nil, err
	}
	id, err := randID("c-")
	if err != nil {
		return nil, nil, err
	}
	if err := writeControlCert(dir, ca, id, apiAddr, raftAddr); err != nil {
		return nil, nil, err
	}
	info := localInfo{ControlInfo: ControlInfo{ID: id, APIAddr: apiAddr, RaftAddr: raftAddr}}
	if err := writeJSON0600(filepath.Join(dir, controlInfoFile), info); err != nil {
		return nil, nil, err
	}

	s, err := open(dir, true, logger)
	if err != nil {
		return nil, nil, err
	}
	if err := s.waitLeader(15 * time.Second); err != nil {
		s.Close()
		return nil, nil, err
	}
	gossipKey := make([]byte, 32)
	if _, err := rand.Read(gossipKey); err != nil {
		s.Close()
		return nil, nil, err
	}
	self := s.info.ControlInfo
	if err := s.apply(command{Op: opInit, Cluster: clusterName, GossipKey: gossipKey, Control: &self}); err != nil {
		s.Close()
		return nil, nil, err
	}
	// Register this node's share key and create the first KEK now, so
	// tenants can be created as soon as Init returns.
	for i := 0; i < 3 && !s.KeysUnlocked(); i++ {
		if err := s.keyStep(); err != nil {
			s.Close()
			return nil, nil, err
		}
	}

	apub, apriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.Close()
		return nil, nil, err
	}
	der, err := ca.Issue(pki.KindAdmin, "admin", apub, adminCertLifetime)
	if err != nil {
		s.Close()
		return nil, nil, err
	}
	return s, &AdminCredentials{CertDER: der, Key: apriv}, nil
}

// Open starts an existing control node from dir.
func Open(dir string, logger *log.Logger) (*Server, error) {
	return open(dir, false, logger)
}

func open(dir string, bootstrap bool, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	var info localInfo
	b, err := os.ReadFile(filepath.Join(dir, controlInfoFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, fmt.Errorf("%s: %w", controlInfoFile, err)
	}
	ca, err := pki.LoadCA(dir)
	if err != nil {
		return nil, err
	}
	cert, err := pki.ReadCertPEM(filepath.Join(dir, controlCertFile))
	if err != nil {
		return nil, err
	}
	key, err := pki.ReadKeyPEM(filepath.Join(dir, controlKeyFile))
	if err != nil {
		return nil, err
	}
	sharePub, sharePriv, err := loadShareKey(dir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		sharePub:  sharePub,
		sharePriv: sharePriv,
		done:      make(chan struct{}),
		dir:       dir,
		info:      info,
		ca:        ca,
		tlsCert:   pki.TLSCertificate(cert.Raw, key, ca.Cert),
		prefix:    netip.MustParsePrefix(MeshCIDR),
		logger:    logger,
		fsm:       newFSM(),
		now:       time.Now,
	}
	if err := s.startRaft(bootstrap); err != nil {
		s.Close()
		return nil, err
	}
	go s.keyLoop()
	return s, nil
}

func (s *Server) startRaft(bootstrap bool) error {
	raftDir := filepath.Join(s.dir, raftDirName)
	if err := os.MkdirAll(raftDir, 0o700); err != nil {
		return err
	}
	store, err := openBoltStore(filepath.Join(raftDir, "raft.db"))
	if err != nil {
		return err
	}
	s.store = store
	snaps, err := raft.NewFileSnapshotStore(raftDir, 2, io.Discard)
	if err != nil {
		return err
	}
	stream, err := newTLSStream(s.info.RaftAddr, s.info.RaftAddr, s.tlsCert, s.ca.Cert)
	if err != nil {
		return fmt.Errorf("control: raft listener: %w", err)
	}
	s.stream = stream
	trans := raft.NewNetworkTransport(stream, 3, 10*time.Second, io.Discard)

	cfg := raft.DefaultConfig()
	cfg.LocalID = raft.ServerID(s.info.ID)
	cfg.LogOutput = s.logger.Writer()
	// Home links: slower than a datacentre LAN, so be less trigger-happy.
	cfg.HeartbeatTimeout = 2 * time.Second
	cfg.ElectionTimeout = 2 * time.Second
	cfg.LeaderLeaseTimeout = time.Second
	cfg.SnapshotThreshold = 1024

	if bootstrap {
		err := raft.BootstrapCluster(cfg, store, store, snaps, trans, raft.Configuration{
			Servers: []raft.Server{{ID: cfg.LocalID, Address: trans.LocalAddr()}},
		})
		if err != nil {
			return err
		}
	}
	r, err := raft.NewRaft(cfg, s.fsm, store, store, snaps, trans)
	if err != nil {
		return err
	}
	s.raft = r
	return nil
}

// Close stops this control node. It is safe to call more than once.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		var errs []error
		if s.raft != nil {
			// Shutdown also closes the transport and its listener.
			errs = append(errs, s.raft.Shutdown().Error())
		} else if s.stream != nil {
			errs = append(errs, s.stream.Close())
		}
		if s.store != nil {
			errs = append(errs, s.store.Close())
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

// ID returns this control node's Raft ID.
func (s *Server) ID() string { return s.info.ID }

// CA returns the cluster CA certificate.
func (s *Server) CA() *x509.Certificate { return s.ca.Cert }

// APIAddr returns the address this node serves the API on.
func (s *Server) APIAddr() string { return s.info.APIAddr }

// IsLeader reports whether this node currently leads the Raft group.
func (s *Server) IsLeader() bool { return s.raft.State() == raft.Leader }

// IsVoter reports whether this node is part of the Raft configuration yet.
func (s *Server) IsVoter() bool {
	f := s.raft.GetConfiguration()
	if f.Error() != nil {
		return false
	}
	for _, srv := range f.Configuration().Servers {
		if string(srv.ID) == s.info.ID {
			return true
		}
	}
	return false
}

func (s *Server) waitLeader(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, id := s.raft.LeaderWithID(); id != "" {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("control: no raft leader elected")
}

// apply commits a command and returns the state machine's verdict.
func (s *Server) apply(c command) error {
	_, err := s.applyResult(c)
	return err
}

// applyResult commits a command and returns its non-error result.
func (s *Server) applyResult(c command) (any, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	f := s.raft.Apply(b, applyTimeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return nil, ErrNotLeader
		}
		return nil, err
	}
	resp := f.Response()
	if err, ok := resp.(error); ok && err != nil {
		return nil, err
	}
	return resp, nil
}

// leaderBarrier makes sure this node leads and has applied every committed
// entry, so validation reads current state.
func (s *Server) leaderBarrier() error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	if err := s.raft.Barrier(applyTimeout).Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return ErrNotLeader
		}
		return err
	}
	return nil
}

// TLSConfig is the API's server-side TLS configuration. Client certificates
// are optional at the TLS layer (a joining node has none yet) and required
// per endpoint by the handlers.
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
	anyCert := []pki.Kind{pki.KindAdmin, pki.KindNode, pki.KindControl}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/join", s.leaderOnly(s.handleJoin))
	mux.HandleFunc("POST /v1/tokens", s.requireKind(s.leaderOnly(s.handleToken), pki.KindAdmin))
	mux.HandleFunc("GET /v1/members", s.requireKind(s.handleMembers, anyCert...))
	mux.HandleFunc("GET /v1/controls", s.requireKind(s.handleControls, anyCert...))
	mux.HandleFunc("POST /v1/controls/enroll", s.requireKind(s.leaderOnly(s.handleControlEnroll), pki.KindNode))
	mux.HandleFunc("POST /v1/controls/activate", s.requireKind(s.leaderOnly(s.handleControlActivate), pki.KindControl))
	mux.HandleFunc("DELETE /v1/controls/{id}", s.requireKind(s.leaderOnly(s.handleControlRemove), pki.KindAdmin))
	s.s3Routes(mux)
	s.keyRoutes(mux)
	return mux
}

// Serve serves the API on ln until it fails.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         s.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ServeTLS(ln, "", "")
}

// ListenAndServe serves the API on this node's API address.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.info.APIAddr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// IssueToken creates a join token. trusted marks nodes joining with it as
// owner-trusted; otherwise they join as untrusted.
func (s *Server) IssueToken(trusted bool, ttl time.Duration, maxUses int) (string, error) {
	if ttl <= 0 || ttl > maxTokenTTL {
		return "", fmt.Errorf("control: token ttl must be between 1s and %s", maxTokenTTL)
	}
	if !s.IsLeader() {
		return "", ErrNotLeader
	}
	t, rec, err := token.New(s.info.APIAddr, s.ca.Fingerprint(), trusted, ttl, maxUses)
	if err != nil {
		return "", err
	}
	if err := s.apply(command{Op: opPutToken, Token: &rec}); err != nil {
		return "", err
	}
	_ = s.apply(command{Op: opPruneTokens, Now: s.now()})
	return t.String(), nil
}

// Join admits a node presenting a join token.
func (s *Server) Join(req cluster.JoinRequest) (*cluster.JoinResponse, error) {
	if err := validateKeys(req); err != nil {
		return nil, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.leaderBarrier(); err != nil {
		return nil, err
	}
	var rec token.Record
	var found bool
	s.fsm.view(func(st *state) {
		if r, ok := st.Tokens[req.TokenID]; ok {
			rec, found = *r, true
		}
	})
	if !found {
		return nil, ErrUnauthorized
	}
	if err := rec.Check(req.TokenSecret, s.now()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return s.admit(req, rec.ID, rec.Trusted)
}

// EnrollLocal admits the PC running this control node as an owner-trusted
// node, without a token. Used once by jyctl init.
func (s *Server) EnrollLocal(req cluster.JoinRequest) (*cluster.JoinResponse, error) {
	if err := validateKeys(req); err != nil {
		return nil, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.leaderBarrier(); err != nil {
		return nil, err
	}
	return s.admit(req, "", true)
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

// admit must be called on the leader with writeMu held.
func (s *Server) admit(req cluster.JoinRequest, tokenID string, trusted bool) (*cluster.JoinResponse, error) {
	// Hardware memory encryption is only a claim until attestation (M2), so
	// a stranger's PC joins as untrusted even if it reports SEV-SNP or TDX.
	tier := cluster.TierUntrusted
	if trusted {
		tier = cluster.TierTrusted
	}
	roles := tier.AllowedRoles(req.Roles)
	if len(roles) == 0 {
		roles = []cluster.Role{cluster.RoleStorage}
	}

	nodeID, err := randID("n-")
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	var clusterName string
	var gossipKey []byte
	s.fsm.view(func(st *state) {
		for _, m := range st.Members {
			used[m.MeshIP] = true
		}
		clusterName = st.Cluster
		gossipKey = append([]byte(nil), st.GossipKey...)
	})
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
		StoragePort: func() int {
			if hasRole(roles, cluster.RoleStorage) {
				return req.StoragePort
			}
			return 0
		}(),
		JoinedAt: s.now().UTC().Format(time.RFC3339),
	}
	if err := s.apply(command{Op: opAdmit, TokenID: tokenID, Member: m}); err != nil {
		if errors.Is(err, errTokenGone) {
			return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
		}
		return nil, err
	}
	return &cluster.JoinResponse{
		NodeID:       nodeID,
		Cluster:      clusterName,
		CertPEM:      pki.CertPEM(certDER),
		CAPEM:        pki.CertPEM(s.ca.Cert.Raw),
		Tier:         tier,
		Roles:        roles,
		MeshIP:       ip.String(),
		MeshCIDR:     s.prefix.String(),
		GossipKey:    gossipKey,
		Peers:        s.members(nodeID),
		ControlAddrs: s.controlAddrs(),
	}, nil
}

// Members returns every admitted node, sorted by mesh address.
func (s *Server) Members() []cluster.Member { return s.members("") }

func (s *Server) members(except string) []cluster.Member {
	var out []cluster.Member
	s.fsm.view(func(st *state) {
		for id, m := range st.Members {
			if id != except {
				out = append(out, *m)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].MeshIP)
		b, _ := netip.ParseAddr(out[j].MeshIP)
		return a.Less(b)
	})
	return out
}

// Controls returns the known control nodes, sorted by ID.
func (s *Server) Controls() []ControlInfo {
	var out []ControlInfo
	s.fsm.view(func(st *state) {
		for _, c := range st.Controls {
			out = append(out, *c)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) controlAddrs() []string {
	var out []string
	for _, c := range s.Controls() {
		out = append(out, c.APIAddr)
	}
	return out
}

// EnrollControl prepares a trusted node to become a control node: it issues
// a control certificate and hands over the CA key. The new node joins the
// Raft group when it starts and calls activate.
func (s *Server) EnrollControl(nodeID string, req cluster.ControlEnrollRequest) (*cluster.ControlEnrollResponse, error) {
	if len(req.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("control: public key must be Ed25519")
	}
	for _, a := range []string{req.APIAddr, req.RaftAddr} {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return nil, fmt.Errorf("control: address %q: %w", a, err)
		}
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.leaderBarrier(); err != nil {
		return nil, err
	}
	var member *cluster.Member
	s.fsm.view(func(st *state) {
		if m, ok := st.Members[nodeID]; ok {
			cp := *m
			member = &cp
		}
	})
	if member == nil || member.Tier != cluster.TierTrusted || !hasRole(member.Roles, cluster.RoleControl) {
		return nil, errors.New("control: only owner-trusted nodes with the control role can become control nodes")
	}
	id, err := randID("c-")
	if err != nil {
		return nil, err
	}
	certDER, err := s.ca.Issue(pki.KindControl, id, ed25519.PublicKey(req.PublicKey), nodeCertLifetime,
		hostOf(req.APIAddr), hostOf(req.RaftAddr), "localhost", "127.0.0.1")
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(s.ca.Key)
	if err != nil {
		return nil, err
	}
	info := &ControlInfo{ID: id, APIAddr: req.APIAddr, RaftAddr: req.RaftAddr}
	if err := s.apply(command{Op: opPutControl, Control: info}); err != nil {
		return nil, err
	}
	return &cluster.ControlEnrollResponse{
		ID:       id,
		CertPEM:  pki.CertPEM(certDER),
		CAPEM:    pki.CertPEM(s.ca.Cert.Raw),
		CAKeyDER: keyDER,
		APIAddr:  req.APIAddr,
		RaftAddr: req.RaftAddr,
		Peers:    s.controlAddrs(),
	}, nil
}

// ActivateControl adds an enrolled control node to the Raft group as a voter.
func (s *Server) ActivateControl(id string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	var info *ControlInfo
	s.fsm.view(func(st *state) {
		if c, ok := st.Controls[id]; ok {
			cp := *c
			info = &cp
		}
	})
	if info == nil {
		return fmt.Errorf("control: %s is not enrolled", id)
	}
	err := s.raft.AddVoter(raft.ServerID(id), raft.ServerAddress(info.RaftAddr), 0, applyTimeout).Error()
	if errors.Is(err, raft.ErrNotLeader) {
		return ErrNotLeader
	}
	return err
}

// RemoveControl takes a control node out of the Raft group and the registry.
func (s *Server) RemoveControl(id string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	if id == s.info.ID {
		return errors.New("control: transfer leadership before removing the leader")
	}
	if err := s.raft.RemoveServer(raft.ServerID(id), 0, applyTimeout).Error(); err != nil {
		return err
	}
	return s.apply(command{Op: opDelControl, Control: &ControlInfo{ID: id}})
}

// WriteEnrollment saves what a new control node received from EnrollControl,
// plus the private key it generated, into dir.
func WriteEnrollment(dir string, resp *cluster.ControlEnrollResponse, key ed25519.PrivateKey) error {
	if _, err := os.Stat(filepath.Join(dir, controlInfoFile)); err == nil {
		return fmt.Errorf("control: %s already holds a control node", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	caKey, err := x509.ParsePKCS8PrivateKey(resp.CAKeyDER)
	if err != nil {
		return err
	}
	edKey, ok := caKey.(ed25519.PrivateKey)
	if !ok {
		return errors.New("control: CA key is not Ed25519")
	}
	caCert, err := pki.ParseCertPEM(resp.CAPEM)
	if err != nil {
		return err
	}
	ca := &pki.CA{Cert: caCert, Key: edKey}
	if !edKey.Public().(ed25519.PublicKey).Equal(caCert.PublicKey) {
		return errors.New("control: CA key does not match CA certificate")
	}
	cert, err := pki.ParseCertPEM(resp.CertPEM)
	if err != nil {
		return err
	}
	if _, err := ca.Verify(cert.Raw); err != nil {
		return err
	}
	if err := ca.Save(dir); err != nil {
		return err
	}
	if err := pki.WriteCertPEM(filepath.Join(dir, controlCertFile), cert.Raw); err != nil {
		return err
	}
	if err := pki.WriteKeyPEM(filepath.Join(dir, controlKeyFile), key); err != nil {
		return err
	}
	info := localInfo{
		ControlInfo: ControlInfo{ID: resp.ID, APIAddr: resp.APIAddr, RaftAddr: resp.RaftAddr},
		Peers:       resp.Peers,
	}
	return writeJSON0600(filepath.Join(dir, controlInfoFile), info)
}

// Peers returns the control API addresses this node was told about at
// enrollment, for asking the leader to activate it.
func (s *Server) Peers() []string { return append([]string(nil), s.info.Peers...) }

// ClientCertificate is this control node's certificate, for calling other
// control nodes (activation).
func (s *Server) ClientCertificate() tls.Certificate { return s.tlsCert }

// --- HTTP handlers ---

// leaderOnly redirects writes to the leader's API with a 307, which clients
// follow with the same method and body.
func (s *Server) leaderOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.IsLeader() {
			next(w, r)
			return
		}
		_, leaderID := s.raft.LeaderWithID()
		var api string
		s.fsm.view(func(st *state) {
			if c, ok := st.Controls[string(leaderID)]; ok {
				api = c.APIAddr
			}
		})
		if api == "" || api == s.info.APIAddr {
			httpError(w, http.StatusServiceUnavailable, "no control-plane leader right now; retry")
			return
		}
		http.Redirect(w, r, "https://"+api+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req cluster.JoinRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.Join(req)
	switch {
	case errors.Is(err, ErrUnauthorized):
		httpError(w, http.StatusUnauthorized, "join token rejected")
	case errors.Is(err, ErrNotLeader):
		httpError(w, http.StatusServiceUnavailable, "leader changed; retry")
	case err != nil:
		httpError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSON(w, resp)
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var req cluster.TokenRequest
	if !decode(w, r, &req) {
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

func (s *Server) handleControls(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Controls())
}

func (s *Server) handleControlEnroll(w http.ResponseWriter, r *http.Request) {
	var req cluster.ControlEnrollRequest
	if !decode(w, r, &req) {
		return
	}
	nodeID := r.TLS.VerifiedChains[0][0].Subject.CommonName
	resp, err := s.EnrollControl(nodeID, req)
	if err != nil {
		httpError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleControlActivate(w http.ResponseWriter, r *http.Request) {
	// A control node may only activate itself: its certificate's CN is its ID.
	id := r.TLS.VerifiedChains[0][0].Subject.CommonName
	if err := s.ActivateControl(id); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]string{"id": id})
}

func (s *Server) handleControlRemove(w http.ResponseWriter, r *http.Request) {
	if err := s.RemoveControl(r.PathValue("id")); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]string{"removed": r.PathValue("id")})
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

// --- helpers ---

func writeControlCert(dir string, ca *pki.CA, id, apiAddr, raftAddr string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := ca.Issue(pki.KindControl, id, pub, nodeCertLifetime, hostOf(apiAddr), hostOf(raftAddr), "localhost", "127.0.0.1")
	if err != nil {
		return err
	}
	if err := pki.WriteCertPEM(filepath.Join(dir, controlCertFile), der); err != nil {
		return err
	}
	return pki.WriteKeyPEM(filepath.Join(dir, controlKeyFile), priv)
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return h
}

func hasRole(roles []cluster.Role, want cluster.Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func randID(prefix string) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func writeJSON0600(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, maxBodyBytes)
}

func decodeLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSONStatus(w, code, map[string]string{"error": msg})
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
