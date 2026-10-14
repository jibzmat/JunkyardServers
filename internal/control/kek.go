package control

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/shamir"
)

// Key protection. Tenant master keys are stored in the Raft state sealed by
// a cluster key-encryption key (KEK). The KEK itself is never stored: it is
// Shamir-split across the control nodes, each share sealed to that node's
// own X25519 key (share.key, never replicated). A control node rebuilds the
// KEK in memory from a majority of shares, asking its peers for theirs over
// mutual TLS. So neither a Raft snapshot nor one node's disk holds usable
// tenant keys, except in a one-control-node cluster, where the single share
// is the whole key.
//
// The leader rotates the KEK whenever the set of control nodes changes:
// shares held by a removed node then open nothing.

const shareKeyFile = "share.key"

// kekState is the replicated part of key protection.
type kekState struct {
	Epoch     int               `json:"epoch"`
	Threshold int               `json:"threshold"`
	Shares    map[string][]byte `json:"shares"` // control ID -> share sealed to its share key
	Check     []byte            `json:"check"`  // seals a constant, to recognise the right KEK
}

// ErrKeysLocked means this control node hasn't rebuilt the KEK yet.
var ErrKeysLocked = errors.New("control: tenant keys are locked until enough control nodes are reachable")

var errStaleKEK = errors.New("control: key state changed; retry")

// loadShareKey reads or creates this node's X25519 share key.
func loadShareKey(dir string) (pub, priv *[32]byte, err error) {
	path := filepath.Join(dir, shareKeyFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		pub, priv, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(path, priv[:], 0o600); err != nil {
			return nil, nil, err
		}
		return pub, priv, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(b) != 32 {
		return nil, nil, fmt.Errorf("control: %s is not a 32-byte key", path)
	}
	priv = new([32]byte)
	copy(priv[:], b)
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	pub = new([32]byte)
	copy(pub[:], p)
	return pub, priv, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealValue(key, plain, ad []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, ad), nil
}

func openSealed(key, sealed, ad []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("sealed value too short")
	}
	ns := aead.NonceSize()
	return aead.Open(nil, sealed[:ns], sealed[ns:], ad)
}

func checkAD(epoch int) []byte           { return []byte("jy-kek-check-v1:" + strconv.Itoa(epoch)) }
func tenantAD(name string) []byte        { return []byte("jy-tenant-v1:" + name) }
func (s *Server) currentKEK() []byte     { s.kekMu.Lock(); defer s.kekMu.Unlock(); return s.kek }
func (s *Server) currentEpoch() int      { s.kekMu.Lock(); defer s.kekMu.Unlock(); return s.kekEpoch }
func (s *Server) setKEK(k []byte, e int) { s.kekMu.Lock(); s.kek, s.kekEpoch = k, e; s.kekMu.Unlock() }

// KeysUnlocked reports whether this node holds the current KEK.
func (s *Server) KeysUnlocked() bool {
	var epoch int
	s.fsm.view(func(st *state) {
		if st.KEK != nil {
			epoch = st.KEK.Epoch
		}
	})
	return epoch != 0 && s.currentKEK() != nil && s.currentEpoch() == epoch
}

// tenantKey returns a tenant's master key.
func (s *Server) tenantKey(tenant string) ([]byte, error) {
	var t *s3meta.Tenant
	var epoch int
	s.fsm.view(func(st *state) {
		if x, ok := st.Tenants[tenant]; ok {
			cp := *x
			t = &cp
		}
		if st.KEK != nil {
			epoch = st.KEK.Epoch
		}
	})
	if t == nil {
		return nil, s3meta.Errorf(s3meta.CodeInvalidAccessKey, "unknown tenant")
	}
	if t.SealedKey == nil {
		return t.MasterKey, nil // written before key protection; sealed on next rotation
	}
	kek := s.currentKEK()
	if kek == nil || s.currentEpoch() != epoch {
		return nil, ErrKeysLocked
	}
	mk, err := openSealed(kek, t.SealedKey, tenantAD(tenant))
	if err != nil {
		return nil, ErrKeysLocked
	}
	return mk, nil
}

// keyLoop registers this node's share key, rebuilds the KEK, and on the
// leader keeps the shares matching the set of control nodes.
func (s *Server) keyLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		if err := s.keyStep(); err != nil && !errors.Is(err, ErrNotLeader) {
			s.logger.Printf("keys: %v", err)
		}
		select {
		case <-s.done:
			return
		case <-t.C:
		}
	}
}

func (s *Server) keyStep() error {
	if s.raft.State() == raft.Shutdown {
		return nil
	}
	var mine []byte
	var st *kekState
	var registered bool
	s.fsm.view(func(x *state) {
		if c, ok := x.Controls[s.info.ID]; ok {
			registered = true
			mine = c.ShareKey
		}
		if x.KEK != nil {
			cp := *x.KEK
			st = &cp
		}
	})
	if !registered {
		return nil // not enrolled in the replicated state yet
	}
	if string(mine) != string(s.sharePub[:]) {
		return s.registerShareKey()
	}
	if s.IsLeader() {
		return s.leaderKeys(st)
	}
	if st != nil && (s.currentKEK() == nil || s.currentEpoch() != st.Epoch) {
		return s.unlock(st)
	}
	return nil
}

func (s *Server) registerShareKey() error {
	if s.IsLeader() {
		return s.apply(command{Op: opSetShareKey, Control: &ControlInfo{ID: s.info.ID, ShareKey: s.sharePub[:]}})
	}
	c := NewClient(s.otherControlAddrs(), s.tlsCert, s.ca.Cert)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out struct{}
	return c.call(ctx, http.MethodPost, "/v1/controls/share-key", shareKeyRequest{ShareKey: s.sharePub[:]}, &out)
}

// leaderKeys unlocks or creates the KEK, then rotates it if the voters
// changed or a tenant key is still unsealed.
func (s *Server) leaderKeys(st *kekState) error {
	if st != nil && (s.currentKEK() == nil || s.currentEpoch() != st.Epoch) {
		if err := s.unlock(st); err != nil {
			return err
		}
	}
	holders, err := s.shareHolders()
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return nil
	}
	need := st == nil || st.Threshold != len(holders)/2+1 || len(st.Shares) != len(holders)
	if st != nil {
		for id := range holders {
			if _, ok := st.Shares[id]; !ok {
				need = true
			}
		}
	}
	s.fsm.view(func(x *state) {
		for _, t := range x.Tenants {
			if t.SealedKey == nil {
				need = true
			}
		}
	})
	if !need {
		return nil
	}
	return s.rotate(holders)
}

// shareHolders lists Raft voters that have registered a share key.
func (s *Server) shareHolders() (map[string][]byte, error) {
	f := s.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	s.fsm.view(func(x *state) {
		for _, srv := range f.Configuration().Servers {
			if srv.Suffrage != raft.Voter {
				continue
			}
			if c, ok := x.Controls[string(srv.ID)]; ok && len(c.ShareKey) == 32 {
				out[c.ID] = c.ShareKey
			}
		}
	})
	return out, nil
}

// rotate makes a new KEK, re-seals every tenant key under it and splits it
// among holders, in one Raft write.
func (s *Server) rotate(holders map[string][]byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.leaderBarrier(); err != nil {
		return err
	}
	var epoch int
	tenants := map[string][]byte{}
	var locked bool
	s.fsm.view(func(x *state) {
		if x.KEK != nil {
			epoch = x.KEK.Epoch
		}
		for name, t := range x.Tenants {
			if t.SealedKey == nil {
				tenants[name] = t.MasterKey
				continue
			}
			kek := s.currentKEK()
			if kek == nil || s.currentEpoch() != epoch {
				locked = true
				return
			}
			mk, err := openSealed(kek, t.SealedKey, tenantAD(name))
			if err != nil {
				locked = true
				return
			}
			tenants[name] = mk
		}
	})
	if locked {
		return ErrKeysLocked
	}

	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return err
	}
	ids := make([]string, 0, len(holders))
	for id := range holders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t := len(ids)/2 + 1
	parts, err := shamir.Split(kek, len(ids), t)
	if err != nil {
		return err
	}
	next := &kekState{Epoch: epoch + 1, Threshold: t, Shares: map[string][]byte{}}
	for i, id := range ids {
		var pub [32]byte
		copy(pub[:], holders[id])
		sealed, err := box.SealAnonymous(nil, parts[i], &pub, rand.Reader)
		if err != nil {
			return err
		}
		next.Shares[id] = sealed
	}
	if next.Check, err = sealValue(kek, []byte("ok"), checkAD(next.Epoch)); err != nil {
		return err
	}
	sealedTenants := map[string][]byte{}
	for name, mk := range tenants {
		if sealedTenants[name], err = sealValue(kek, mk, tenantAD(name)); err != nil {
			return err
		}
	}
	if err := s.apply(command{Op: opPutKEK, KEK: next, Sealed: sealedTenants}); err != nil {
		return err
	}
	s.setKEK(kek, next.Epoch)
	s.logger.Printf("keys: rotated the key-encryption key (epoch %d, %d of %d control nodes needed)", next.Epoch, t, len(ids))
	return nil
}

// ownShare opens this node's share of the given epoch.
func (s *Server) ownShare(st *kekState) ([]byte, error) {
	sealed, ok := st.Shares[s.info.ID]
	if !ok {
		return nil, errors.New("no share for this node")
	}
	share, ok := box.OpenAnonymous(nil, sealed, s.sharePub, s.sharePriv)
	if !ok {
		return nil, errors.New("cannot open this node's share")
	}
	return share, nil
}

// unlock gathers a threshold of shares and rebuilds the KEK.
func (s *Server) unlock(st *kekState) error {
	var shares [][]byte
	if mine, err := s.ownShare(st); err == nil {
		shares = append(shares, mine)
	}
	var addrs []string
	s.fsm.view(func(x *state) {
		for id := range st.Shares {
			if c, ok := x.Controls[id]; ok && id != s.info.ID {
				addrs = append(addrs, c.APIAddr)
			}
		}
	})
	for _, a := range addrs {
		if len(shares) >= st.Threshold {
			break
		}
		c := NewClient([]string{a}, s.tlsCert, s.ca.Cert)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var resp shareResponse
		err := c.call(ctx, http.MethodGet, "/v1/kek/share?epoch="+strconv.Itoa(st.Epoch), nil, &resp)
		cancel()
		if err == nil && resp.Epoch == st.Epoch {
			shares = append(shares, resp.Share)
		}
	}
	if len(shares) < st.Threshold {
		return fmt.Errorf("%w (%d of %d shares)", ErrKeysLocked, len(shares), st.Threshold)
	}
	kek, err := shamir.Combine(shares[:st.Threshold])
	if err != nil {
		return err
	}
	if _, err := openSealed(kek, st.Check, checkAD(st.Epoch)); err != nil {
		return errors.New("rebuilt key-encryption key does not match; a share is wrong")
	}
	s.setKEK(kek, st.Epoch)
	s.logger.Printf("keys: unlocked tenant keys (epoch %d)", st.Epoch)
	return nil
}

func (s *Server) otherControlAddrs() []string {
	var out []string
	s.fsm.view(func(x *state) {
		for id, c := range x.Controls {
			if id != s.info.ID {
				out = append(out, c.APIAddr)
			}
		}
	})
	return append(out, s.info.Peers...)
}

type shareKeyRequest struct {
	ShareKey []byte `json:"share_key"`
}

type shareResponse struct {
	Epoch int    `json:"epoch"`
	Share []byte `json:"share"`
}

// handleShare gives a peer control node this node's share of the KEK.
func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	epoch, _ := strconv.Atoi(r.URL.Query().Get("epoch"))
	var st *kekState
	s.fsm.view(func(x *state) {
		if x.KEK != nil {
			cp := *x.KEK
			st = &cp
		}
	})
	if st == nil || st.Epoch != epoch {
		httpError(w, http.StatusConflict, "this node is at a different key epoch")
		return
	}
	share, err := s.ownShare(st)
	if err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, shareResponse{Epoch: epoch, Share: share})
}

func (s *Server) handleShareKey(w http.ResponseWriter, r *http.Request) {
	var req shareKeyRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.ShareKey) != 32 {
		httpError(w, http.StatusBadRequest, "share key must be 32 bytes")
		return
	}
	id := r.TLS.VerifiedChains[0][0].Subject.CommonName
	if err := s.apply(command{Op: opSetShareKey, Control: &ControlInfo{ID: id, ShareKey: req.ShareKey}}); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) keyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/kek/share", s.requireKind(s.handleShare, pki.KindControl))
	mux.HandleFunc("POST /v1/controls/share-key", s.requireKind(s.leaderOnly(s.handleShareKey), pki.KindControl))
}
