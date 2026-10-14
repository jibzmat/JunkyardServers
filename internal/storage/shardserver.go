package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/pki"
)

// ShardServer serves a ShardStore to other cluster nodes over mutual TLS.
// Any cluster certificate may read and write: shards are ciphertext named by
// their hash, so a node can neither read nor forge another tenant's data.
// Deleting is different, since a stranger deleting shards would destroy
// data, so only callers MayDelete approves can delete.
type ShardServer struct {
	Store *ShardStore
	Cert  tls.Certificate
	CA    *x509.Certificate
	// MayDelete decides whether the holder of a verified certificate may
	// delete shards. Nil means nobody may.
	MayDelete func(*x509.Certificate) bool
}

// Handler returns the shard API.
func (s *ShardServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/shards/{hash}", s.authed(s.put))
	mux.HandleFunc("GET /v1/shards/{hash}", s.authed(s.get))
	mux.HandleFunc("DELETE /v1/shards/{hash}", s.authed(s.del))
	mux.HandleFunc("GET /v1/shards", s.authed(s.list))
	return mux
}

// TLSConfig requires a client certificate from the cluster CA.
func (s *ShardServer) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.CA)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.Cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
}

// Serve serves on ln until it fails.
func (s *ShardServer) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), TLSConfig: s.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
	return srv.ServeTLS(ln, "", "")
}

func (s *ShardServer) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		switch pki.KindOf(r.TLS.VerifiedChains[0][0]) {
		case pki.KindNode, pki.KindControl:
			next(w, r)
		default:
			http.Error(w, "certificate not allowed", http.StatusForbidden)
		}
	}
}

func (s *ShardServer) put(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, MaxShardSize+1))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if len(data) > MaxShardSize {
		http.Error(w, "shard too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := s.Store.Put(r.PathValue("hash"), data); errors.Is(err, ErrFull) {
		http.Error(w, err.Error(), http.StatusInsufficientStorage)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *ShardServer) get(w http.ResponseWriter, r *http.Request) {
	data, err := s.Store.Get(r.PathValue("hash"))
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

// list streams "hash unix-seconds" lines, one per stored shard. Hashes of
// ciphertext reveal nothing, so any cluster certificate may list.
func (s *ShardServer) list(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	bw := bufio.NewWriter(w)
	err := s.Store.Walk(func(hash string, mod time.Time) error {
		_, err := fmt.Fprintf(bw, "%s %d\n", hash, mod.Unix())
		return err
	})
	if err == nil {
		bw.WriteString("end\n") // lets the client tell a full list from a cut one
	}
	bw.Flush()
}

func (s *ShardServer) del(w http.ResponseWriter, r *http.Request) {
	if s.MayDelete == nil || !s.MayDelete(r.TLS.VerifiedChains[0][0]) {
		http.Error(w, "not allowed to delete shards", http.StatusForbidden)
		return
	}
	if err := s.Store.Delete(r.PathValue("hash")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ShardClient talks to other nodes' shard servers.
type ShardClient struct {
	tls *tls.Config

	mu      sync.Mutex
	clients map[string]*http.Client // by certificate name
}

// NewShardClient presents cert and trusts only the cluster CA.
func NewShardClient(cert tls.Certificate, ca *x509.Certificate) *ShardClient {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &ShardClient{
		tls: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
		},
		clients: map[string]*http.Client{},
	}
}

// client returns an HTTP client that requires the server certificate to
// name n (its mesh IP), whatever address it is dialed on.
func (c *ShardClient) client(n Node) *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if hc, ok := c.clients[n.Name]; ok {
		return hc
	}
	cfg := c.tls.Clone()
	cfg.ServerName = n.Name
	hc := &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 8},
		Timeout:   60 * time.Second,
	}
	c.clients[n.Name] = hc
	return hc
}

func (c *ShardClient) do(ctx context.Context, n Node, method, hash string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+n.Addr+"/v1/shards/"+hash, rd)
	if err != nil {
		return nil, err
	}
	return c.client(n).Do(req)
}

// Put uploads a shard to node n.
func (c *ShardClient) Put(ctx context.Context, n Node, hash string, data []byte) error {
	resp, err := c.do(ctx, n, http.MethodPut, hash, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage: put shard on %s: HTTP %d", n.ID, resp.StatusCode)
	}
	return nil
}

// Get downloads a shard and checks its hash.
func (c *ShardClient) Get(ctx context.Context, n Node, hash string) ([]byte, error) {
	resp, err := c.do(ctx, n, http.MethodGet, hash, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage: get shard from %s: HTTP %d", n.ID, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxShardSize+1))
	if err != nil {
		return nil, err
	}
	if ShardHash(data) != hash {
		return nil, errHashMismatch
	}
	return data, nil
}

// List returns every shard node n holds, with its modification time.
func (c *ShardClient) List(ctx context.Context, n Node) (map[string]time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+n.Addr+"/v1/shards", nil)
	if err != nil {
		return nil, err
	}
	hc := *c.client(n)
	hc.Timeout = 10 * time.Minute // large stores take a while to walk
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage: list shards on %s: HTTP %d", n.ID, resp.StatusCode)
	}
	out := map[string]time.Time{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if line == "end" {
			return out, nil
		}
		hash, ts, ok := strings.Cut(line, " ")
		secs, err := strconv.ParseInt(ts, 10, 64)
		if !ok || err != nil || !ValidHash(hash) {
			return nil, fmt.Errorf("storage: bad shard list line from %s", n.ID)
		}
		out[hash] = time.Unix(secs, 0)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("storage: shard list from %s was cut short", n.ID)
}

// Delete removes a shard from node n.
func (c *ShardClient) Delete(ctx context.Context, n Node, hash string) error {
	resp, err := c.do(ctx, n, http.MethodDelete, hash, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage: delete shard on %s: HTTP %d", n.ID, resp.StatusCode)
	}
	return nil
}
