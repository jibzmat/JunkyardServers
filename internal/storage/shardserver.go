package storage

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	if err := s.Store.Put(r.PathValue("hash"), data); err != nil {
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
	http *http.Client
}

// NewShardClient presents cert and trusts only the cluster CA.
func NewShardClient(cert tls.Certificate, ca *x509.Certificate) *ShardClient {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 8,
	}
	return &ShardClient{http: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// Put uploads a shard to the node at addr.
func (c *ShardClient) Put(ctx context.Context, addr, hash string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://"+addr+"/v1/shards/"+hash, bytes.NewReader(data))
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage: put shard on %s: HTTP %d", addr, resp.StatusCode)
	}
	return nil
}

// Get downloads a shard and checks its hash.
func (c *ShardClient) Get(ctx context.Context, addr, hash string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/v1/shards/"+hash, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage: get shard from %s: HTTP %d", addr, resp.StatusCode)
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

// Delete removes a shard from the node at addr.
func (c *ShardClient) Delete(ctx context.Context, addr, hash string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "https://"+addr+"/v1/shards/"+hash, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage: delete shard on %s: HTTP %d", addr, resp.StatusCode)
	}
	return nil
}
