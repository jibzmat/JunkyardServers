package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// S3 metadata API. Gateways call it to authenticate requests, wrap and
// unwrap object data keys, and read and write bucket and object records.
// Tenant master keys never leave the control plane.

const (
	// maxMetaBodyBytes bounds S3 metadata requests: an object record lists
	// every shard of every chunk (about 1 KiB per 4 MiB chunk).
	maxMetaBodyBytes = 16 << 20
	defaultMaxKeys   = 1000
)

var (
	bucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	tenantNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
)

// CreateTenant adds a tenant with a fresh master key and returns its first
// access key.
func (s *Server) CreateTenant(name string) (*s3meta.TenantResponse, error) {
	if !tenantNameRE.MatchString(name) {
		return nil, fmt.Errorf("tenant name %q: use 1-63 lowercase letters, digits, - or _", name)
	}
	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		return nil, err
	}
	id, err := randString("JY", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 18)
	if err != nil {
		return nil, err
	}
	secret, err := randString("", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 40)
	if err != nil {
		return nil, err
	}
	err = s.apply(command{
		Op:        opPutTenant,
		Tenant:    &s3meta.Tenant{Name: name, MasterKey: mk, Created: s.now().UTC()},
		AccessKey: &s3meta.AccessKey{ID: id, Secret: secret, Tenant: name},
	})
	if err != nil {
		return nil, err
	}
	return &s3meta.TenantResponse{Tenant: name, AccessKeyID: id, SecretAccessKey: secret}, nil
}

// AccessKey looks up an S3 credential.
func (s *Server) AccessKey(id string) (*s3meta.AccessKey, error) {
	var out *s3meta.AccessKey
	s.fsm.view(func(st *state) {
		if k, ok := st.AccessKeys[id]; ok {
			c := *k
			out = &c
		}
	})
	if out == nil {
		return nil, s3meta.Errorf(s3meta.CodeInvalidAccessKey, "access key does not exist")
	}
	return out, nil
}

// WrapKey seals an object data key with the tenant's master key.
func (s *Server) WrapKey(tenant string, key []byte) ([]byte, error) {
	aead, err := s.tenantAEAD(tenant)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, key, wrapAD(tenant)), nil
}

// UnwrapKey opens a data key sealed by WrapKey.
func (s *Server) UnwrapKey(tenant string, wrapped []byte) ([]byte, error) {
	aead, err := s.tenantAEAD(tenant)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, errors.New("wrapped key too short")
	}
	ns := aead.NonceSize()
	key, err := aead.Open(nil, wrapped[:ns], wrapped[ns:], wrapAD(tenant))
	if err != nil {
		return nil, errors.New("wrapped key does not belong to this tenant")
	}
	return key, nil
}

func wrapAD(tenant string) []byte { return []byte("jy-wrap-v1:" + tenant) }

func (s *Server) tenantAEAD(tenant string) (cipher.AEAD, error) {
	var mk []byte
	s.fsm.view(func(st *state) {
		if t, ok := st.Tenants[tenant]; ok {
			mk = t.MasterKey
		}
	})
	if mk == nil {
		return nil, s3meta.Errorf(s3meta.CodeInvalidAccessKey, "unknown tenant")
	}
	block, err := aes.NewCipher(mk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ListBuckets lists a tenant's buckets by name.
func (s *Server) ListBuckets(tenant string) []s3meta.Bucket {
	var out []s3meta.Bucket
	s.fsm.view(func(st *state) {
		for _, b := range st.Buckets {
			if b.Tenant == tenant {
				out = append(out, *b)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Bucket returns one of a tenant's buckets.
func (s *Server) Bucket(tenant, name string) (*s3meta.Bucket, error) {
	var out *s3meta.Bucket
	s.fsm.view(func(st *state) {
		if b, ok := st.Buckets[name]; ok && b.Tenant == tenant {
			c := *b
			out = &c
		}
	})
	if out == nil {
		return nil, s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", name)
	}
	return out, nil
}

// CreateBucket creates a bucket. Names are global across tenants, as in S3.
func (s *Server) CreateBucket(tenant, name string) error {
	if !bucketNameRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid bucket name %q", name)
	}
	return s.apply(command{Op: opCreateBucket, Bucket: &s3meta.Bucket{Name: name, Tenant: tenant, Created: s.now().UTC()}})
}

// DeleteBucket deletes an empty bucket.
func (s *Server) DeleteBucket(tenant, name string) error {
	return s.apply(command{Op: opDeleteBucket, Owner: tenant, Name: name})
}

// PutObject records an object and returns the one it replaced, if any, so
// the gateway can delete that object's shards.
func (s *Server) PutObject(tenant string, obj s3meta.Object) (*s3meta.Object, error) {
	if obj.Key == "" || len(obj.Key) > 1024 {
		return nil, errors.New("object key must be 1-1024 bytes")
	}
	if obj.Modified.IsZero() {
		obj.Modified = s.now().UTC()
	}
	return s.objectOp(command{Op: opPutObject, Owner: tenant, Object: &obj})
}

// DeleteObject removes an object record and returns it (nil if it did not
// exist; S3 deletes are idempotent).
func (s *Server) DeleteObject(tenant, bucket, key string) (*s3meta.Object, error) {
	return s.objectOp(command{Op: opDeleteObject, Owner: tenant, Name: bucket, Key: key})
}

func (s *Server) objectOp(c command) (*s3meta.Object, error) {
	res, err := s.applyResult(c)
	if err != nil {
		return nil, err
	}
	old, _ := res.(*s3meta.Object)
	return old, nil
}

// Object returns an object record.
func (s *Server) Object(tenant, bucket, key string) (*s3meta.Object, error) {
	var out *s3meta.Object
	var err error
	s.fsm.view(func(st *state) {
		b, ok := st.Buckets[bucket]
		if !ok || b.Tenant != tenant {
			err = s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", bucket)
			return
		}
		if o, ok := st.Objects[bucket][key]; ok {
			c := *o
			out = &c
		}
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, s3meta.Errorf(s3meta.CodeNoSuchKey, "key %q does not exist", key)
	}
	return out, nil
}

// ListObjects is ListObjectsV2. Returned objects carry no layout or key.
func (s *Server) ListObjects(req s3meta.ListRequest) (*s3meta.ListResponse, error) {
	max := req.MaxKeys
	if max <= 0 || max > defaultMaxKeys {
		max = defaultMaxKeys
	}
	var keys []string
	var objs map[string]*s3meta.Object
	var err error
	s.fsm.view(func(st *state) {
		b, ok := st.Buckets[req.Bucket]
		if !ok || b.Tenant != req.Tenant {
			err = s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", req.Bucket)
			return
		}
		objs = map[string]*s3meta.Object{}
		for k, o := range st.Objects[req.Bucket] {
			if strings.HasPrefix(k, req.Prefix) && k > req.StartAfter {
				keys = append(keys, k)
				objs[k] = o
			}
		}
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)

	resp := &s3meta.ListResponse{Objects: []s3meta.Object{}}
	seen := map[string]bool{}
	last := ""
	for _, k := range keys {
		if req.Delimiter != "" {
			rest := k[len(req.Prefix):]
			if i := strings.Index(rest, req.Delimiter); i >= 0 {
				cp := req.Prefix + rest[:i+len(req.Delimiter)]
				// A continuation may resume right after a common prefix.
				if seen[cp] || cp <= req.StartAfter {
					continue
				}
				if len(resp.Objects)+len(resp.CommonPrefixes) == max {
					resp.Truncated = true
					break
				}
				seen[cp] = true
				resp.CommonPrefixes = append(resp.CommonPrefixes, cp)
				last = cp
				continue
			}
		}
		if len(resp.Objects)+len(resp.CommonPrefixes) == max {
			resp.Truncated = true
			break
		}
		o := *objs[k]
		o.WrappedKey, o.Layout = nil, storage.Layout{}
		resp.Objects = append(resp.Objects, o)
		last = k
	}
	if resp.Truncated {
		resp.Next = last
	}
	return resp, nil
}

// --- HTTP ---

func (s *Server) s3Routes(mux *http.ServeMux) {
	gw := func(h http.HandlerFunc) http.HandlerFunc { return s.requireGateway(s.leaderOnly(h)) }
	mux.HandleFunc("POST /v1/tenants", s.requireKind(s.leaderOnly(s.handleTenantCreate), pki.KindAdmin))
	mux.HandleFunc("GET /v1/s3/access-keys/{id}", gw(s.handleAccessKey))
	mux.HandleFunc("POST /v1/s3/wrap", gw(s.handleWrap))
	mux.HandleFunc("POST /v1/s3/unwrap", gw(s.handleUnwrap))
	mux.HandleFunc("POST /v1/s3/buckets/list", gw(s.handleBucketList))
	mux.HandleFunc("POST /v1/s3/buckets/get", gw(s.handleBucketGet))
	mux.HandleFunc("POST /v1/s3/buckets/create", gw(s.handleBucketCreate))
	mux.HandleFunc("POST /v1/s3/buckets/delete", gw(s.handleBucketDelete))
	mux.HandleFunc("POST /v1/s3/objects/put", gw(s.handleObjectPut))
	mux.HandleFunc("POST /v1/s3/objects/get", gw(s.handleObjectGet))
	mux.HandleFunc("POST /v1/s3/objects/delete", gw(s.handleObjectDelete))
	mux.HandleFunc("POST /v1/s3/objects/list", gw(s.handleObjectList))
}

// requireGateway admits control nodes and owner-trusted nodes holding the
// gateway role. Gateways see every tenant's data keys.
func (s *Server) requireGateway(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			httpError(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		switch pki.KindOf(leaf) {
		case pki.KindControl:
			next(w, r)
			return
		case pki.KindNode:
			ok := false
			s.fsm.view(func(st *state) {
				m, found := st.Members[leaf.Subject.CommonName]
				ok = found && m.Tier == cluster.TierTrusted && hasRole(m.Roles, cluster.RoleGateway)
			})
			if ok {
				next(w, r)
				return
			}
		}
		httpError(w, http.StatusForbidden, "only gateways may use the S3 metadata API")
	}
}

func (s *Server) handleTenantCreate(w http.ResponseWriter, r *http.Request) {
	var req s3meta.TenantRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.CreateTenant(req.Name)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleAccessKey(w http.ResponseWriter, r *http.Request) {
	k, err := s.AccessKey(r.PathValue("id"))
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, k)
}

func (s *Server) handleWrap(w http.ResponseWriter, r *http.Request) {
	var req s3meta.KeyRequest
	if !decode(w, r, &req) {
		return
	}
	k, err := s.WrapKey(req.Tenant, req.Key)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.KeyResponse{Key: k})
}

func (s *Server) handleUnwrap(w http.ResponseWriter, r *http.Request) {
	var req s3meta.KeyRequest
	if !decode(w, r, &req) {
		return
	}
	k, err := s.UnwrapKey(req.Tenant, req.Key)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.KeyResponse{Key: k})
}

func (s *Server) handleBucketList(w http.ResponseWriter, r *http.Request) {
	var req s3meta.BucketRequest
	if !decode(w, r, &req) {
		return
	}
	out := s.ListBuckets(req.Tenant)
	if out == nil {
		out = []s3meta.Bucket{}
	}
	writeJSON(w, out)
}

func (s *Server) handleBucketGet(w http.ResponseWriter, r *http.Request) {
	var req s3meta.BucketRequest
	if !decode(w, r, &req) {
		return
	}
	b, err := s.Bucket(req.Tenant, req.Bucket)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, b)
}

func (s *Server) handleBucketCreate(w http.ResponseWriter, r *http.Request) {
	var req s3meta.BucketRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.CreateBucket(req.Tenant, req.Bucket); err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleBucketDelete(w http.ResponseWriter, r *http.Request) {
	var req s3meta.BucketRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.DeleteBucket(req.Tenant, req.Bucket); err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleObjectPut(w http.ResponseWriter, r *http.Request) {
	var req s3meta.PutObjectRequest
	if !decodeLimit(w, r, &req, maxMetaBodyBytes) {
		return
	}
	old, err := s.PutObject(req.Tenant, req.Object)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.ObjectResponse{Object: old})
}

func (s *Server) handleObjectGet(w http.ResponseWriter, r *http.Request) {
	var req s3meta.ObjectRequest
	if !decode(w, r, &req) {
		return
	}
	o, err := s.Object(req.Tenant, req.Bucket, req.Key)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.ObjectResponse{Object: o})
}

func (s *Server) handleObjectDelete(w http.ResponseWriter, r *http.Request) {
	var req s3meta.ObjectRequest
	if !decode(w, r, &req) {
		return
	}
	old, err := s.DeleteObject(req.Tenant, req.Bucket, req.Key)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.ObjectResponse{Object: old})
}

func (s *Server) handleObjectList(w http.ResponseWriter, r *http.Request) {
	var req s3meta.ListRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.ListObjects(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, resp)
}

// metaError writes an error, keeping the S3 code of metadata errors.
func metaError(w http.ResponseWriter, err error) {
	var me *s3meta.Error
	if !errors.As(err, &me) {
		if errors.Is(err, ErrNotLeader) {
			httpError(w, http.StatusServiceUnavailable, "leader changed; retry")
			return
		}
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	code := http.StatusConflict
	switch me.Code {
	case s3meta.CodeNoSuchBucket, s3meta.CodeNoSuchKey:
		code = http.StatusNotFound
	case s3meta.CodeInvalidAccessKey:
		code = http.StatusForbidden
	}
	writeJSONStatus(w, code, me)
}

func randString(prefix, alphabet string, n int) (string, error) {
	b := []byte(prefix)
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b = append(b, alphabet[v.Int64()])
	}
	return string(b), nil
}
