package control

import (
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	kek, epoch := s.currentKEK(), s.currentEpoch()
	if kek == nil {
		return nil, ErrKeysLocked
	}
	sealed, err := sealValue(kek, mk, tenantAD(name))
	if err != nil {
		return nil, err
	}
	err = s.apply(command{
		Op:        opPutTenant,
		Tenant:    &s3meta.Tenant{Name: name, SealedKey: sealed, Created: s.now().UTC()},
		AccessKey: &s3meta.AccessKey{ID: id, Secret: secret, Tenant: name},
		KEKEpoch:  epoch,
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
	mk, err := s.tenantKey(tenant)
	if err != nil {
		return nil, err
	}
	return gcm(mk)
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
	if !s3meta.ValidBucketName(name) {
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
		if o, ok := st.Objects[bucket].get(key); ok {
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
	resp := &s3meta.ListResponse{Objects: []s3meta.Object{}}
	var err error
	s.fsm.view(func(st *state) {
		b, ok := st.Buckets[req.Bucket]
		if !ok || b.Tenant != req.Tenant {
			err = s3meta.Errorf(s3meta.CodeNoSuchBucket, "bucket %q does not exist", req.Bucket)
			return
		}
		listPage(st.Objects[req.Bucket], req, max, resp)
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// listPage fills resp with up to max keys and common prefixes after
// req.StartAfter. It walks the bucket's key index, jumping over each common
// prefix's keys rather than visiting them.
func listPage(objs *objectSet, req s3meta.ListRequest, max int, resp *s3meta.ListResponse) {
	from := req.Prefix
	if req.StartAfter >= from {
		from = req.StartAfter + "\x00"
	}
	last := ""
	for {
		var skipTo string
		objs.ascend(from, func(k string, o *s3meta.Object) bool {
			if !strings.HasPrefix(k, req.Prefix) {
				return false // past the prefix
			}
			if req.Delimiter != "" {
				rest := k[len(req.Prefix):]
				if i := strings.Index(rest, req.Delimiter); i >= 0 {
					cp := req.Prefix + rest[:i+len(req.Delimiter)]
					// A continuation may resume inside a common prefix
					// already returned.
					if cp > req.StartAfter {
						if len(resp.Objects)+len(resp.CommonPrefixes) == max {
							resp.Truncated = true
							return false
						}
						resp.CommonPrefixes = append(resp.CommonPrefixes, cp)
						last = cp
					}
					// Every key after an all-0xff prefix shares it.
					skipTo = prefixEnd(cp)
					return false
				}
			}
			if len(resp.Objects)+len(resp.CommonPrefixes) == max {
				resp.Truncated = true
				return false
			}
			c := *o
			c.WrappedKey, c.Layout, c.Parts = nil, storage.Layout{}, nil
			resp.Objects = append(resp.Objects, c)
			last = k
			return true
		})
		if skipTo == "" || resp.Truncated {
			break
		}
		from = skipTo
	}
	if resp.Truncated {
		resp.Next = last
	}
}

// CreateUpload starts a multipart upload.
func (s *Server) CreateUpload(tenant string, u s3meta.Upload) error {
	if u.ID == "" || u.Key == "" || len(u.Key) > 1024 {
		return errors.New("upload needs an ID and a 1-1024 byte key")
	}
	u.Created = s.now().UTC()
	_, err := s.applyResult(command{Op: opCreateUpload, Owner: tenant, Upload: &u})
	return err
}

// PutPart records a part and returns the one it replaced, if any.
func (s *Server) PutPart(u s3meta.UploadRequest, p s3meta.Part) (*s3meta.Part, error) {
	if p.Number < 1 || p.Number > s3meta.MaxParts {
		return nil, fmt.Errorf("part number must be 1 to %d", s3meta.MaxParts)
	}
	p.Modified = s.now().UTC()
	res, err := s.applyResult(command{Op: opPutPart, Owner: u.Tenant, Name: u.Bucket, Key: u.Key, UploadID: u.UploadID, Part: &p})
	if err != nil {
		return nil, err
	}
	old, _ := res.(*s3meta.Part)
	return old, nil
}

// CompleteUpload assembles an object from uploaded parts.
func (s *Server) CompleteUpload(u s3meta.UploadRequest, parts []s3meta.CompletedPart) (*s3meta.CompleteUploadResponse, error) {
	res, err := s.applyResult(command{Op: opCompleteUpload, Owner: u.Tenant, Name: u.Bucket, Key: u.Key, UploadID: u.UploadID, Parts: parts, Now: s.now().UTC()})
	if err != nil {
		return nil, err
	}
	return res.(*s3meta.CompleteUploadResponse), nil
}

// AbortUpload drops an upload and returns it, so its parts can be deleted.
func (s *Server) AbortUpload(u s3meta.UploadRequest) (*s3meta.Upload, error) {
	res, err := s.applyResult(command{Op: opAbortUpload, Owner: u.Tenant, Name: u.Bucket, Key: u.Key, UploadID: u.UploadID})
	if err != nil {
		return nil, err
	}
	return res.(*s3meta.Upload), nil
}

// Upload returns an upload in progress.
func (s *Server) Upload(req s3meta.UploadRequest) (*s3meta.Upload, error) {
	var out *s3meta.Upload
	s.fsm.view(func(st *state) {
		if u, ok := st.Uploads[req.UploadID]; ok && u.Tenant == req.Tenant && u.Bucket == req.Bucket && u.Key == req.Key {
			c := *u
			c.Parts = map[int]*s3meta.Part{}
			for n, p := range u.Parts {
				c.Parts[n] = p
			}
			out = &c
		}
	})
	if out == nil {
		return nil, s3meta.Errorf(s3meta.CodeNoSuchUpload, "upload does not exist")
	}
	return out, nil
}

// ListUploads lists a bucket's uploads in progress, without their parts,
// ordered by key then start time.
func (s *Server) ListUploads(tenant, bucket string) ([]s3meta.Upload, error) {
	if _, err := s.Bucket(tenant, bucket); err != nil {
		return nil, err
	}
	out := []s3meta.Upload{}
	s.fsm.view(func(st *state) {
		for _, u := range st.Uploads {
			if u.Tenant == tenant && u.Bucket == bucket {
				c := *u
				c.Parts = nil
				out = append(out, c)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Created.Before(out[j].Created)
	})
	return out, nil
}

// AllObjects returns every object record, for repair. Records are never
// modified in place, so the copies may share their layouts.
func (s *Server) AllObjects() []s3meta.Object {
	var out []s3meta.Object
	s.fsm.view(func(st *state) {
		for _, objs := range st.Objects {
			objs.each(func(o *s3meta.Object) { out = append(out, *o) })
		}
	})
	return out
}

// AllUploads returns the segments of every part of every unfinished
// multipart upload, so garbage collection keeps their shards.
func (s *Server) AllUploads() []s3meta.Segment {
	var out []s3meta.Segment
	s.fsm.view(func(st *state) {
		for _, u := range st.Uploads {
			for _, p := range u.Parts {
				out = append(out, p.Segment)
			}
		}
	})
	return out
}

// MoveShards records shards that repair rebuilt on other nodes. It fails
// if the object or segment changed since it was read.
func (s *Server) MoveShards(bucket, key, segmentID string, moves []s3meta.ShardMove) error {
	return s.apply(command{Op: opMoveShards, Name: bucket, Key: key, SegmentID: segmentID, Moves: moves})
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
	mux.HandleFunc("POST /v1/s3/uploads/create", gw(s.handleUploadCreate))
	mux.HandleFunc("POST /v1/s3/uploads/part", gw(s.handleUploadPart))
	mux.HandleFunc("POST /v1/s3/uploads/complete", gw(s.handleUploadComplete))
	mux.HandleFunc("POST /v1/s3/uploads/abort", gw(s.handleUploadAbort))
	mux.HandleFunc("POST /v1/s3/uploads/get", gw(s.handleUploadGet))
	mux.HandleFunc("POST /v1/s3/uploads/list", gw(s.handleUploadList))
}

func (s *Server) handleUploadCreate(w http.ResponseWriter, r *http.Request) {
	var req s3meta.CreateUploadRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.CreateUpload(req.Tenant, req.Upload); err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleUploadPart(w http.ResponseWriter, r *http.Request) {
	var req s3meta.PutPartRequest
	if !decodeLimit(w, r, &req, maxMetaBodyBytes) {
		return
	}
	old, err := s.PutPart(req.UploadRequest, req.Part)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.PartResponse{Part: old})
}

func (s *Server) handleUploadComplete(w http.ResponseWriter, r *http.Request) {
	var req s3meta.CompleteUploadRequest
	if !decodeLimit(w, r, &req, maxMetaBodyBytes) {
		return
	}
	resp, err := s.CompleteUpload(req.UploadRequest, req.Parts)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleUploadAbort(w http.ResponseWriter, r *http.Request) {
	var req s3meta.UploadRequest
	if !decode(w, r, &req) {
		return
	}
	u, err := s.AbortUpload(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.UploadResponse{Upload: u})
}

func (s *Server) handleUploadGet(w http.ResponseWriter, r *http.Request) {
	var req s3meta.UploadRequest
	if !decode(w, r, &req) {
		return
	}
	u, err := s.Upload(req)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, s3meta.UploadResponse{Upload: u})
}

func (s *Server) handleUploadList(w http.ResponseWriter, r *http.Request) {
	var req s3meta.BucketRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := s.ListUploads(req.Tenant, req.Bucket)
	if err != nil {
		metaError(w, err)
		return
	}
	writeJSON(w, out)
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
		if errors.Is(err, ErrNotLeader) || errors.Is(err, ErrKeysLocked) || errors.Is(err, errStaleKEK) {
			httpError(w, http.StatusServiceUnavailable, err.Error())
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
