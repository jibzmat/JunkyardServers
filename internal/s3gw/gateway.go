// Package s3gw is the S3-compatible gateway. It authenticates requests with
// SigV4, keeps metadata in the control plane, and stores object data as
// encrypted, erasure-coded shards on storage nodes.
//
// Gateways see plaintext and unwrapped data keys, so they run only on
// owner-trusted PCs.
package s3gw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// Meta is the control plane's S3 metadata API; *control.Client implements it.
type Meta interface {
	AccessKey(ctx context.Context, id string) (*s3meta.AccessKey, error)
	WrapKey(ctx context.Context, tenant string, key []byte) ([]byte, error)
	UnwrapKey(ctx context.Context, tenant string, wrapped []byte) ([]byte, error)

	ListBuckets(ctx context.Context, tenant string) ([]s3meta.Bucket, error)
	Bucket(ctx context.Context, tenant, name string) (*s3meta.Bucket, error)
	CreateBucket(ctx context.Context, tenant, name string) error
	DeleteBucket(ctx context.Context, tenant, name string) error

	PutObject(ctx context.Context, tenant string, obj s3meta.Object) (*s3meta.Object, error)
	Object(ctx context.Context, tenant, bucket, key string) (*s3meta.Object, error)
	DeleteObject(ctx context.Context, tenant, bucket, key string) (*s3meta.Object, error)
	ListObjects(ctx context.Context, req s3meta.ListRequest) (*s3meta.ListResponse, error)

	CreateUpload(ctx context.Context, tenant string, u s3meta.Upload) error
	PutPart(ctx context.Context, u s3meta.UploadRequest, p s3meta.Part) (*s3meta.Part, error)
	CompleteUpload(ctx context.Context, u s3meta.UploadRequest, parts []s3meta.CompletedPart) (*s3meta.CompleteUploadResponse, error)
	AbortUpload(ctx context.Context, u s3meta.UploadRequest) (*s3meta.Upload, error)
	Upload(ctx context.Context, u s3meta.UploadRequest) (*s3meta.Upload, error)
	ListUploads(ctx context.Context, tenant, bucket string) ([]s3meta.Upload, error)
}

// MaxObjectSize is the largest single PUT, as in S3.
const MaxObjectSize = 5 << 30

// credTTL is how long a looked-up access key is cached.
const credTTL = time.Minute

// Gateway serves the S3 API.
type Gateway struct {
	Meta Meta
	// EC2 serves the EC2 API on the same port when set.
	EC2   EC2Meta
	Store *storage.Store
	// Region is reported to clients; any region in a signature is accepted.
	Region string
	// Domain enables virtual-hosted-style requests (bucket.Domain).
	Domain string
	Logger *log.Logger
	Now    func() time.Time

	mu    sync.Mutex
	creds map[string]cred
	bg    sync.WaitGroup
}

type cred struct {
	secret, tenant string
	expires        time.Time
}

// Wait blocks until background shard deletions finish.
func (g *Gateway) Wait() { g.bg.Wait() }

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gateway) region() string {
	if g.Region == "" {
		return "us-east-1"
	}
	return g.Region
}

func (g *Gateway) logf(format string, args ...any) {
	if g.Logger != nil {
		g.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (g *Gateway) lookup(ctx context.Context, id string) (string, string, error) {
	g.mu.Lock()
	c, ok := g.creds[id]
	g.mu.Unlock()
	if ok && g.now().Before(c.expires) {
		return c.secret, c.tenant, nil
	}
	k, err := g.Meta.AccessKey(ctx, id)
	if err != nil {
		return "", "", err
	}
	g.mu.Lock()
	if g.creds == nil {
		g.creds = map[string]cred{}
	}
	g.creds[id] = cred{k.Secret, k.Tenant, g.now().Add(credTTL)}
	g.mu.Unlock()
	return k.Secret, k.Tenant, nil
}

// request is one S3 call in flight.
type request struct {
	w      http.ResponseWriter
	r      *http.Request
	ctx    context.Context
	auth   *Auth
	tenant string
	bucket string
	key    string
	id     string
	ec2    bool
}

// ServeHTTP authenticates and dispatches a request.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := newID(8)
	w.Header().Set("x-amz-request-id", id)
	w.Header().Set("Server", "JunkyardServers")
	req := &request{w: w, r: r, ctx: r.Context(), id: id, ec2: isEC2(r)}
	var vhost bool
	req.bucket, req.key, vhost = g.route(r)

	vb := ""
	if vhost {
		vb = req.bucket
	}
	auth, err := verify(r.Context(), r, g.lookup, g.now(), vb)
	if err != nil {
		g.fail(req, err)
		return
	}
	req.auth, req.tenant = auth, auth.Tenant
	if auth.Service == "ec2" {
		if err := g.serveEC2(req); err != nil {
			g.fail(req, err)
		}
		return
	}
	if err := g.dispatch(req); err != nil {
		g.fail(req, err)
	}
}

// route splits the request into bucket and key, path-style or
// virtual-hosted-style.
func (g *Gateway) route(r *http.Request) (bucket, key string, vhost bool) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if g.Domain != "" {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if b, ok := strings.CutSuffix(host, "."+g.Domain); ok && b != "" {
			return b, path, true
		}
	}
	bucket, key, _ = strings.Cut(path, "/")
	return bucket, key, false
}

// unsupported lists bucket and object subresources the gateway doesn't
// implement; requests naming them get NotImplemented, not a wrong answer.
var unsupported = []string{
	"acl", "policy", "cors", "lifecycle", "tagging", "website", "logging",
	"notification", "replication", "encryption", "object-lock", "retention",
	"legal-hold", "torrent", "restore", "select", "analytics", "metrics",
	"inventory", "intelligent-tiering", "accelerate", "requestPayment",
	"ownershipControls", "publicAccessBlock", "versions", "attributes",
}

func (g *Gateway) dispatch(q *request) error {
	query := q.r.URL.Query()
	for _, s := range unsupported {
		if query.Has(s) {
			return errf("NotImplemented", http.StatusNotImplemented, "%s is not supported", s)
		}
	}
	m := q.r.Method
	switch {
	case q.bucket == "":
		if m == http.MethodGet {
			return g.listBuckets(q)
		}
	case q.key == "":
		switch m {
		case http.MethodPut:
			if query.Has("versioning") {
				return errf("NotImplemented", http.StatusNotImplemented, "versioning is not supported")
			}
			return g.createBucket(q)
		case http.MethodDelete:
			return g.deleteBucket(q)
		case http.MethodHead:
			return g.headBucket(q)
		case http.MethodGet:
			switch {
			case query.Has("location"):
				return g.location(q)
			case query.Has("versioning"):
				return g.versioning(q)
			case query.Has("uploads"):
				return g.listUploads(q)
			case query.Get("list-type") == "2":
				return g.listObjectsV2(q)
			default:
				return g.listObjectsV1(q)
			}
		case http.MethodPost:
			if query.Has("delete") {
				return g.deleteObjects(q)
			}
		}
	default:
		upload := query.Get("uploadId")
		switch m {
		case http.MethodPut:
			if upload != "" {
				return g.uploadPart(q, upload)
			}
			if q.r.Header.Get("X-Amz-Copy-Source") != "" {
				return g.copyObject(q)
			}
			return g.putObject(q)
		case http.MethodGet, http.MethodHead:
			if upload != "" && m == http.MethodGet {
				return g.listParts(q, upload)
			}
			return g.getObject(q, m == http.MethodHead)
		case http.MethodDelete:
			if upload != "" {
				return g.abortUpload(q, upload)
			}
			return g.deleteObject(q)
		case http.MethodPost:
			if query.Has("uploads") {
				return g.createUpload(q)
			}
			if upload != "" {
				return g.completeUpload(q, upload)
			}
		}
	}
	return errf("MethodNotAllowed", http.StatusMethodNotAllowed, "%s is not allowed on this resource", m)
}

// --- shared data path ---

// store encrypts r into a new segment.
func (g *Gateway) store(ctx context.Context, tenant string, r io.Reader) (s3meta.Segment, error) {
	key, err := storage.NewObjectKey()
	if err != nil {
		return s3meta.Segment{}, err
	}
	id := newID(16)
	layout, etag, err := g.Store.Put(ctx, id, key, r)
	if err != nil {
		return s3meta.Segment{}, err
	}
	wrapped, err := g.Meta.WrapKey(ctx, tenant, key.Bytes())
	if err != nil {
		g.Store.Delete(context.WithoutCancel(ctx), layout)
		return s3meta.Segment{}, err
	}
	return s3meta.Segment{ID: id, Size: layout.Size(), ETag: etag, WrappedKey: wrapped, Layout: layout}, nil
}

// read writes length bytes of obj from offset to w (length < 0: to the end).
func (g *Gateway) read(ctx context.Context, tenant string, obj *s3meta.Object, offset, length int64, w io.Writer) error {
	if length < 0 {
		length = obj.Size - offset
	}
	var pos int64
	for _, seg := range obj.Segments() {
		start, end := pos, pos+seg.Size
		pos = end
		if length <= 0 {
			break
		}
		if end <= offset {
			continue
		}
		from := max(offset-start, 0)
		n := min(seg.Size-from, length)
		raw, err := g.Meta.UnwrapKey(ctx, tenant, seg.WrappedKey)
		if err != nil {
			return err
		}
		key, err := storage.ObjectKeyFromBytes(raw)
		if err != nil {
			return err
		}
		if err := g.Store.Get(ctx, seg.ID, key, seg.Layout, from, n, w); err != nil {
			return err
		}
		offset, length = end, length-n
	}
	return nil
}

// discard deletes segments' shards in the background.
func (g *Gateway) discard(segs ...s3meta.Segment) {
	if len(segs) == 0 {
		return
	}
	g.bg.Add(1)
	go func() {
		defer g.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		for _, s := range segs {
			g.Store.Delete(ctx, s.Layout)
		}
	}()
}

// --- errors ---

// Error is an S3 error response.
type Error struct {
	Code    string
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(code string, status int, format string, args ...any) *Error {
	return &Error{Code: code, Status: status, Message: fmt.Sprintf(format, args...)}
}

func errAccessDenied(msg string) *Error { return errf("AccessDenied", http.StatusForbidden, "%s", msg) }

var metaStatus = map[string]int{
	s3meta.CodeNoSuchBucket:     http.StatusNotFound,
	s3meta.CodeNoSuchKey:        http.StatusNotFound,
	s3meta.CodeNoSuchUpload:     http.StatusNotFound,
	s3meta.CodeBucketExists:     http.StatusConflict,
	s3meta.CodeBucketTaken:      http.StatusConflict,
	s3meta.CodeBucketNotEmpty:   http.StatusConflict,
	s3meta.CodeInvalidAccessKey: http.StatusForbidden,
	s3meta.CodeInvalidPart:      http.StatusBadRequest,
	s3meta.CodeInvalidPartOrder: http.StatusBadRequest,
	s3meta.CodeEntityTooSmall:   http.StatusBadRequest,
}

func (g *Gateway) fail(q *request, err error) {
	var e *Error
	var me *s3meta.Error
	switch {
	case errors.As(err, &e):
	case errors.As(err, &me):
		status, ok := metaStatus[me.Code]
		if !ok {
			status = http.StatusBadRequest
		}
		e = &Error{Code: me.Code, Status: status, Message: me.Msg}
	case errors.Is(err, storage.ErrNotEnoughNodes):
		g.logf("s3: %s %s: %v", q.r.Method, q.r.URL.Path, err)
		e = errf("ServiceUnavailable", http.StatusServiceUnavailable, "not enough storage nodes are reachable; try again")
	case errors.Is(err, context.Canceled):
		return
	default:
		g.logf("s3: %s %s: %v", q.r.Method, q.r.URL.Path, err)
		e = errf("InternalError", http.StatusInternalServerError, "internal error")
	}
	if q.ec2 {
		if e.Code == "AccessDenied" || e.Code == "SignatureDoesNotMatch" || e.Code == s3meta.CodeInvalidAccessKey {
			e = errf("AuthFailure", http.StatusUnauthorized, "%s", e.Message)
		} else if e.Status == http.StatusNotFound || e.Status == http.StatusConflict {
			e.Status = http.StatusBadRequest
		}
		g.ec2Fail(q, e)
		return
	}
	if q.r.Method == http.MethodHead {
		q.w.WriteHeader(e.Status)
		return
	}
	resource := q.r.URL.Path
	writeXML(q.w, e.Status, errorXML{Code: e.Code, Message: e.Message, Resource: resource, RequestID: q.id})
}

func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
