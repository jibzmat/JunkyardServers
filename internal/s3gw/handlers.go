package s3gw

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

// --- buckets ---

func (g *Gateway) listBuckets(q *request) error {
	bs, err := g.Meta.ListBuckets(q.ctx, q.tenant)
	if err != nil {
		return err
	}
	out := listBucketsXML{Owner: owner{ID: q.tenant, DisplayName: q.tenant}}
	for _, b := range bs {
		out.Buckets = append(out.Buckets, bucketXML{Name: b.Name, CreationDate: iso(b.Created)})
	}
	writeXML(q.w, http.StatusOK, out)
	return nil
}

func (g *Gateway) createBucket(q *request) error {
	if !s3meta.ValidBucketName(q.bucket) {
		return errf("InvalidBucketName", http.StatusBadRequest, "the bucket name %q is not valid", q.bucket)
	}
	// The body may hold a CreateBucketConfiguration; regions don't apply.
	if err := g.Meta.CreateBucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	q.w.Header().Set("Location", "/"+q.bucket)
	q.w.WriteHeader(http.StatusOK)
	return nil
}

func (g *Gateway) deleteBucket(q *request) error {
	if err := g.Meta.DeleteBucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (g *Gateway) headBucket(q *request) error {
	if _, err := g.Meta.Bucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	q.w.Header().Set("x-amz-bucket-region", g.region())
	q.w.WriteHeader(http.StatusOK)
	return nil
}

func (g *Gateway) location(q *request) error {
	if _, err := g.Meta.Bucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	region := g.region()
	if region == "us-east-1" {
		region = "" // S3 reports the default region as empty
	}
	writeXML(q.w, http.StatusOK, locationXML{Region: region})
	return nil
}

func (g *Gateway) versioning(q *request) error {
	if _, err := g.Meta.Bucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	writeXML(q.w, http.StatusOK, versioningXML{})
	return nil
}

// --- listing ---

// listParams reads the parameters shared by both list versions.
func listParams(q *request) (s3meta.ListRequest, func(string) string, error) {
	query := q.r.URL.Query()
	req := s3meta.ListRequest{Tenant: q.tenant, Bucket: q.bucket, Prefix: query.Get("prefix"), Delimiter: query.Get("delimiter"), MaxKeys: 1000}
	if s := query.Get("max-keys"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return req, nil, errf("InvalidArgument", http.StatusBadRequest, "max-keys must be a non-negative integer")
		}
		req.MaxKeys = min(n, 1000)
	}
	enc := func(s string) string { return s }
	switch query.Get("encoding-type") {
	case "":
	case "url":
		enc = func(s string) string { return awsEscape(s, true) }
	default:
		return req, nil, errf("InvalidArgument", http.StatusBadRequest, "encoding-type must be url")
	}
	return req, enc, nil
}

func (g *Gateway) list(q *request, req s3meta.ListRequest) (*s3meta.ListResponse, error) {
	if req.MaxKeys == 0 {
		// S3 answers max-keys=0 with an empty page, but still checks the bucket.
		if _, err := g.Meta.Bucket(q.ctx, q.tenant, q.bucket); err != nil {
			return nil, err
		}
		return &s3meta.ListResponse{}, nil
	}
	return g.Meta.ListObjects(q.ctx, req)
}

func contents(objs []s3meta.Object, enc func(string) string, withOwner bool, tenant string) []contentXML {
	out := make([]contentXML, 0, len(objs))
	for _, o := range objs {
		c := contentXML{Key: enc(o.Key), LastModified: iso(o.Modified), ETag: `"` + o.ETag + `"`, Size: o.Size, StorageClass: "STANDARD"}
		if withOwner {
			c.Owner = &owner{ID: tenant, DisplayName: tenant}
		}
		out = append(out, c)
	}
	return out
}

func prefixes(ps []string, enc func(string) string) []prefixXML {
	out := make([]prefixXML, 0, len(ps))
	for _, p := range ps {
		out = append(out, prefixXML{Prefix: enc(p)})
	}
	return out
}

func (g *Gateway) listObjectsV2(q *request) error {
	query := q.r.URL.Query()
	req, enc, err := listParams(q)
	if err != nil {
		return err
	}
	req.StartAfter = query.Get("start-after")
	token := query.Get("continuation-token")
	if token != "" {
		b, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return errf("InvalidArgument", http.StatusBadRequest, "the continuation token is not valid")
		}
		req.StartAfter = max(req.StartAfter, string(b))
	}
	resp, err := g.list(q, req)
	if err != nil {
		return err
	}
	out := listV2XML{
		Name: q.bucket, Prefix: enc(req.Prefix), Delimiter: enc(req.Delimiter), MaxKeys: req.MaxKeys,
		KeyCount: len(resp.Objects) + len(resp.CommonPrefixes), IsTruncated: resp.Truncated,
		ContinuationToken: token, StartAfter: enc(query.Get("start-after")),
		Contents:       contents(resp.Objects, enc, query.Get("fetch-owner") == "true", q.tenant),
		CommonPrefixes: prefixes(resp.CommonPrefixes, enc),
	}
	if query.Get("encoding-type") == "url" {
		out.EncodingType = "url"
	}
	if resp.Truncated {
		out.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(resp.Next))
	}
	writeXML(q.w, http.StatusOK, out)
	return nil
}

func (g *Gateway) listObjectsV1(q *request) error {
	query := q.r.URL.Query()
	req, enc, err := listParams(q)
	if err != nil {
		return err
	}
	req.StartAfter = query.Get("marker")
	resp, err := g.list(q, req)
	if err != nil {
		return err
	}
	out := listV1XML{
		Name: q.bucket, Prefix: enc(req.Prefix), Marker: enc(req.StartAfter), Delimiter: enc(req.Delimiter),
		MaxKeys: req.MaxKeys, IsTruncated: resp.Truncated,
		Contents:       contents(resp.Objects, enc, true, q.tenant),
		CommonPrefixes: prefixes(resp.CommonPrefixes, enc),
	}
	if query.Get("encoding-type") == "url" {
		out.EncodingType = "url"
	}
	if resp.Truncated {
		out.NextMarker = enc(resp.Next)
	}
	writeXML(q.w, http.StatusOK, out)
	return nil
}

// --- objects ---

const maxMetadataBytes = 2 << 10

func userMetadata(h http.Header) (map[string]string, error) {
	var out map[string]string
	total := 0
	for k, vs := range h {
		name, ok := strings.CutPrefix(strings.ToLower(k), "x-amz-meta-")
		if !ok || len(vs) == 0 {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[name] = vs[0]
		total += len(name) + len(vs[0])
	}
	if total > maxMetadataBytes {
		return nil, errf("MetadataTooLarge", http.StatusBadRequest, "user metadata is over 2 KiB")
	}
	return out, nil
}

// putBody returns the request body after checking its declared size.
func putBody(q *request, limit int64) (io.Reader, error) {
	body, size, err := q.auth.body(q.r)
	if err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, errf("MissingContentLength", http.StatusLengthRequired, "Content-Length is required")
	}
	if size > limit {
		return nil, errf("EntityTooLarge", http.StatusBadRequest, "the upload is larger than %d bytes", limit)
	}
	return body, nil
}

func (g *Gateway) putObject(q *request) error {
	meta, err := userMetadata(q.r.Header)
	if err != nil {
		return err
	}
	if _, err := g.Meta.Bucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	body, err := putBody(q, MaxObjectSize)
	if err != nil {
		return err
	}
	seg, err := g.store(q.ctx, q.tenant, body)
	if err != nil {
		return err
	}
	obj := s3meta.Object{
		Bucket: q.bucket, Key: q.key, ID: seg.ID, Size: seg.Size, ETag: seg.ETag,
		ContentType: q.r.Header.Get("Content-Type"), WrappedKey: seg.WrappedKey, Layout: seg.Layout, Metadata: meta,
	}
	return g.commit(q, obj, seg, func(o *s3meta.Object) {
		q.w.Header().Set("ETag", `"`+o.ETag+`"`)
		q.w.WriteHeader(http.StatusOK)
	})
}

// commit records obj, deleting its new segment if that fails and the
// replaced object's segments if it succeeds.
func (g *Gateway) commit(q *request, obj s3meta.Object, seg s3meta.Segment, respond func(*s3meta.Object)) error {
	old, err := g.Meta.PutObject(q.ctx, q.tenant, obj)
	if err != nil {
		g.discard(seg)
		return err
	}
	if old != nil {
		g.discard(old.Segments()...)
	}
	respond(&obj)
	return nil
}

func (g *Gateway) copySource(q *request) (*s3meta.Object, error) {
	src, err := url.PathUnescape(q.r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		return nil, errf("InvalidArgument", http.StatusBadRequest, "x-amz-copy-source is not valid")
	}
	src, _, _ = strings.Cut(src, "?versionId=")
	sb, sk, _ := strings.Cut(strings.TrimPrefix(src, "/"), "/")
	if sb == "" || sk == "" {
		return nil, errf("InvalidArgument", http.StatusBadRequest, "x-amz-copy-source must be bucket/key")
	}
	return g.Meta.Object(q.ctx, q.tenant, sb, sk)
}

// copyFrom streams length bytes of src from offset into a new segment.
func (g *Gateway) copyFrom(q *request, src *s3meta.Object, offset, length int64) (s3meta.Segment, error) {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(g.read(q.ctx, q.tenant, src, offset, length, pw)) }()
	seg, err := g.store(q.ctx, q.tenant, pr)
	pr.CloseWithError(errors.New("copy stopped"))
	return seg, err
}

func (g *Gateway) copyObject(q *request) error {
	src, err := g.copySource(q)
	if err != nil {
		return err
	}
	if src.Size > MaxObjectSize {
		return errf("InvalidRequest", http.StatusBadRequest, "copies over 5 GiB need a multipart upload")
	}
	if _, err := g.Meta.Bucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	ctype, meta := src.ContentType, src.Metadata
	if strings.EqualFold(q.r.Header.Get("X-Amz-Metadata-Directive"), "REPLACE") {
		if meta, err = userMetadata(q.r.Header); err != nil {
			return err
		}
		ctype = q.r.Header.Get("Content-Type")
	}
	seg, err := g.copyFrom(q, src, 0, -1)
	if err != nil {
		return err
	}
	obj := s3meta.Object{
		Bucket: q.bucket, Key: q.key, ID: seg.ID, Size: seg.Size, ETag: seg.ETag,
		ContentType: ctype, WrappedKey: seg.WrappedKey, Layout: seg.Layout, Metadata: meta,
	}
	return g.commit(q, obj, seg, func(o *s3meta.Object) {
		writeXML(q.w, http.StatusOK, copyResultXML{LastModified: iso(g.now()), ETag: `"` + o.ETag + `"`})
	})
}

// headerWriter holds response headers back until the first body byte, so
// an error before then can still be sent as a proper S3 error.
type headerWriter struct {
	w      http.ResponseWriter
	h      http.Header
	status int
	wrote  bool
}

func (hw *headerWriter) flush() {
	if hw.wrote {
		return
	}
	hw.wrote = true
	for k, v := range hw.h {
		hw.w.Header()[k] = v
	}
	hw.w.WriteHeader(hw.status)
}

func (hw *headerWriter) Write(p []byte) (int, error) {
	hw.flush()
	return hw.w.Write(p)
}

func (g *Gateway) getObject(q *request, head bool) error {
	query := q.r.URL.Query()
	if query.Has("partNumber") {
		return errf("NotImplemented", http.StatusNotImplemented, "partNumber is not supported")
	}
	obj, err := g.Meta.Object(q.ctx, q.tenant, q.bucket, q.key)
	if err != nil {
		return err
	}
	h := http.Header{}
	etag := `"` + obj.ETag + `"`
	mod := obj.Modified.UTC().Truncate(time.Second)
	h.Set("ETag", etag)
	h.Set("Last-Modified", mod.Format(http.TimeFormat))
	h.Set("Accept-Ranges", "bytes")
	ctype := obj.ContentType
	if ctype == "" {
		ctype = "binary/octet-stream"
	}
	h.Set("Content-Type", ctype)
	for k, v := range obj.Metadata {
		h.Set("x-amz-meta-"+k, v)
	}
	for _, p := range []string{"Content-Type", "Content-Language", "Expires", "Cache-Control", "Content-Disposition", "Content-Encoding"} {
		if v := query.Get("response-" + strings.ToLower(p)); v != "" {
			h.Set(p, v)
		}
	}

	if status := preconditions(q.r, etag, mod); status != 0 {
		if status == http.StatusPreconditionFailed {
			return errf("PreconditionFailed", status, "a precondition does not hold")
		}
		for _, k := range []string{"ETag", "Last-Modified"} {
			q.w.Header().Set(k, h.Get(k))
		}
		q.w.WriteHeader(status)
		return nil
	}

	start, length, partial, err := parseRange(q.r.Header.Get("Range"), obj.Size)
	if err != nil {
		q.w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(obj.Size, 10))
		return err
	}
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		h.Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(start+length-1, 10)+"/"+strconv.FormatInt(obj.Size, 10))
	}
	h.Set("Content-Length", strconv.FormatInt(length, 10))
	hw := &headerWriter{w: q.w, h: h, status: status}
	if head || length == 0 {
		hw.flush()
		return nil
	}
	if err := g.read(q.ctx, q.tenant, obj, start, length, hw); err != nil {
		if !hw.wrote {
			return err
		}
		g.logf("s3: GET %s/%s failed mid-stream: %v", q.bucket, q.key, err)
		panic(http.ErrAbortHandler)
	}
	return nil
}

// preconditions evaluates conditional headers: 0 to proceed, else 304 or 412.
func preconditions(r *http.Request, etag string, mod time.Time) int {
	match := func(list string) bool {
		for _, t := range strings.Split(list, ",") {
			t = strings.TrimSpace(t)
			if t == "*" || strings.Trim(t, `"`) == strings.Trim(etag, `"`) {
				return true
			}
		}
		return false
	}
	if v := r.Header.Get("If-Match"); v != "" && !match(v) {
		return http.StatusPreconditionFailed
	}
	if v := r.Header.Get("If-Unmodified-Since"); v != "" && r.Header.Get("If-Match") == "" {
		if t, err := http.ParseTime(v); err == nil && mod.After(t) {
			return http.StatusPreconditionFailed
		}
	}
	if v := r.Header.Get("If-None-Match"); v != "" {
		if match(v) {
			return http.StatusNotModified
		}
	} else if v := r.Header.Get("If-Modified-Since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && !mod.After(t) {
			return http.StatusNotModified
		}
	}
	return 0
}

// parseRange parses a single byte range. Malformed or multi-range headers
// are ignored (the whole object is sent), as HTTP allows.
func parseRange(h string, size int64) (start, length int64, partial bool, err error) {
	spec, ok := strings.CutPrefix(h, "bytes=")
	if h == "" || !ok || strings.Contains(spec, ",") {
		return 0, size, false, nil
	}
	a, b, ok := strings.Cut(strings.TrimSpace(spec), "-")
	if !ok {
		return 0, size, false, nil
	}
	invalid := errf("InvalidRange", http.StatusRequestedRangeNotSatisfiable, "the requested range is not satisfiable")
	if a == "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil {
			return 0, size, false, nil
		}
		if n <= 0 || size == 0 {
			return 0, 0, false, invalid
		}
		n = min(n, size)
		return size - n, n, true, nil
	}
	first, err1 := strconv.ParseInt(a, 10, 64)
	last := size - 1
	var err2 error
	if b != "" {
		last, err2 = strconv.ParseInt(b, 10, 64)
	}
	if err1 != nil || err2 != nil || first < 0 {
		return 0, size, false, nil
	}
	if first >= size {
		return 0, 0, false, invalid
	}
	if last < first {
		return 0, size, false, nil
	}
	last = min(last, size-1)
	return first, last - first + 1, true, nil
}

func (g *Gateway) deleteObject(q *request) error {
	old, err := g.Meta.DeleteObject(q.ctx, q.tenant, q.bucket, q.key)
	if err != nil {
		return err
	}
	if old != nil {
		g.discard(old.Segments()...)
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// readXML decodes a small XML request body.
func readXML(q *request, limit int64, v any) error {
	body, _, err := q.auth.body(q.r)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(b)) > limit {
		return errf("MalformedXML", http.StatusBadRequest, "the XML body is too large")
	}
	if err := xml.Unmarshal(b, v); err != nil {
		return errf("MalformedXML", http.StatusBadRequest, "the XML body is not well-formed")
	}
	return nil
}

func (g *Gateway) deleteObjects(q *request) error {
	var req deleteXML
	if err := readXML(q, 2<<20, &req); err != nil {
		return err
	}
	if len(req.Objects) == 0 || len(req.Objects) > 1000 {
		return errf("MalformedXML", http.StatusBadRequest, "list 1 to 1000 objects")
	}
	if _, err := g.Meta.Bucket(q.ctx, q.tenant, q.bucket); err != nil {
		return err
	}
	var out deleteResultXML
	for _, o := range req.Objects {
		old, err := g.Meta.DeleteObject(q.ctx, q.tenant, q.bucket, o.Key)
		if err != nil {
			code, msg := "InternalError", "internal error"
			var me *s3meta.Error
			if errors.As(err, &me) {
				code, msg = me.Code, me.Msg
			} else {
				g.logf("s3: delete %s/%s: %v", q.bucket, o.Key, err)
			}
			out.Errors = append(out.Errors, deleteErrorXML{Key: o.Key, Code: code, Message: msg})
			continue
		}
		if old != nil {
			g.discard(old.Segments()...)
		}
		if !req.Quiet {
			out.Deleted = append(out.Deleted, deletedXML{Key: o.Key})
		}
	}
	writeXML(q.w, http.StatusOK, out)
	return nil
}

// --- multipart ---

func (q *request) upload(id string) s3meta.UploadRequest {
	return s3meta.UploadRequest{Tenant: q.tenant, Bucket: q.bucket, Key: q.key, UploadID: id}
}

func (g *Gateway) createUpload(q *request) error {
	meta, err := userMetadata(q.r.Header)
	if err != nil {
		return err
	}
	u := s3meta.Upload{ID: newID(16), Bucket: q.bucket, Key: q.key, ContentType: q.r.Header.Get("Content-Type"), Metadata: meta}
	if err := g.Meta.CreateUpload(q.ctx, q.tenant, u); err != nil {
		return err
	}
	writeXML(q.w, http.StatusOK, initiateXML{Bucket: q.bucket, Key: q.key, UploadID: u.ID})
	return nil
}

func (g *Gateway) uploadPart(q *request, uploadID string) error {
	n, err := strconv.Atoi(q.r.URL.Query().Get("partNumber"))
	if err != nil || n < 1 || n > s3meta.MaxParts {
		return errf("InvalidArgument", http.StatusBadRequest, "partNumber must be 1 to %d", s3meta.MaxParts)
	}
	var seg s3meta.Segment
	copying := q.r.Header.Get("X-Amz-Copy-Source") != ""
	if copying {
		src, err := g.copySource(q)
		if err != nil {
			return err
		}
		start, length := int64(0), src.Size
		if rng := q.r.Header.Get("X-Amz-Copy-Source-Range"); rng != "" {
			var partial bool
			start, length, partial, err = parseRange(rng, src.Size)
			if err != nil || !partial {
				return errf("InvalidArgument", http.StatusBadRequest, "x-amz-copy-source-range is not valid")
			}
		}
		if length > s3meta.MaxPartSize {
			return errf("EntityTooLarge", http.StatusBadRequest, "a part can be at most 5 GiB")
		}
		if seg, err = g.copyFrom(q, src, start, length); err != nil {
			return err
		}
	} else {
		body, err := putBody(q, s3meta.MaxPartSize)
		if err != nil {
			return err
		}
		if seg, err = g.store(q.ctx, q.tenant, body); err != nil {
			return err
		}
	}
	old, err := g.Meta.PutPart(q.ctx, q.upload(uploadID), s3meta.Part{Number: n, Segment: seg})
	if err != nil {
		g.discard(seg)
		return err
	}
	if old != nil {
		g.discard(old.Segment)
	}
	if copying {
		writeXML(q.w, http.StatusOK, struct {
			XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyPartResult"`
			LastModified string   `xml:"LastModified"`
			ETag         string   `xml:"ETag"`
		}{LastModified: iso(g.now()), ETag: `"` + seg.ETag + `"`})
		return nil
	}
	q.w.Header().Set("ETag", `"`+seg.ETag+`"`)
	q.w.WriteHeader(http.StatusOK)
	return nil
}

func (g *Gateway) completeUpload(q *request, uploadID string) error {
	var req completeXML
	if err := readXML(q, 4<<20, &req); err != nil {
		return err
	}
	if len(req.Parts) == 0 {
		return errf("MalformedXML", http.StatusBadRequest, "list at least one part")
	}
	parts := make([]s3meta.CompletedPart, len(req.Parts))
	for i, p := range req.Parts {
		parts[i] = s3meta.CompletedPart{Number: p.PartNumber, ETag: p.ETag}
	}
	resp, err := g.Meta.CompleteUpload(q.ctx, q.upload(uploadID), parts)
	if err != nil {
		return err
	}
	g.discard(resp.Discard...)
	if resp.Old != nil {
		g.discard(resp.Old.Segments()...)
	}
	writeXML(q.w, http.StatusOK, completeResultXML{
		Location: "/" + q.bucket + "/" + q.key, Bucket: q.bucket, Key: q.key, ETag: `"` + resp.Object.ETag + `"`,
	})
	return nil
}

func (g *Gateway) abortUpload(q *request, uploadID string) error {
	u, err := g.Meta.AbortUpload(q.ctx, q.upload(uploadID))
	if err != nil {
		return err
	}
	for _, p := range u.Parts {
		g.discard(p.Segment)
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (g *Gateway) listParts(q *request, uploadID string) error {
	query := q.r.URL.Query()
	u, err := g.Meta.Upload(q.ctx, q.upload(uploadID))
	if err != nil {
		return err
	}
	marker, _ := strconv.Atoi(query.Get("part-number-marker"))
	maxParts := 1000
	if s := query.Get("max-parts"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			maxParts = min(n, 1000)
		}
	}
	nums := make([]int, 0, len(u.Parts))
	for n := range u.Parts {
		if n > marker {
			nums = append(nums, n)
		}
	}
	sort.Ints(nums)
	out := listPartsXML{Bucket: q.bucket, Key: q.key, UploadID: uploadID, PartNumberMarker: marker, MaxParts: maxParts, StorageClass: "STANDARD"}
	for _, n := range nums {
		if len(out.Parts) == maxParts {
			out.IsTruncated = true
			break
		}
		p := u.Parts[n]
		out.Parts = append(out.Parts, partXML{PartNumber: n, LastModified: iso(p.Modified), ETag: `"` + p.ETag + `"`, Size: p.Size})
		out.NextPartNumberMarker = n
	}
	writeXML(q.w, http.StatusOK, out)
	return nil
}

func (g *Gateway) listUploads(q *request) error {
	prefix := q.r.URL.Query().Get("prefix")
	us, err := g.Meta.ListUploads(q.ctx, q.tenant, q.bucket)
	if err != nil {
		return err
	}
	out := listUploadsXML{Bucket: q.bucket, Prefix: prefix, MaxUploads: 1000}
	for _, u := range us {
		if !strings.HasPrefix(u.Key, prefix) {
			continue
		}
		if len(out.Uploads) == 1000 {
			out.IsTruncated = true
			break
		}
		out.Uploads = append(out.Uploads, uploadXML{Key: u.Key, UploadID: u.ID, Initiated: iso(u.Created), StorageClass: "STANDARD"})
	}
	writeXML(q.w, http.StatusOK, out)
	return nil
}
