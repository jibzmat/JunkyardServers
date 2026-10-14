package s3gw

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AWS Signature Version 4, as S3 uses it: header and presigned-URL
// authentication, with the payload hash carried in x-amz-content-sha256.

const (
	algorithm   = "AWS4-HMAC-SHA256"
	timeFormat  = "20060102T150405Z"
	maxSkew     = 15 * time.Minute
	maxPresign  = 7 * 24 * time.Hour
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	payloadUnsigned         = "UNSIGNED-PAYLOAD"
	payloadStreamingSigned  = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	payloadStreamingTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	payloadStreamingUnsTrlr = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

// Lookup returns the secret and tenant for an access key ID.
type Lookup func(ctx context.Context, accessKeyID string) (secret, tenant string, err error)

// Auth is a verified request's identity and what is needed to check its body.
type Auth struct {
	AccessKeyID string
	Tenant      string
	// PayloadHash is the x-amz-content-sha256 value (UNSIGNED-PAYLOAD for
	// presigned URLs).
	PayloadHash string

	signingKey []byte
	amzDate    string
	scope      string
	signature  string
}

// verify authenticates r. It returns an *Error with the S3 code on failure.
func verify(ctx context.Context, r *http.Request, lookup Lookup, now time.Time, vhostBucket string) (*Auth, error) {
	if isV2(r) {
		return verifyV2(ctx, r, lookup, now, vhostBucket)
	}
	if q := r.URL.Query(); q.Get("X-Amz-Algorithm") != "" || q.Get("X-Amz-Signature") != "" {
		return verifyPresigned(ctx, r, lookup, now)
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, errAccessDenied("anonymous requests are not supported; sign with an access key")
	}
	if !strings.HasPrefix(h, algorithm+" ") {
		return nil, errf("AuthorizationHeaderMalformed", http.StatusBadRequest, "only %s is supported", algorithm)
	}
	var cred, signed, sig string
	for _, part := range strings.Split(h[len(algorithm)+1:], ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Credential":
			cred = v
		case "SignedHeaders":
			signed = v
		case "Signature":
			sig = v
		}
	}
	if cred == "" || signed == "" || sig == "" {
		return nil, errf("AuthorizationHeaderMalformed", http.StatusBadRequest, "authorization header is missing a field")
	}
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = r.Header.Get("Date")
		if t, err := http.ParseTime(amzDate); err == nil {
			amzDate = t.UTC().Format(timeFormat)
		}
	}
	t, err := time.Parse(timeFormat, amzDate)
	if err != nil {
		return nil, errAccessDenied("missing or malformed X-Amz-Date")
	}
	if d := now.Sub(t); d > maxSkew || d < -maxSkew {
		return nil, errf("RequestTimeTooSkewed", http.StatusForbidden, "request time differs from server time by more than 15 minutes")
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		return nil, errf("InvalidRequest", http.StatusBadRequest, "missing x-amz-content-sha256")
	}
	switch payload {
	case payloadUnsigned, payloadStreamingSigned, payloadStreamingTrailer, payloadStreamingUnsTrlr:
	default:
		if b, err := hex.DecodeString(payload); err != nil || len(b) != sha256.Size {
			return nil, errf("InvalidArgument", http.StatusBadRequest, "unsupported x-amz-content-sha256 %q", payload)
		}
	}
	a, err := check(ctx, r, lookup, cred, signed, sig, amzDate, payload, "X-Amz-Signature")
	if err != nil {
		return nil, err
	}
	a.PayloadHash = payload
	return a, nil
}

func verifyPresigned(ctx context.Context, r *http.Request, lookup Lookup, now time.Time) (*Auth, error) {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != algorithm {
		return nil, errf("AuthorizationQueryParametersError", http.StatusBadRequest, "only %s is supported", algorithm)
	}
	amzDate := q.Get("X-Amz-Date")
	t, err := time.Parse(timeFormat, amzDate)
	if err != nil {
		return nil, errf("AuthorizationQueryParametersError", http.StatusBadRequest, "bad X-Amz-Date")
	}
	secs, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || secs < 1 || time.Duration(secs)*time.Second > maxPresign {
		return nil, errf("AuthorizationQueryParametersError", http.StatusBadRequest, "X-Amz-Expires must be 1 to 604800 seconds")
	}
	if now.Before(t.Add(-maxSkew)) {
		return nil, errAccessDenied("request is not valid yet")
	}
	if now.After(t.Add(time.Duration(secs) * time.Second)) {
		return nil, errAccessDenied("request has expired")
	}
	a, err := check(ctx, r, lookup, q.Get("X-Amz-Credential"), q.Get("X-Amz-SignedHeaders"), q.Get("X-Amz-Signature"), amzDate, payloadUnsigned, "X-Amz-Signature")
	if err != nil {
		return nil, err
	}
	a.PayloadHash = payloadUnsigned
	return a, nil
}

// check recomputes the signature.
func check(ctx context.Context, r *http.Request, lookup Lookup, cred, signedHeaders, sig, amzDate, payload, skipQuery string) (*Auth, error) {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[3] != "s3" || parts[4] != "aws4_request" {
		return nil, errf("AuthorizationHeaderMalformed", http.StatusBadRequest, "bad credential scope %q", cred)
	}
	akid, day, region := parts[0], parts[1], parts[2]
	if !strings.HasPrefix(amzDate, day) {
		return nil, errf("AuthorizationHeaderMalformed", http.StatusBadRequest, "credential date does not match X-Amz-Date")
	}
	secret, tenant, err := lookup(ctx, akid)
	if err != nil {
		return nil, err
	}
	scope := day + "/" + region + "/s3/aws4_request"

	headers := strings.Split(signedHeaders, ";")
	if !sort.StringsAreSorted(headers) || !contains(headers, "host") {
		return nil, errf("AuthorizationHeaderMalformed", http.StatusBadRequest, "signed headers must be sorted and include host")
	}
	var canon strings.Builder
	canon.WriteString(r.Method + "\n")
	canon.WriteString(canonicalURI(r.URL.Path) + "\n")
	canon.WriteString(canonicalQuery(r.URL.RawQuery, skipQuery) + "\n")
	for _, h := range headers {
		canon.WriteString(h + ":" + headerValue(r, h) + "\n")
	}
	canon.WriteString("\n" + signedHeaders + "\n" + payload)

	sum := sha256.Sum256([]byte(canon.String()))
	toSign := algorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	key := signingKey(secret, day, region)
	want := hex.EncodeToString(hmacSHA256(key, toSign))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return nil, errf("SignatureDoesNotMatch", http.StatusForbidden, "the request signature does not match; check your secret key and signing method")
	}
	return &Auth{AccessKeyID: akid, Tenant: tenant, signingKey: key, amzDate: amzDate, scope: scope, signature: sig}, nil
}

func signingKey(secret, day, region string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	return hmacSHA256(k, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// headerValue is a header's canonical value: values joined with commas,
// whitespace trimmed and runs of spaces collapsed.
func headerValue(r *http.Request, name string) string {
	var vals []string
	switch name {
	case "host":
		vals = []string{r.Host}
	default:
		vals = r.Header.Values(name)
		if len(vals) == 0 && name == "content-length" && r.ContentLength >= 0 {
			vals = []string{strconv.FormatInt(r.ContentLength, 10)}
		}
		if len(vals) == 0 && name == "transfer-encoding" {
			vals = r.TransferEncoding
		}
	}
	for i, v := range vals {
		vals[i] = strings.Join(strings.Fields(v), " ")
	}
	return strings.Join(vals, ",")
}

// canonicalURI encodes the decoded path the way S3 clients sign it: every
// byte except unreserved characters and '/' is percent-encoded, once.
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return awsEscape(path, true)
}

func canonicalQuery(raw, skip string) string {
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, err1 := url.QueryUnescape(k)
		v, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil || k == skip {
			continue
		}
		pairs = append(pairs, kv{awsEscape(k, false), awsEscape(v, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

// awsEscape percent-encodes everything but A-Z a-z 0-9 - _ . ~ (and '/'
// when keepSlash).
func awsEscape(s string, keepSlash bool) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' || (keepSlash && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
