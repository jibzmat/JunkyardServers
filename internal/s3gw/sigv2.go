package s3gw

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AWS Signature Version 2: the legacy scheme, still used by AWS CLI v1's
// "s3 presign" and older tools. It signs headers and the resource but not
// the body, so bodies are only checked by Content-MD5 when sent.

// v2Subresources are the query parameters included in the signed resource.
var v2Subresources = map[string]bool{
	"acl": true, "cors": true, "delete": true, "lifecycle": true, "location": true,
	"logging": true, "notification": true, "partNumber": true, "policy": true,
	"requestPayment": true, "restore": true, "tagging": true, "torrent": true,
	"uploadId": true, "uploads": true, "versionId": true, "versioning": true,
	"versions": true, "website": true,
	"response-cache-control": true, "response-content-disposition": true,
	"response-content-encoding": true, "response-content-language": true,
	"response-content-type": true, "response-expires": true,
}

func isV2(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "AWS ") || r.URL.Query().Has("AWSAccessKeyId")
}

// verifyV2 authenticates a SigV2 request. vhostBucket is the bucket named
// by a virtual-hosted-style Host header, if any.
func verifyV2(ctx context.Context, r *http.Request, lookup Lookup, now time.Time, vhostBucket string) (*Auth, error) {
	q := r.URL.Query()
	var akid, sig, date string
	if h := r.Header.Get("Authorization"); h != "" {
		cred, ok := strings.CutPrefix(h, "AWS ")
		i := strings.LastIndex(cred, ":")
		if !ok || i < 0 {
			return nil, errf("AuthorizationHeaderMalformed", http.StatusBadRequest, "malformed authorization header")
		}
		akid, sig = cred[:i], cred[i+1:]
		t, err := parseHTTPDate(r.Header.Get("X-Amz-Date"))
		if err != nil {
			if t, err = parseHTTPDate(r.Header.Get("Date")); err != nil {
				return nil, errAccessDenied("missing or malformed Date")
			}
		}
		if d := now.Sub(t); d > maxSkew || d < -maxSkew {
			return nil, errf("RequestTimeTooSkewed", http.StatusForbidden, "request time differs from server time by more than 15 minutes")
		}
		if r.Header.Get("X-Amz-Date") == "" {
			date = r.Header.Get("Date")
		}
	} else {
		akid, sig, date = q.Get("AWSAccessKeyId"), q.Get("Signature"), q.Get("Expires")
		exp, err := strconv.ParseInt(date, 10, 64)
		if err != nil {
			return nil, errAccessDenied("malformed Expires")
		}
		if now.Unix() > exp {
			return nil, errAccessDenied("request has expired")
		}
		if time.Unix(exp, 0).Sub(now) > maxPresign {
			return nil, errAccessDenied("Expires is more than 7 days ahead")
		}
	}
	secret, tenant, err := lookup(ctx, akid)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	b.WriteString(r.Method + "\n" + r.Header.Get("Content-MD5") + "\n" + r.Header.Get("Content-Type") + "\n" + date + "\n")
	var amz []string
	for k := range r.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz-") {
			amz = append(amz, lk)
		}
	}
	sort.Strings(amz)
	for _, k := range amz {
		b.WriteString(k + ":" + headerValue(r, k) + "\n")
	}
	if vhostBucket != "" {
		b.WriteString("/" + vhostBucket)
	}
	path, _, _ := strings.Cut(r.RequestURI, "?")
	if u, err := url.ParseRequestURI(r.RequestURI); err == nil && u.IsAbs() {
		path = u.EscapedPath()
	}
	b.WriteString(path)
	var subs []string
	for k, vs := range q {
		if v2Subresources[k] {
			if len(vs) == 0 || vs[0] == "" {
				subs = append(subs, k)
			} else {
				subs = append(subs, k+"="+vs[0])
			}
		}
	}
	sort.Strings(subs)
	if len(subs) > 0 {
		b.WriteString("?" + strings.Join(subs, "&"))
	}

	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(b.String()))
	want := base64.StdEncoding.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return nil, errf("SignatureDoesNotMatch", http.StatusForbidden, "the request signature does not match; check your secret key and signing method")
	}
	return &Auth{AccessKeyID: akid, Tenant: tenant, PayloadHash: payloadUnsigned}, nil
}

// parseHTTPDate also accepts numeric zones ("+0000"), which SigV2 clients send.
func parseHTTPDate(v string) (time.Time, error) {
	if t, err := http.ParseTime(v); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC1123Z, v)
}
