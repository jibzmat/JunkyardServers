package s3gw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Examples from the Amazon S3 SigV4 documentation.
const (
	exampleKey    = "AKIAIOSFODNN7EXAMPLE"
	exampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

var exampleTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func exampleLookup(_ context.Context, id string) (string, string, error) {
	if id != exampleKey {
		return "", "", errf("InvalidAccessKeyId", 403, "no")
	}
	return exampleSecret, "example", nil
}

func authHeader(signed, sig string) string {
	return "AWS4-HMAC-SHA256 Credential=" + exampleKey + "/20130524/us-east-1/s3/aws4_request,SignedHeaders=" + signed + ",Signature=" + sig
}

func TestSigV4Examples(t *testing.T) {
	cases := []struct {
		name, method, target, body string
		headers                    map[string]string
	}{
		{"GetObject", "GET", "/test.txt", "", map[string]string{
			"Range":                "bytes=0-9",
			"x-amz-content-sha256": emptySHA256,
			"x-amz-date":           "20130524T000000Z",
			"Authorization":        authHeader("host;range;x-amz-content-sha256;x-amz-date", "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"),
		}},
		{"PutObject", "PUT", "/test%24file.text", "Welcome to Amazon S3.", map[string]string{
			"Date":                 "Fri, 24 May 2013 00:00:00 GMT",
			"x-amz-date":           "20130524T000000Z",
			"x-amz-storage-class":  "REDUCED_REDUNDANCY",
			"x-amz-content-sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			"Authorization":        authHeader("date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class", "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"),
		}},
		{"GetBucketLifecycle", "GET", "/?lifecycle", "", map[string]string{
			"x-amz-date":           "20130524T000000Z",
			"x-amz-content-sha256": emptySHA256,
			"Authorization":        authHeader("host;x-amz-content-sha256;x-amz-date", "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"),
		}},
		{"ListObjects", "GET", "/?max-keys=2&prefix=J", "", map[string]string{
			"x-amz-date":           "20130524T000000Z",
			"x-amz-content-sha256": emptySHA256,
			"Authorization":        authHeader("host;x-amz-content-sha256;x-amz-date", "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"),
		}},
		{"Presigned", "GET", "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://examplebucket.s3.amazonaws.com"+tc.target, strings.NewReader(tc.body))
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			a, err := verify(context.Background(), r, exampleLookup, exampleTime, "")
			if err != nil {
				t.Fatal(err)
			}
			if a.Tenant != "example" {
				t.Fatalf("tenant %q", a.Tenant)
			}
			body, _, err := a.body(r)
			if err != nil {
				t.Fatal(err)
			}
			if b, err := io.ReadAll(body); err != nil || string(b) != tc.body {
				t.Fatalf("body %q %v", b, err)
			}

			// One changed byte anywhere breaks it.
			r2 := r.Clone(context.Background())
			r2.Host = "otherbucket.s3.amazonaws.com"
			if _, err := verify(context.Background(), r2, exampleLookup, exampleTime, ""); err == nil {
				t.Fatal("changed host still verified")
			}
		})
	}
}

func TestSigV4RejectsSkewAndExpiry(t *testing.T) {
	r := httptest.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt", nil)
	r.Header.Set("Range", "bytes=0-9")
	r.Header.Set("x-amz-content-sha256", emptySHA256)
	r.Header.Set("x-amz-date", "20130524T000000Z")
	r.Header.Set("Authorization", authHeader("host;range;x-amz-content-sha256;x-amz-date", "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))
	_, err := verify(context.Background(), r, exampleLookup, exampleTime.Add(time.Hour), "")
	if e := (*Error)(nil); !errors.As(err, &e) || e.Code != "RequestTimeTooSkewed" {
		t.Fatalf("skew: %v", err)
	}
	p := httptest.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", nil)
	if _, err := verify(context.Background(), p, exampleLookup, exampleTime.Add(25*time.Hour), ""); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired presign: %v", err)
	}
}

// chunkedExample builds the documented aws-chunked upload: 66560 bytes of
// 'a' in a 65536-byte chunk, a 1024-byte chunk and the final empty chunk.
func chunkedExample(sigs [3]string) *http.Request {
	var body bytes.Buffer
	for i, n := range []int{65536, 1024, 0} {
		fmt.Fprintf(&body, "%x;chunk-signature=%s\r\n", n, sigs[i])
		body.Write(bytes.Repeat([]byte{'a'}, n))
		body.WriteString("\r\n")
	}
	r := httptest.NewRequest("PUT", "http://s3.amazonaws.com/examplebucket/chunkObject.txt", &body)
	r.Header.Set("x-amz-date", "20130524T000000Z")
	r.Header.Set("x-amz-storage-class", "REDUCED_REDUNDANCY")
	r.Header.Set("x-amz-content-sha256", payloadStreamingSigned)
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("x-amz-decoded-content-length", "66560")
	r.Header.Set("Content-Length", "66824")
	r.ContentLength = 66824
	r.Header.Set("Authorization", authHeader("content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class",
		"4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"))
	return r
}

func TestChunkedUploadExample(t *testing.T) {
	good := [3]string{
		"ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
		"0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
		"b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
	}
	read := func(sigs [3]string) ([]byte, error) {
		r := chunkedExample(sigs)
		a, err := verify(context.Background(), r, exampleLookup, exampleTime, "")
		if err != nil {
			return nil, err
		}
		body, size, err := a.body(r)
		if err != nil {
			return nil, err
		}
		if size != 66560 {
			return nil, fmt.Errorf("size %d", size)
		}
		return io.ReadAll(body)
	}
	b, err := read(good)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, bytes.Repeat([]byte{'a'}, 66560)) {
		t.Fatal("decoded body differs")
	}
	bad := good
	bad[1] = strings.Repeat("0", 64)
	if _, err := read(bad); err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("forged chunk: %v", err)
	}
}

func TestUnsignedTrailer(t *testing.T) {
	sign := func(r *http.Request) *Auth { return &Auth{PayloadHash: payloadStreamingUnsTrlr} }
	mk := func(trailer string) *http.Request {
		body := "5\r\nhello\r\n0\r\n" + trailer + "\r\n\r\n"
		r := httptest.NewRequest("PUT", "http://x/b/k", strings.NewReader(body))
		r.Header.Set("Content-Encoding", "aws-chunked")
		r.Header.Set("x-amz-decoded-content-length", "5")
		r.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
		return r
	}
	// CRC32 of "hello" is 0x3610a686.
	r := mk("x-amz-checksum-crc32:NhCmhg==")
	body, _, err := sign(r).body(r)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(body); err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
	r = mk("x-amz-checksum-crc32:AAAAAA==")
	body, _, _ = sign(r).body(r)
	if _, err := io.ReadAll(body); err == nil || !strings.Contains(err.Error(), "BadDigest") {
		t.Fatalf("bad checksum accepted: %v", err)
	}
}

func TestCRC64NVME(t *testing.T) {
	if got := crc64.Checksum([]byte("123456789"), nvme); got != 0xae8b14860a799888 {
		t.Fatalf("crc64nvme check value %x", got)
	}
}

func TestParseRange(t *testing.T) {
	for _, c := range []struct {
		h             string
		start, length int64
		partial, bad  bool
	}{
		{"", 0, 100, false, false},
		{"bytes=0-9", 0, 10, true, false},
		{"bytes=90-", 90, 10, true, false},
		{"bytes=-5", 95, 5, true, false},
		{"bytes=50-500", 50, 50, true, false},
		{"bytes=100-", 0, 0, false, true},
		{"bytes=0-1,5-6", 0, 100, false, false},
		{"bytes=9-1", 0, 100, false, false},
	} {
		s, l, p, err := parseRange(c.h, 100)
		if s != c.start || l != c.length || p != c.partial || (err != nil) != c.bad {
			t.Errorf("%q: %d %d %v %v", c.h, s, l, p, err)
		}
	}
}

func TestSigV2Example(t *testing.T) {
	// GET Object from the S3 SigV2 documentation (virtual-hosted bucket).
	r := httptest.NewRequest("GET", "/photos/puppy.jpg", nil)
	r.Host = "johnsmith.s3.amazonaws.com"
	r.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	r.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	now := time.Date(2007, 3, 27, 19, 36, 42, 0, time.UTC)
	if _, err := verify(context.Background(), r, exampleLookup, now, "johnsmith"); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(context.Background(), r, exampleLookup, now, "otherbucket"); err == nil {
		t.Fatal("signature verified for another bucket")
	}
}
