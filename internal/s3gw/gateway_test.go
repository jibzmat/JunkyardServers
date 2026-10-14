package s3gw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jibzmat/JunkyardServers/internal/control"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

type env struct {
	t      *testing.T
	url    string
	gw     *Gateway
	shards []string // shard directories
	akid   string
	secret string
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// newEnv runs a control plane, three shard servers and a gateway.
func newEnv(t *testing.T) *env {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv, creds, err := control.Init(filepath.Join(t.TempDir(), "control"), "test", addr, freeAddr(t), nil)
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	cs := httptest.NewUnstartedServer(srv.Handler())
	cs.Listener.Close()
	cs.Listener = ln
	cs.TLS = srv.TLSConfig()
	cs.StartTLS()
	t.Cleanup(cs.Close)

	admin := control.NewClient([]string{addr}, pki.TLSCertificate(creds.CertDER, creds.Key, srv.CA()), srv.CA())
	ten, err := admin.CreateTenant(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.CreateTenant(context.Background(), "bob"); err != nil {
		t.Fatal(err)
	}

	// Shard servers under their own CA; only the gateway's client cares.
	ca, err := pki.NewCA("shards")
	if err != nil {
		t.Fatal(err)
	}
	issue := func(kind pki.Kind, name string) (*x509.Certificate, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		der, err := ca.Issue(kind, name, pub, time.Hour, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, priv
	}
	e := &env{t: t, akid: ten.AccessKeyID, secret: ten.SecretAccessKey}
	var nodes []storage.Node
	for i := 0; i < 3; i++ {
		dir := filepath.Join(t.TempDir(), "shards")
		st, err := storage.OpenShardStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		cert, key := issue(pki.KindNode, fmt.Sprintf("n-%d", i))
		ss := &storage.ShardServer{Store: st, Cert: pki.TLSCertificate(cert.Raw, key, ca.Cert), CA: ca.Cert,
			MayDelete: func(c *x509.Certificate) bool { return pki.KindOf(c) == pki.KindControl }}
		ts := httptest.NewUnstartedServer(ss.Handler())
		ts.TLS = ss.TLSConfig()
		ts.StartTLS()
		t.Cleanup(ts.Close)
		e.shards = append(e.shards, dir)
		nodes = append(nodes, storage.Node{ID: fmt.Sprintf("n-%d", i), Addr: ts.Listener.Addr().String()})
	}
	gwCert, gwKey := issue(pki.KindControl, "gateway")
	e.gw = &Gateway{
		Meta: control.NewClient([]string{addr}, srv.ClientCertificate(), srv.CA()),
		Store: &storage.Store{
			Client: storage.NewShardClient(pki.TLSCertificate(gwCert.Raw, gwKey, ca.Cert), ca.Cert),
			Nodes:  func() []storage.Node { return nodes },
		},
		Logger: log.New(io.Discard, "", 0),
	}
	hs := httptest.NewServer(e.gw)
	t.Cleanup(hs.Close)
	e.url = hs.URL
	return e
}

// do sends a SigV4-signed request with a hashed payload.
func (e *env) do(method, target string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	return e.doAs(e.akid, e.secret, method, target, body, hdr)
}

func (e *env) doAs(akid, secret, method, target string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.url+target, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	sum := sha256.Sum256(body)
	now := time.Now().UTC()
	day := now.Format("20060102")
	req.Header.Set("X-Amz-Date", now.Format(timeFormat))
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))
	signed := "host;x-amz-content-sha256;x-amz-date"
	canon := method + "\n" + canonicalURI(req.URL.Path) + "\n" + canonicalQuery(req.URL.RawQuery, "") + "\n" +
		"host:" + req.URL.Host + "\nx-amz-content-sha256:" + hex.EncodeToString(sum[:]) + "\nx-amz-date:" + now.Format(timeFormat) + "\n\n" +
		signed + "\n" + hex.EncodeToString(sum[:])
	cs := sha256.Sum256([]byte(canon))
	scope := day + "/us-east-1/s3/aws4_request"
	sig := hex.EncodeToString(hmacSHA256(signingKey(secret, day, "us-east-1"), algorithm+"\n"+now.Format(timeFormat)+"\n"+scope+"\n"+hex.EncodeToString(cs[:])))
	req.Header.Set("Authorization", algorithm+" Credential="+akid+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) expect(status int, method, target string, body []byte, hdr map[string]string) []byte {
	e.t.Helper()
	resp, b := e.do(method, target, body, hdr)
	if resp.StatusCode != status {
		e.t.Fatalf("%s %s: HTTP %d, want %d: %s", method, target, resp.StatusCode, status, b)
	}
	return b
}

func (e *env) shardCount() int {
	n := 0
	for _, d := range e.shards {
		filepath.Walk(d, func(_ string, info os.FileInfo, _ error) error {
			if info != nil && !info.IsDir() {
				n++
			}
			return nil
		})
	}
	return n
}

func TestGatewayObjects(t *testing.T) {
	e := newEnv(t)
	e.expect(200, "PUT", "/photos", nil, nil)
	e.expect(409, "PUT", "/photos", nil, nil)
	if b := e.expect(200, "GET", "/", nil, nil); !strings.Contains(string(b), "<Name>photos</Name>") {
		t.Fatalf("list buckets: %s", b)
	}

	data := bytes.Repeat([]byte("junkyard!"), 1<<20) // 9 MiB: three chunks
	sum := md5.Sum(data)
	bad := md5.Sum([]byte("other"))
	if b := e.expect(400, "PUT", "/photos/a/b.bin", data, map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(bad[:])}); !strings.Contains(string(b), "BadDigest") {
		t.Fatalf("bad md5: %s", b)
	}
	e.gw.Wait()
	if n := e.shardCount(); n != 0 {
		t.Fatalf("rejected upload left %d shards", n)
	}
	resp, _ := e.do("PUT", "/photos/a/b.bin", data, map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(sum[:]), "Content-Type": "application/x-test", "x-amz-meta-color": "blue"})
	if want := `"` + hex.EncodeToString(sum[:]) + `"`; resp.Header.Get("ETag") != want {
		t.Fatalf("etag %q want %q", resp.Header.Get("ETag"), want)
	}
	shards := e.shardCount()

	if b := e.expect(200, "GET", "/photos/a/b.bin", nil, nil); !bytes.Equal(b, data) {
		t.Fatal("GET returned different bytes")
	}
	resp, b := e.do("GET", "/photos/a/b.bin", nil, map[string]string{"Range": "bytes=4194300-4194310"})
	if resp.StatusCode != 206 || !bytes.Equal(b, data[4194300:4194311]) {
		t.Fatalf("range across chunks: %d %q", resp.StatusCode, b)
	}
	resp, _ = e.do("HEAD", "/photos/a/b.bin", nil, nil)
	if resp.Header.Get("Content-Type") != "application/x-test" || resp.Header.Get("X-Amz-Meta-Color") != "blue" || resp.ContentLength != int64(len(data)) {
		t.Fatalf("head headers %v", resp.Header)
	}
	if resp, _ := e.do("GET", "/photos/a/b.bin", nil, map[string]string{"If-None-Match": `"` + hex.EncodeToString(sum[:]) + `"`}); resp.StatusCode != 304 {
		t.Fatalf("if-none-match: %d", resp.StatusCode)
	}

	// Overwriting deletes the old object's shards.
	e.expect(200, "PUT", "/photos/a/b.bin", []byte("small now"), nil)
	e.gw.Wait()
	if n := e.shardCount(); n >= shards {
		t.Fatalf("shards after overwrite %d, before %d", n, shards)
	}

	e.expect(200, "PUT", "/photos/a/c%20d+e.txt", []byte("x"), nil)
	e.expect(200, "PUT", "/photos/top.txt", []byte("y"), nil)
	b = e.expect(200, "GET", "/photos?list-type=2&delimiter=%2F&encoding-type=url", nil, nil)
	if !strings.Contains(string(b), "<Prefix>a%2F</Prefix>") && !strings.Contains(string(b), "<Prefix>a/</Prefix>") || !strings.Contains(string(b), "<Key>top.txt</Key>") {
		t.Fatalf("delimited list: %s", b)
	}
	b = e.expect(200, "GET", "/photos?list-type=2&prefix=a%2F&encoding-type=url", nil, nil)
	if !strings.Contains(string(b), "<Key>a/c%20d%2Be.txt</Key>") {
		t.Fatalf("url-encoded keys: %s", b)
	}
	b = e.expect(200, "GET", "/photos?list-type=2&max-keys=1", nil, nil)
	if !strings.Contains(string(b), "<IsTruncated>true</IsTruncated>") || !strings.Contains(string(b), "<NextContinuationToken>") {
		t.Fatalf("paging: %s", b)
	}

	e.expect(409, "DELETE", "/photos", nil, nil)
	del := `<Delete><Object><Key>a/b.bin</Key></Object><Object><Key>a/c d+e.txt</Key></Object><Object><Key>top.txt</Key></Object></Delete>`
	if b := e.expect(200, "POST", "/photos?delete", []byte(del), nil); strings.Count(string(b), "<Deleted>") != 3 {
		t.Fatalf("multi-delete: %s", b)
	}
	e.expect(404, "GET", "/photos/top.txt", nil, nil)
	e.expect(204, "DELETE", "/photos", nil, nil)
	e.gw.Wait()
	if n := e.shardCount(); n != 0 {
		t.Fatalf("%d shards left after deleting everything", n)
	}
}

func TestGatewayMultipart(t *testing.T) {
	e := newEnv(t)
	e.expect(200, "PUT", "/big", nil, nil)
	b := e.expect(200, "POST", "/big/file.bin?uploads", nil, nil)
	id := between(string(b), "<UploadId>", "</UploadId>")

	part1 := bytes.Repeat([]byte{1}, 5<<20)
	part2 := []byte("tail")
	etag := func(p []byte) string { s := md5.Sum(p); return hex.EncodeToString(s[:]) }
	e.expect(200, "PUT", "/big/file.bin?partNumber=1&uploadId="+id, part1, nil)
	e.expect(200, "PUT", "/big/file.bin?partNumber=2&uploadId="+id, []byte("replaced below"), nil)
	e.expect(200, "PUT", "/big/file.bin?partNumber=2&uploadId="+id, part2, nil)
	e.expect(404, "PUT", "/big/other.bin?partNumber=1&uploadId="+id, part2, nil)
	if b := e.expect(200, "GET", "/big/file.bin?uploadId="+id, nil, nil); strings.Count(string(b), "<Part>") != 2 {
		t.Fatalf("list parts: %s", b)
	}

	complete := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"%s"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"%s"</ETag></Part></CompleteMultipartUpload>`, etag(part1), etag(part2))
	b = e.expect(200, "POST", "/big/file.bin?uploadId="+id, []byte(complete), nil)
	if !strings.Contains(string(b), "-2&#34;</ETag>") && !strings.Contains(string(b), `-2"</ETag>`) {
		t.Fatalf("complete: %s", b)
	}
	want := append(append([]byte{}, part1...), part2...)
	if got := e.expect(200, "GET", "/big/file.bin", nil, nil); !bytes.Equal(got, want) {
		t.Fatal("assembled object differs")
	}
	resp, got := e.do("GET", "/big/file.bin", nil, map[string]string{"Range": fmt.Sprintf("bytes=%d-", len(part1)-2)})
	if resp.StatusCode != 206 || string(got) != "\x01\x01tail" {
		t.Fatalf("range across parts: %q", got)
	}

	// Small non-final parts are refused; aborting removes every part.
	b = e.expect(200, "POST", "/big/x.bin?uploads", nil, nil)
	id2 := between(string(b), "<UploadId>", "</UploadId>")
	e.expect(200, "PUT", "/big/x.bin?partNumber=1&uploadId="+id2, part2, nil)
	e.expect(200, "PUT", "/big/x.bin?partNumber=2&uploadId="+id2, part2, nil)
	small := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part><Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag(part2), etag(part2))
	if b := e.expect(400, "POST", "/big/x.bin?uploadId="+id2, []byte(small), nil); !strings.Contains(string(b), "EntityTooSmall") {
		t.Fatalf("small part: %s", b)
	}
	e.expect(409, "DELETE", "/big", nil, nil) // upload in progress
	e.expect(204, "DELETE", "/big/x.bin?uploadId="+id2, nil, nil)
	e.expect(204, "DELETE", "/big/file.bin", nil, nil)
	e.gw.Wait()
	if n := e.shardCount(); n != 0 {
		t.Fatalf("%d shards left", n)
	}
}

func TestGatewayAuth(t *testing.T) {
	e := newEnv(t)
	e.expect(200, "PUT", "/mine", nil, nil)
	if resp, b := e.doAs(e.akid, "wrong-secret", "GET", "/", nil, nil); resp.StatusCode != 403 || !strings.Contains(string(b), "SignatureDoesNotMatch") {
		t.Fatalf("wrong secret: %d %s", resp.StatusCode, b)
	}
	if resp, b := e.doAs("JYNOSUCHKEY", "x", "GET", "/", nil, nil); resp.StatusCode != 403 || !strings.Contains(string(b), "InvalidAccessKeyId") {
		t.Fatalf("unknown key: %d %s", resp.StatusCode, b)
	}
	resp, err := http.Get(e.url + "/mine")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("anonymous: %d", resp.StatusCode)
	}
	if b := e.expect(501, "GET", "/mine?acl", nil, nil); !strings.Contains(string(b), "NotImplemented") {
		t.Fatalf("acl: %s", b)
	}
}

func between(s, a, b string) string {
	_, rest, _ := strings.Cut(s, a)
	v, _, _ := strings.Cut(rest, b)
	return v
}
