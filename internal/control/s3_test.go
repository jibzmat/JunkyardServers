package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/cluster"
	"github.com/jibzmat/JunkyardServers/internal/pki"
	"github.com/jibzmat/JunkyardServers/internal/s3meta"
	"github.com/jibzmat/JunkyardServers/internal/storage"
)

// nodeClient joins a node and returns a client using its certificate.
func (c *testCluster) nodeClient(t *testing.T, trusted bool, roles ...cluster.Role) *Client {
	t.Helper()
	req, keys := joinReq(t, roles...)
	resp, err := Join(context.Background(), c.token(t, trusted), req)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pki.ParseCertPEM(resp.CertPEM)
	return NewClient([]string{c.addr}, pki.TLSCertificate(cert.Raw, keys.Signing, c.srv.CA()), c.srv.CA())
}

func s3Code(err error) string {
	var me *s3meta.Error
	if errors.As(err, &me) {
		return me.Code
	}
	return ""
}

func TestS3Metadata(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)
	gw := c.nodeClient(t, true, cluster.RoleGateway)

	ten, err := c.admin.CreateTenant(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.admin.CreateTenant(ctx, "alice"); s3Code(err) != s3meta.CodeTenantExists {
		t.Fatalf("duplicate tenant: %v", err)
	}
	bob, err := c.admin.CreateTenant(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}

	ak, err := gw.AccessKey(ctx, ten.AccessKeyID)
	if err != nil || ak.Secret != ten.SecretAccessKey || ak.Tenant != "alice" {
		t.Fatalf("access key %+v %v", ak, err)
	}
	if _, err := gw.AccessKey(ctx, "JYNOPE"); s3Code(err) != s3meta.CodeInvalidAccessKey {
		t.Fatalf("unknown key: %v", err)
	}

	// Data keys wrap per tenant; bob's master key can't open alice's.
	dk := bytes.Repeat([]byte{7}, 56)
	wrapped, err := gw.WrapKey(ctx, "alice", dk)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := gw.UnwrapKey(ctx, "alice", wrapped); err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("unwrap %v", err)
	}
	if _, err := gw.UnwrapKey(ctx, bob.Tenant, wrapped); err == nil {
		t.Fatal("bob unwrapped alice's key")
	}

	if err := gw.CreateBucket(ctx, "alice", "photos"); err != nil {
		t.Fatal(err)
	}
	if err := gw.CreateBucket(ctx, "alice", "photos"); s3Code(err) != s3meta.CodeBucketExists {
		t.Fatalf("recreate: %v", err)
	}
	if err := gw.CreateBucket(ctx, "bob", "photos"); s3Code(err) != s3meta.CodeBucketTaken {
		t.Fatalf("taken: %v", err)
	}
	if err := gw.CreateBucket(ctx, "alice", "Bad_Name"); err == nil {
		t.Fatal("bad bucket name accepted")
	}
	if _, err := gw.Bucket(ctx, "bob", "photos"); s3Code(err) != s3meta.CodeNoSuchBucket {
		t.Fatalf("bob sees alice's bucket: %v", err)
	}

	obj := s3meta.Object{Bucket: "photos", Key: "a.jpg", ID: "o1", Size: 3, ETag: "x", WrappedKey: wrapped,
		Layout: storage.Layout{DataShards: 1, Chunks: []storage.ChunkRef{{Size: 3, Shards: []storage.ShardRef{{Hash: "h", Node: "n"}}}}}}
	if old, err := gw.PutObject(ctx, "alice", obj); err != nil || old != nil {
		t.Fatalf("put: %v %v", old, err)
	}
	obj.ID = "o2"
	old, err := gw.PutObject(ctx, "alice", obj)
	if err != nil || old == nil || old.ID != "o1" {
		t.Fatalf("overwrite should return o1: %+v %v", old, err)
	}
	if _, err := gw.PutObject(ctx, "bob", obj); s3Code(err) != s3meta.CodeNoSuchBucket {
		t.Fatalf("bob wrote into alice's bucket: %v", err)
	}
	got, err := gw.Object(ctx, "alice", "photos", "a.jpg")
	if err != nil || got.ID != "o2" || len(got.Layout.Chunks) != 1 {
		t.Fatalf("get %+v %v", got, err)
	}
	if _, err := gw.Object(ctx, "alice", "photos", "nope"); s3Code(err) != s3meta.CodeNoSuchKey {
		t.Fatalf("missing key: %v", err)
	}

	if err := gw.DeleteBucket(ctx, "alice", "photos"); s3Code(err) != s3meta.CodeBucketNotEmpty {
		t.Fatalf("delete non-empty: %v", err)
	}
	if old, err := gw.DeleteObject(ctx, "alice", "photos", "a.jpg"); err != nil || old == nil || old.ID != "o2" {
		t.Fatalf("delete: %+v %v", old, err)
	}
	if old, err := gw.DeleteObject(ctx, "alice", "photos", "a.jpg"); err != nil || old != nil {
		t.Fatalf("second delete: %+v %v", old, err)
	}
	if err := gw.DeleteBucket(ctx, "alice", "photos"); err != nil {
		t.Fatal(err)
	}
	if bs, err := gw.ListBuckets(ctx, "alice"); err != nil || len(bs) != 0 {
		t.Fatalf("buckets %v %v", bs, err)
	}
}

func TestS3MetadataNeedsGateway(t *testing.T) {
	ctx := context.Background()
	c := newTestCluster(t)
	if _, err := c.admin.CreateTenant(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	for name, cl := range map[string]*Client{
		"admin":              c.admin,
		"trusted storage":    c.nodeClient(t, true, cluster.RoleStorage),
		"untrusted stranger": c.nodeClient(t, false, cluster.RoleGateway, cluster.RoleStorage),
	} {
		if _, err := cl.ListBuckets(ctx, "alice"); err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("%s used the gateway API: %v", name, err)
		}
	}
	if _, err := c.nodeClient(t, true, cluster.RoleGateway).CreateTenant(ctx, "eve"); err == nil {
		t.Error("gateway created a tenant")
	}
}

func TestListObjects(t *testing.T) {
	c := newTestCluster(t)
	if _, err := c.srv.CreateTenant("alice"); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.CreateBucket("alice", "docs"); err != nil {
		t.Fatal(err)
	}
	keys := []string{"a.txt", "dir/1", "dir/2", "dir/sub/3", "other/x", "z.txt"}
	for i, k := range keys {
		if _, err := c.srv.PutObject("alice", s3meta.Object{Bucket: "docs", Key: k, ID: fmt.Sprint(i), WrappedKey: []byte{1}}); err != nil {
			t.Fatal(err)
		}
	}
	list := func(req s3meta.ListRequest) *s3meta.ListResponse {
		t.Helper()
		req.Tenant, req.Bucket = "alice", "docs"
		r, err := c.srv.ListObjects(req)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range r.Objects {
			if o.WrappedKey != nil {
				t.Fatal("listing leaked a wrapped key")
			}
		}
		return r
	}
	names := func(r *s3meta.ListResponse) string {
		var out []string
		for _, o := range r.Objects {
			out = append(out, o.Key)
		}
		return strings.Join(out, ",") + "|" + strings.Join(r.CommonPrefixes, ",")
	}

	if got := names(list(s3meta.ListRequest{})); got != "a.txt,dir/1,dir/2,dir/sub/3,other/x,z.txt|" {
		t.Fatalf("flat: %s", got)
	}
	if got := names(list(s3meta.ListRequest{Delimiter: "/"})); got != "a.txt,z.txt|dir/,other/" {
		t.Fatalf("delimited: %s", got)
	}
	if got := names(list(s3meta.ListRequest{Prefix: "dir/", Delimiter: "/"})); got != "dir/1,dir/2|dir/sub/" {
		t.Fatalf("prefix: %s", got)
	}

	// Page through with a delimiter, two entries at a time.
	var all []string
	after := ""
	for i := 0; ; i++ {
		r := list(s3meta.ListRequest{Delimiter: "/", MaxKeys: 2, StartAfter: after})
		all = append(all, names(r))
		if !r.Truncated {
			break
		}
		after = r.Next
		if i > 5 {
			t.Fatal("paging does not end")
		}
	}
	if got := strings.Join(all, " "); got != "a.txt|dir/ z.txt|other/" {
		t.Fatalf("pages: %s", got)
	}
}
