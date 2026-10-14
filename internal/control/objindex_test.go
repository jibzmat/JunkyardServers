package control

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

// naiveList is the obvious sort-everything listing, as a reference.
func naiveList(objs map[string]*s3meta.Object, req s3meta.ListRequest, max int) *s3meta.ListResponse {
	var keys []string
	for k := range objs {
		if strings.HasPrefix(k, req.Prefix) && k > req.StartAfter {
			keys = append(keys, k)
		}
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
		resp.Objects = append(resp.Objects, s3meta.Object{Key: k})
		last = k
	}
	if resp.Truncated {
		resp.Next = last
	}
	return resp
}

func TestListPageMatchesNaiveListing(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	parts := []string{"a", "b", "a/", "/", "-", "x/y", "\xff", "é"}
	set := newObjectSet()
	ref := map[string]*s3meta.Object{}
	for i := 0; i < 2000; i++ {
		var k strings.Builder
		for n := 1 + rng.Intn(5); n > 0; n-- {
			k.WriteString(parts[rng.Intn(len(parts))])
		}
		o := &s3meta.Object{Key: k.String()}
		set.set(o.Key, o)
		ref[o.Key] = o
		if rng.Intn(10) == 0 { // and some deletes
			set.del(o.Key)
			delete(ref, o.Key)
		}
	}
	prefixes := []string{"", "a", "a/", "b", "x/", "\xff", "zz"}
	delims := []string{"", "/", "a", "-"}
	for _, p := range prefixes {
		for _, d := range delims {
			for _, max := range []int{1, 3, 1000} {
				// Page through the whole listing both ways.
				req := s3meta.ListRequest{Prefix: p, Delimiter: d}
				for page := 0; ; page++ {
					got := &s3meta.ListResponse{Objects: []s3meta.Object{}}
					listPage(set, req, max, got)
					for i := range got.Objects {
						got.Objects[i] = s3meta.Object{Key: got.Objects[i].Key}
					}
					want := naiveList(ref, req, max)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("prefix %q delim %q max %d page %d after %q:\n got %+v\nwant %+v", p, d, max, page, req.StartAfter, got, want)
					}
					if !got.Truncated {
						break
					}
					req.StartAfter = got.Next
				}
			}
		}
	}
}

func TestObjectSetJSONRoundTrip(t *testing.T) {
	s := newObjectSet()
	for i := 0; i < 50; i++ {
		k := fmt.Sprintf("k%03d", i)
		s.set(k, &s3meta.Object{Key: k, Size: int64(i)})
	}
	b, err := json.Marshal(map[string]*objectSet{"b": s})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]*objectSet
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	var keys []string
	back["b"].ascend("k010", func(k string, o *s3meta.Object) bool {
		keys = append(keys, k)
		return len(keys) < 3
	})
	if !reflect.DeepEqual(keys, []string{"k010", "k011", "k012"}) {
		t.Fatalf("keys %v", keys)
	}
	if o, _ := back["b"].get("k049"); o == nil || o.Size != 49 {
		t.Fatal("object lost")
	}
}

func BenchmarkListPageLargeBucket(b *testing.B) {
	s := newObjectSet()
	for i := 0; i < 1_000_000; i++ {
		k := fmt.Sprintf("logs/%04d/%07d", i%1000, i)
		s.set(k, &s3meta.Object{Key: k})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &s3meta.ListResponse{}
		listPage(s, s3meta.ListRequest{Prefix: "logs/0500/", StartAfter: "logs/0500/0300500"}, 1000, resp)
		resp = &s3meta.ListResponse{}
		listPage(s, s3meta.ListRequest{Prefix: "logs/", Delimiter: "/"}, 1000, resp)
	}
}
