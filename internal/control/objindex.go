package control

import (
	"encoding/json"

	"github.com/google/btree"

	"github.com/jibzmat/JunkyardServers/internal/s3meta"
)

// objectSet is one bucket's objects: a map for lookups and a B-tree of keys
// so listing a page costs O(log n + page) however large the bucket is. It
// encodes as a plain key -> object map, so snapshots keep their format.
type objectSet struct {
	m    map[string]*s3meta.Object
	keys *btree.BTreeG[string]
}

func newObjectSet() *objectSet {
	return &objectSet{m: map[string]*s3meta.Object{}, keys: btree.NewOrderedG[string](32)}
}

func (s *objectSet) get(key string) (*s3meta.Object, bool) {
	if s == nil {
		return nil, false
	}
	o, ok := s.m[key]
	return o, ok
}

func (s *objectSet) len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}

func (s *objectSet) set(key string, o *s3meta.Object) {
	if _, ok := s.m[key]; !ok {
		s.keys.ReplaceOrInsert(key)
	}
	s.m[key] = o
}

func (s *objectSet) del(key string) {
	if _, ok := s.m[key]; ok {
		delete(s.m, key)
		s.keys.Delete(key)
	}
}

// each calls fn for every object, in no particular order.
func (s *objectSet) each(fn func(*s3meta.Object)) {
	if s == nil {
		return
	}
	for _, o := range s.m {
		fn(o)
	}
}

// ascend calls fn for keys >= from in order until fn returns false.
func (s *objectSet) ascend(from string, fn func(key string, o *s3meta.Object) bool) {
	if s == nil {
		return
	}
	s.keys.AscendGreaterOrEqual(from, func(k string) bool { return fn(k, s.m[k]) })
}

func (s *objectSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.m)
}

func (s *objectSet) UnmarshalJSON(b []byte) error {
	var m map[string]*s3meta.Object
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*s = *newObjectSet()
	for k, o := range m {
		s.set(k, o)
	}
	return nil
}

// prefixEnd returns the smallest string greater than every string that
// starts with p, or "" if there is none (p is empty or all 0xff bytes).
func prefixEnd(p string) string {
	b := []byte(p)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b[:i+1])
		}
	}
	return ""
}
