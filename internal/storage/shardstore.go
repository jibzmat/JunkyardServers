package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

// MaxShardSize bounds what a storage node accepts: one whole sealed chunk
// (the k=1 coding used by one- and two-node clusters) plus slack.
const MaxShardSize = ChunkSize + Overhead + 64

// ErrNotFound is returned for a shard this node does not hold.
var ErrNotFound = errors.New("storage: shard not found")

// ShardStore keeps shards on local disk, named by hash, two directory levels
// deep so no directory gets huge.
type ShardStore struct {
	dir string

	// Quota is the most this node stores, in bytes (0: no limit), and
	// KeepFree how much of its filesystem must stay free. A put past
	// either fails with ErrFull, and writers place the shard elsewhere.
	Quota    int64
	KeepFree int64

	used atomic.Int64
}

// ErrFull means the node has reached its storage quota.
var ErrFull = errors.New("storage: this node's storage quota is used up")

// OpenShardStore uses dir, creating it if needed.
func OpenShardStore(dir string) (*ShardStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &ShardStore{dir: dir}
	var used int64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				used += info.Size()
			}
		}
		return nil
	})
	s.used.Store(used)
	return s, err
}

// Used is how many bytes of shards this node holds.
func (s *ShardStore) Used() int64 { return s.used.Load() }

// room reports whether n more bytes fit.
func (s *ShardStore) room(n int64) bool {
	if s.Quota > 0 && s.used.Load()+n > s.Quota {
		return false
	}
	if s.KeepFree > 0 {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(s.dir, &fs); err == nil && int64(fs.Bavail)*int64(fs.Bsize)-n < s.KeepFree {
			return false
		}
	}
	return true
}

func (s *ShardStore) path(hash string) string {
	return filepath.Join(s.dir, hash[:2], hash[2:4], hash)
}

// Put stores data under hash after checking the hash matches. Storing a
// shard that is already present is a no-op.
func (s *ShardStore) Put(hash string, data []byte) error {
	if !ValidHash(hash) {
		return fmt.Errorf("storage: bad shard name %q", hash)
	}
	if ShardHash(data) != hash {
		return errHashMismatch
	}
	p := s.path(hash)
	if _, err := os.Stat(p); err == nil {
		// Refresh the time so garbage collection treats it as new: repair
		// may be re-adding a shard that was left here earlier.
		now := time.Now()
		return os.Chtimes(p, now, now)
	}
	if !s.room(int64(len(data))) {
		return ErrFull
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return err
	}
	s.used.Add(int64(len(data)))
	return nil
}

// Get returns a shard, re-checking its hash so bit rot is caught here
// rather than at decode time.
func (s *ShardStore) Get(hash string) ([]byte, error) {
	if !ValidHash(hash) {
		return nil, fmt.Errorf("storage: bad shard name %q", hash)
	}
	f, err := os.Open(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxShardSize+1))
	if err != nil {
		return nil, err
	}
	if ShardHash(data) != hash {
		// Bit rot: drop it so the shard shows as missing and gets rebuilt.
		s.Delete(hash)
		return nil, errHashMismatch
	}
	return data, nil
}

// Walk calls fn for every stored shard with its modification time.
func (s *ShardStore) Walk(fn func(hash string, mod time.Time) error) error {
	return filepath.WalkDir(s.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil // removed while walking
			}
			return err
		}
		if d.IsDir() || !ValidHash(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		return fn(d.Name(), info.ModTime())
	})
}

// Scrub re-reads every shard and removes those whose content no longer
// matches their hash, pausing between shards to spare the disk. It returns
// how many shards it checked and removed.
func (s *ShardStore) Scrub(ctx context.Context, pause time.Duration) (checked, removed int, err error) {
	err = s.Walk(func(hash string, _ time.Time) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		checked++
		if _, err := s.Get(hash); errors.Is(err, errHashMismatch) {
			removed++
		}
		if pause > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pause):
			}
		}
		return nil
	})
	return checked, removed, err
}

// Delete removes a shard; deleting a missing shard is not an error.
func (s *ShardStore) Delete(hash string) error {
	if !ValidHash(hash) {
		return fmt.Errorf("storage: bad shard name %q", hash)
	}
	info, err := os.Stat(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	err = os.Remove(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		s.used.Add(-info.Size())
	}
	return err
}
