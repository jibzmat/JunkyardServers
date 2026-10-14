package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
}

// OpenShardStore uses dir, creating it if needed.
func OpenShardStore(dir string) (*ShardStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &ShardStore{dir: dir}, nil
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
		return nil
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
	return os.Rename(tmp.Name(), p)
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
		return nil, errHashMismatch
	}
	return data, nil
}

// Delete removes a shard; deleting a missing shard is not an error.
func (s *ShardStore) Delete(hash string) error {
	if !ValidHash(hash) {
		return fmt.Errorf("storage: bad shard name %q", hash)
	}
	err := os.Remove(s.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
