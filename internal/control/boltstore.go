package control

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketLogs   = []byte("logs")
	bucketStable = []byte("stable")
)

// boltStore is the Raft log and stable store, one bbolt file per control node.
type boltStore struct {
	db *bolt.DB
}

var _ raft.LogStore = (*boltStore)(nil)
var _ raft.StableStore = (*boltStore)(nil)

func openBoltStore(path string) (*boltStore, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketLogs); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketStable)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &boltStore{db: db}, nil
}

func (b *boltStore) Close() error { return b.db.Close() }

func u64(v uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], v)
	return k[:]
}

func (b *boltStore) FirstIndex() (uint64, error) {
	var idx uint64
	err := b.db.View(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bucketLogs).Cursor().First(); k != nil {
			idx = binary.BigEndian.Uint64(k)
		}
		return nil
	})
	return idx, err
}

func (b *boltStore) LastIndex() (uint64, error) {
	var idx uint64
	err := b.db.View(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bucketLogs).Cursor().Last(); k != nil {
			idx = binary.BigEndian.Uint64(k)
		}
		return nil
	})
	return idx, err
}

func (b *boltStore) GetLog(index uint64, log *raft.Log) error {
	return b.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLogs).Get(u64(index))
		if v == nil {
			return raft.ErrLogNotFound
		}
		return json.Unmarshal(v, log)
	})
}

func (b *boltStore) StoreLog(log *raft.Log) error { return b.StoreLogs([]*raft.Log{log}) }

func (b *boltStore) StoreLogs(logs []*raft.Log) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketLogs)
		for _, l := range logs {
			v, err := json.Marshal(l)
			if err != nil {
				return err
			}
			if err := bk.Put(u64(l.Index), v); err != nil {
				return err
			}
		}
		return nil
	})
}

func (b *boltStore) DeleteRange(min, max uint64) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketLogs).Cursor()
		for k, _ := c.Seek(u64(min)); k != nil; k, _ = c.Next() {
			if binary.BigEndian.Uint64(k) > max {
				break
			}
			if err := c.Delete(); err != nil {
				return err
			}
		}
		return nil
	})
}

var errKeyNotFound = errors.New("not found")

func (b *boltStore) Set(key, val []byte) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketStable).Put(key, val)
	})
}

func (b *boltStore) Get(key []byte) ([]byte, error) {
	var out []byte
	err := b.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketStable).Get(key)
		if v == nil {
			return errKeyNotFound
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

func (b *boltStore) SetUint64(key []byte, val uint64) error { return b.Set(key, u64(val)) }

func (b *boltStore) GetUint64(key []byte) (uint64, error) {
	v, err := b.Get(key)
	if err != nil {
		return 0, err
	}
	if len(v) != 8 {
		return 0, errors.New("stable store: bad uint64 value")
	}
	return binary.BigEndian.Uint64(v), nil
}
