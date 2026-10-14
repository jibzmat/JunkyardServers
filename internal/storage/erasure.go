package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

// Default coding: survives the loss of any 2 shards, 1.5x storage overhead.
const (
	DefaultDataShards   = 4
	DefaultParityShards = 2
)

// ChooseCoding picks k data + m parity shards for a cluster with n storage
// nodes: 4+2 once there are 6 nodes, otherwise as much parity as the node
// count allows while keeping every shard on its own node.
func ChooseCoding(n int) (k, m int) {
	switch {
	case n >= DefaultDataShards+DefaultParityShards:
		return DefaultDataShards, DefaultParityShards
	case n == 5:
		return 3, 2
	case n == 4:
		return 2, 2
	case n == 3:
		return 2, 1
	case n == 2:
		return 1, 1
	default:
		return 1, 0
	}
}

// Encode splits sealed into k data + m parity shards of equal size.
func Encode(sealed []byte, k, m int) ([][]byte, error) {
	if m == 0 && k == 1 {
		return [][]byte{append([]byte(nil), sealed...)}, nil
	}
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, err
	}
	shards, err := enc.Split(sealed)
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

// Decode rebuilds the sealed chunk of length size from shards, where missing
// shards are nil. At least k shards must be present.
func Decode(shards [][]byte, k, m, size int) ([]byte, error) {
	if len(shards) != k+m {
		return nil, fmt.Errorf("storage: want %d shards, got %d", k+m, len(shards))
	}
	if m == 0 && k == 1 {
		if shards[0] == nil || len(shards[0]) < size {
			return nil, errors.New("storage: shard missing")
		}
		return shards[0][:size], nil
	}
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, err
	}
	if err := enc.ReconstructData(shards); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := enc.Join(&buf, shards, size); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ShardHash names a shard by the SHA-256 of its bytes.
func ShardHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ValidHash reports whether s looks like a shard hash.
func ValidHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

var errHashMismatch = errors.New("storage: shard content does not match its hash")
