// Package storage turns objects into encrypted, erasure-coded shards spread
// across storage nodes, and back.
//
// Each object gets its own random data key. The object is cut into chunks;
// each chunk is sealed with XChaCha20-Poly1305 (nonce = per-object prefix ||
// chunk index, additional data = object ID || chunk index, so chunks can't be
// swapped or replayed into another object), then Reed-Solomon coded into
// k data + m parity shards. Storage nodes only ever see shards of ciphertext,
// named by their SHA-256.
package storage

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChunkSize is the plaintext size of every chunk except the last.
const ChunkSize = 4 << 20

// Overhead is what sealing adds to a chunk.
const Overhead = chacha20poly1305.Overhead

// ObjectKey is an object's data key and nonce prefix.
type ObjectKey struct {
	Key         [chacha20poly1305.KeySize]byte
	NoncePrefix [16]byte
}

// NewObjectKey returns a random key.
func NewObjectKey() (ObjectKey, error) {
	var k ObjectKey
	if _, err := rand.Read(k.Key[:]); err != nil {
		return k, err
	}
	if _, err := rand.Read(k.NoncePrefix[:]); err != nil {
		return k, err
	}
	return k, nil
}

// Bytes serialises the key (for wrapping by the key service).
func (k ObjectKey) Bytes() []byte {
	out := make([]byte, 0, len(k.Key)+len(k.NoncePrefix))
	out = append(out, k.Key[:]...)
	return append(out, k.NoncePrefix[:]...)
}

// ObjectKeyFromBytes parses a key serialised with Bytes.
func ObjectKeyFromBytes(b []byte) (ObjectKey, error) {
	var k ObjectKey
	if len(b) != len(k.Key)+len(k.NoncePrefix) {
		return k, errors.New("storage: bad object key length")
	}
	copy(k.Key[:], b)
	copy(k.NoncePrefix[:], b[len(k.Key):])
	return k, nil
}

func nonceAndAD(k ObjectKey, objectID string, idx uint64) ([]byte, []byte) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(nonce, k.NoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[16:], idx)
	ad := make([]byte, 0, len(objectID)+8)
	ad = append(ad, objectID...)
	ad = binary.BigEndian.AppendUint64(ad, idx)
	return nonce, ad
}

// SealChunk encrypts chunk idx of an object.
func SealChunk(k ObjectKey, objectID string, idx uint64, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.Key[:])
	if err != nil {
		return nil, err
	}
	nonce, ad := nonceAndAD(k, objectID, idx)
	return aead.Seal(nil, nonce, plain, ad), nil
}

// OpenChunk decrypts and authenticates chunk idx of an object.
func OpenChunk(k ObjectKey, objectID string, idx uint64, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.Key[:])
	if err != nil {
		return nil, err
	}
	nonce, ad := nonceAndAD(k, objectID, idx)
	plain, err := aead.Open(nil, nonce, sealed, ad)
	if err != nil {
		return nil, errors.New("storage: chunk failed authentication")
	}
	return plain, nil
}
