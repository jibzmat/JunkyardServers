// Package token implements join tokens. A token tells a new node where the
// control plane is and which CA to pin, and carries a one-time secret the
// control plane checks before it signs the node's certificate.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const prefix = "jy1."

// Token is what the operator hands to a new node.
type Token struct {
	Control       string `json:"c"` // control plane address, host:port
	CAFingerprint string `json:"f"` // hex SHA-256 of the CA certificate
	ID            string `json:"i"`
	Secret        string `json:"s"`
}

// String encodes the token for copy and paste.
func (t Token) String() string {
	b, _ := json.Marshal(t)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Parse decodes a token string.
func Parse(s string) (Token, error) {
	var t Token
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, prefix) {
		return t, errors.New("token: not a junkyard join token")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return t, errors.New("token: bad encoding")
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return t, errors.New("token: bad payload")
	}
	if t.Control == "" || t.CAFingerprint == "" || t.ID == "" || t.Secret == "" {
		return t, errors.New("token: missing fields")
	}
	return t, nil
}

// Record is the control plane's copy of a token. Only a hash of the secret is
// kept, so a leaked state file cannot be used to join.
type Record struct {
	ID         string    `json:"id"`
	SecretHash string    `json:"secret_hash"`
	Trusted    bool      `json:"trusted"` // nodes joining with it are owner-trusted
	Expires    time.Time `json:"expires"`
	MaxUses    int       `json:"max_uses"` // 0 means unlimited
	Uses       int       `json:"uses"`
}

// New creates a token and its record.
func New(control, caFingerprint string, trusted bool, ttl time.Duration, maxUses int) (Token, Record, error) {
	id, err := randHex(6)
	if err != nil {
		return Token{}, Record{}, err
	}
	secret, err := randHex(16)
	if err != nil {
		return Token{}, Record{}, err
	}
	t := Token{Control: control, CAFingerprint: caFingerprint, ID: id, Secret: secret}
	r := Record{
		ID:         id,
		SecretHash: hashSecret(secret),
		Trusted:    trusted,
		Expires:    time.Now().Add(ttl),
		MaxUses:    maxUses,
	}
	return t, r, nil
}

// Errors returned by Check.
var (
	ErrInvalid   = errors.New("token: invalid")
	ErrExpired   = errors.New("token: expired")
	ErrExhausted = errors.New("token: already used")
)

// Check validates a presented secret against the record at time now. It does
// not count the use; the caller increments Uses once the join succeeds.
func (r *Record) Check(secret string, now time.Time) error {
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(r.SecretHash)) != 1 {
		return ErrInvalid
	}
	if now.After(r.Expires) {
		return ErrExpired
	}
	if r.MaxUses > 0 && r.Uses >= r.MaxUses {
		return ErrExhausted
	}
	return nil
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
