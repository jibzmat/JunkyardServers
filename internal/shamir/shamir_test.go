package shamir

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitCombine(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	for _, c := range []struct{ n, t int }{{1, 1}, {3, 2}, {5, 3}, {7, 4}} {
		shares, err := Split(secret, c.n, c.t)
		if err != nil {
			t.Fatal(err)
		}
		// Every window of t consecutive shares works.
		for start := 0; start+c.t <= c.n; start++ {
			got, err := Combine(shares[start : start+c.t])
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("%d of %d from %d: wrong secret", c.t, c.n, start)
			}
		}
		if c.t > 1 {
			if got, _ := Combine(shares[:c.t-1]); bytes.Equal(got, secret) {
				t.Fatalf("%d shares of a %d-threshold split rebuilt the secret", c.t-1, c.t)
			}
		}
	}
}

func TestFieldInverse(t *testing.T) {
	for a := 1; a < 256; a++ {
		if mul(byte(a), div(1, byte(a))) != 1 {
			t.Fatalf("no inverse for %d", a)
		}
	}
}

func TestBadShares(t *testing.T) {
	shares, _ := Split([]byte("k"), 3, 2)
	if _, err := Combine([][]byte{shares[0], shares[0]}); err == nil {
		t.Fatal("duplicate shares accepted")
	}
	if _, err := Split([]byte("k"), 2, 3); err == nil {
		t.Fatal("t > n accepted")
	}
}
