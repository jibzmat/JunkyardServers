// Package shamir splits a secret into n shares so that any t of them
// rebuild it and fewer reveal nothing (Shamir's scheme over GF(2^8)).
package shamir

import (
	"crypto/rand"
	"errors"
)

// Field arithmetic in GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1,
// using log/exp tables for generator 3.
var expT, logT [256]byte

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		expT[i] = x
		logT[x] = byte(i)
		// x *= 3, i.e. x ^ (x*2)
		hi := x & 0x80
		x2 := x << 1
		if hi != 0 {
			x2 ^= 0x1b
		}
		x ^= x2
	}
	expT[255] = expT[0]
}

func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expT[(int(logT[a])+int(logT[b]))%255]
}

func div(a, b byte) byte {
	if a == 0 {
		return 0
	}
	return expT[(int(logT[a])-int(logT[b])+255)%255]
}

// Split returns n shares of secret, any t of which rebuild it. Each share is
// len(secret)+1 bytes: the evaluation point, then the values.
func Split(secret []byte, n, t int) ([][]byte, error) {
	if t < 1 || n < t || n > 255 {
		return nil, errors.New("shamir: need 1 <= t <= n <= 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("shamir: empty secret")
	}
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][0] = byte(i + 1) // x = 1..n; never 0, which is the secret
	}
	coef := make([]byte, t)
	for j, s := range secret {
		coef[0] = s
		if _, err := rand.Read(coef[1:]); err != nil {
			return nil, err
		}
		for i := range shares {
			x := shares[i][0]
			// Horner's rule.
			var y byte
			for k := t - 1; k >= 0; k-- {
				y = mul(y, x) ^ coef[k]
			}
			shares[i][j+1] = y
		}
	}
	return shares, nil
}

// Combine rebuilds the secret from t or more shares by Lagrange
// interpolation at x = 0. With fewer than t shares it returns garbage, so
// callers check the result (for example against a sealed test value).
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("shamir: no shares")
	}
	size := len(shares[0])
	seen := map[byte]bool{}
	for _, s := range shares {
		if len(s) != size || size < 2 || s[0] == 0 || seen[s[0]] {
			return nil, errors.New("shamir: malformed or duplicate shares")
		}
		seen[s[0]] = true
	}
	secret := make([]byte, size-1)
	for i, si := range shares {
		// Lagrange basis at 0: prod over j != i of x_j / (x_j - x_i);
		// subtraction is xor in GF(2^8).
		basis := byte(1)
		for j, sj := range shares {
			if i != j {
				basis = mul(basis, div(sj[0], sj[0]^si[0]))
			}
		}
		for k := range secret {
			secret[k] ^= mul(si[k+1], basis)
		}
	}
	return secret, nil
}
