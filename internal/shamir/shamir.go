package shamir

import (
	"crypto/rand"
	"fmt"
)

const (
	shareCount = 3 //n: total shares generated
	threshold  = 2 // k: shares required to reconstruct
)

// share is one point (x, y) on the secret polynomial, for a single byte
// of the original secret. A full share for multi-byte secret is a
// slice of these y-values sharing the same x- coordinate

type Share struct {
	X    byte
	YVal []byte // one y-value per byte of the original secret
}

// Split divides secret into shareCount shares, any threshold of which
// can reconstruct the original secret exactly. Each byte of the secret
// is split independently using its own random degree-(threshold-1)
// polynomial with that byte as the constant term.
// gfAdd returns a + b in GF(256). Addition in this field is XOR —
// there is no carrying, which is a direct consequence of GF(256)
// being built from GF(2) (bits) rather than base-10 digits.
func gfAdd(a, b byte) byte {
	return a ^ b
}

// gfMul returns a * b in GF(256), using the standard Rijndael/AES
// reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B). This is the
// same field construction used by hashicorp/vault's shamir package
// and by AES itself — a long-audited standard, not invented here.
func gfMul(a, b byte) byte {
	var result byte
	for b > 0 {
		if b&1 != 0 {
			result ^= a
		}
		highBitSet := a & 0x80
		a <<= 1
		if highBitSet != 0 {
			a ^= 0x1B // reduction step: x^8 = x^4 + x^3 + x + 1 (mod 2)
		}
		b >>= 1
	}
	return result
}

// evalPolynomial evaluates f(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
// entirely in GF(256), using Horner's method to avoid computing large
// powers of x directly.
func evalPolynomial(coeffs []byte, x byte) byte {
	result := byte(0)
	// Horner's method, evaluated from the highest-degree coefficient down:
	// ((c_n * x + c_{n-1}) * x + c_{n-2}) * x + ... + c_0
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gfAdd(gfMul(result, x), coeffs[i])
	}
	return result
}
func Split(secret []byte) ([]Share, error) {

	if len(secret) == 0 {

		return nil, fmt.Errorf("shamir: secret must not be empty")
	}

	shares := make([]Share, shareCount)

	for i := 0; i < shareCount; i++ {

		shares[i] = Share{

			X:    byte(i + 1), // x=0 is reserved for the secret itself, never used as a share
			YVal: make([]byte, len(secret)),
		}
	}

	for byteIdx, secretByte := range secret {
		// Build a random degree-(threshold-1) polynomial for this byte:
		// f(x) = secretByte + c1*x + c2*x^2 + ... (threshold-1 random coefficients)
		coeffs := make([]byte, threshold)
		coeffs[0] = secretByte // constant term = the secret byte
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("shamir: failed to generate random polynomial coefficients: %w", err)
		}

		for i := 0; i < shareCount; i++ {
			x := shares[i].X
			shares[i].YVal[byteIdx] = evalPolynomial(coeffs, x)
		}
	}

	return shares, nil
}

// gfInverse returns the multiplicative inverse of a in GF(256), i.e. the
// unique b such that gfMul(a, b) == 1. Panics on a == 0, which has no
// inverse — callers must never pass 0 (see Combine's distinct-x-coordinate
// check below, which guarantees this).
func gfInverse(a byte) byte {
	if a == 0 {
		panic("shamir: attempted to invert zero in GF(256)")
	}
	// GF(256)* is cyclic of order 255, so a^254 == a^-1 for all nonzero a
	// (Fermat's little theorem analogue: a^255 == 1, so a^254 == a^-1).
	// Computed by repeated squaring/multiplication rather than a log table,
	// trading a little speed for fewer moving parts in a first hand-rolled pass.
	result := byte(1)
	base := a
	exp := 254
	for exp > 0 {
		if exp&1 == 1 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
		exp >>= 1
	}
	return result
}

// Combine reconstructs the original secret from exactly `threshold` shares
// using Lagrange interpolation evaluated at x=0, entirely in GF(256).
// It is a hard error to supply anything other than exactly `threshold`
// shares — see the design discussion on why threshold must be checked
// explicitly rather than inferred from share count.
func Combine(shares []Share) ([]byte, error) {
	if len(shares) != threshold {
		return nil, fmt.Errorf("shamir: combine requires exactly %d shares, got %d", threshold, len(shares))
	}

	seen := make(map[byte]bool, threshold)
	secretLen := len(shares[0].YVal)
	for _, s := range shares {
		if seen[s.X] {
			return nil, fmt.Errorf("shamir: duplicate share x-coordinate %d", s.X)
		}
		seen[s.X] = true
		if s.X == 0 {
			return nil, fmt.Errorf("shamir: share x-coordinate must not be zero")
		}
		if len(s.YVal) != secretLen {
			return nil, fmt.Errorf("shamir: mismatched share lengths")
		}
	}

	secret := make([]byte, secretLen)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		var result byte
		for j, sj := range shares {
			// Lagrange basis term for this share, evaluated at x=0:
			// product over m != j of x_m / (x_m - x_j), all in GF(256)
			// (subtraction == addition == XOR in characteristic 2).
			num := byte(1)
			den := byte(1)
			for m, sm := range shares {
				if m == j {
					continue
				}
				num = gfMul(num, sm.X)
				den = gfMul(den, sm.X^sj.X) // sm.X - sj.X, i.e. XOR
			}
			term := gfMul(sj.YVal[byteIdx], gfMul(num, gfInverse(den)))
			result = gfAdd(result, term)
		}
		secret[byteIdx] = result
	}

	return secret, nil
}
