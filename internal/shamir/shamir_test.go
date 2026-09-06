package shamir

import (
	"bytes"
	"testing"
)

// TestSplit_ProducesCorrectShareCount verifies Split produces exactly
// shareCount shares, each with a distinct nonzero x-coordinate and a
// y-value slice matching the secret's length.
func TestSplit_ProducesCorrectShareCount(t *testing.T) {
	secret := []byte("0123456789ABCDEF") // 16 bytes, matches Kinga's entropy size
	shares, err := Split(secret)
	if err != nil {
		t.Fatalf("Split() returned unexpected error: %v", err)
	}
	if len(shares) != shareCount {
		t.Fatalf("Split() returned %d shares, want %d", len(shares), shareCount)
	}
	seen := make(map[byte]bool)
	for _, s := range shares {
		if s.X == 0 {
			t.Fatal("Split() produced a share with x=0, which would leak the secret directly")
		}
		if seen[s.X] {
			t.Fatalf("Split() produced duplicate x-coordinate %d", s.X)
		}
		seen[s.X] = true
		if len(s.YVal) != len(secret) {
			t.Fatalf("share YVal length = %d, want %d", len(s.YVal), len(secret))
		}
	}
}

// TestSplit_RejectsEmptySecret enforces the input boundary.
func TestSplit_RejectsEmptySecret(t *testing.T) {
	_, err := Split([]byte{})
	if err == nil {
		t.Fatal("Split(empty) succeeded, want error")
	}
}

// TestCombine_AllThreeSharesReconstruct is the core correctness property
// for Orizu's 3-of-3 threshold: combining all three shares must reproduce
// the exact original secret. Unlike Kinga's 2-of-3, no partial subset of
// shares is sufficient here — see TestCombine_RejectsFewerThanThreeShares.
func TestCombine_AllThreeSharesReconstruct(t *testing.T) {
	secret := []byte("0123456789ABCDEF")
	shares, err := Split(secret)
	if err != nil {
		t.Fatalf("Split() returned unexpected error: %v", err)
	}

	got, err := Combine(shares)
	if err != nil {
		t.Fatalf("Combine(all 3 shares) returned unexpected error: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Combine(all 3 shares) = %x, want %x", got, secret)
	}
}

// TestCombine_RejectsFewerThanThreeShares proves that under Orizu's 3-of-3
// threshold, any two guardians acting alone — without the third — cannot
// reconstruct the secret. This is the property the whole 3-of-3 design
// decision rests on.
func TestCombine_RejectsFewerThanThreeShares(t *testing.T) {
	secret := []byte("0123456789ABCDEF")
	shares, err := Split(secret)
	if err != nil {
		t.Fatalf("Split() returned unexpected error: %v", err)
	}

	pairs := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, p := range pairs {
		_, err := Combine([]Share{shares[p[0]], shares[p[1]]})
		if err == nil {
			t.Fatalf("Combine(shares[%d], shares[%d]) succeeded with only 2 of 3 shares — 3-of-3 threshold violated", p[0], p[1])
		}
	}
}

// TestCombine_RejectsWrongShareCount proves the explicit threshold check
// fires regardless of whether too few or too many shares are supplied —
// this is the check discussed at length: threshold must never be inferred
// from len(shares).
func TestCombine_RejectsWrongShareCount(t *testing.T) {
	secret := []byte("0123456789ABCDEF")
	shares, err := Split(secret)
	if err != nil {
		t.Fatalf("Split() returned unexpected error: %v", err)
	}

	t.Run("zero shares", func(t *testing.T) {
		_, err := Combine(nil)
		if err == nil {
			t.Fatal("Combine(0 shares) succeeded, want error")
		}
	})
	t.Run("one share", func(t *testing.T) {
		_, err := Combine(shares[:1])
		if err == nil {
			t.Fatal("Combine(1 share) succeeded, want error")
		}
	})
	t.Run("two shares", func(t *testing.T) {
		_, err := Combine(shares[:2])
		if err == nil {
			t.Fatal("Combine(2 shares) succeeded, want error — threshold is 3, not 2")
		}
	})
	t.Run("three shares succeeds", func(t *testing.T) {
		_, err := Combine(shares)
		if err != nil {
			t.Fatalf("Combine(3 shares) returned unexpected error: %v — threshold is exactly 3", err)
		}
	})
}

// TestCombine_OneShareRevealsNothing is a practical (not formal-proof)
// sanity check on the information-theoretic guarantee: a single share's
// y-values, taken alone, must not equal the original secret bytes. This
// doesn't prove the security property (that requires the mathematical
// argument, not a unit test) — it's a tripwire against a catastrophic
// implementation bug like x=0 or an unshuffled constant term.
func TestCombine_OneShareRevealsNothing(t *testing.T) {
	secret := []byte("0123456789ABCDEF")
	shares, err := Split(secret)
	if err != nil {
		t.Fatalf("Split() returned unexpected error: %v", err)
	}
	for _, s := range shares {
		if bytes.Equal(s.YVal, secret) {
			t.Fatalf("share x=%d has YVal equal to the secret itself — catastrophic leak", s.X)
		}
	}
}

// TestCombine_DetectsCorruptedShare proves Combine doesn't crash on a
// corrupted share, but also documents (per Part 3.6 of the design) that
// Combine alone cannot detect the corruption — it will still return some
// output, given the full threshold count. Integrity detection happens one
// layer up, not here. This test exists to make that boundary explicit
// rather than accidentally assumed.
func TestCombine_DetectsCorruptedShare(t *testing.T) {
	secret := []byte("0123456789ABCDEF")
	shares, err := Split(secret)
	if err != nil {
		t.Fatalf("Split() returned unexpected error: %v", err)
	}

	corrupted := shares[0]
	corrupted.YVal = append([]byte(nil), corrupted.YVal...) // copy before mutating
	corrupted.YVal[0] ^= 0xFF                                // flip bits in first byte

	got, err := Combine([]Share{corrupted, shares[1], shares[2]})
	if err != nil {
		t.Fatalf("Combine() with corrupted share returned unexpected error: %v (expected: no error, but wrong output)", err)
	}
	if bytes.Equal(got, secret) {
		t.Fatal("Combine() with a corrupted share coincidentally reproduced the original secret — flawed test setup, pick a different corruption")
	}
	// got != secret, and no error was returned — this is the documented,
	// expected behavior: Shamir provides no integrity check on its own.
}

// TestCombine_RejectsMismatchedShareLengths guards against combining
// shares from different secrets (or corrupted length data).
func TestCombine_RejectsMismatchedShareLengths(t *testing.T) {
	a := Share{X: 1, YVal: []byte{1, 2, 3}}
	b := Share{X: 2, YVal: []byte{1, 2}}
	c := Share{X: 3, YVal: []byte{1, 2, 3}}
	_, err := Combine([]Share{a, b, c})
	if err == nil {
		t.Fatal("Combine() with mismatched YVal lengths succeeded, want error")
	}
}

// TestCombine_RejectsDuplicateXCoordinate guards against two shares that
// happen to carry the same x-coordinate (e.g. a bug upstream, or two
// copies of the same share presented as if they were different).
func TestCombine_RejectsDuplicateXCoordinate(t *testing.T) {
	a := Share{X: 1, YVal: []byte{1, 2, 3}}
	b := Share{X: 1, YVal: []byte{4, 5, 6}}
	c := Share{X: 2, YVal: []byte{7, 8, 9}}
	_, err := Combine([]Share{a, b, c})
	if err == nil {
		t.Fatal("Combine() with duplicate x-coordinates succeeded, want error")
	}
}

// TestGFArithmetic_KnownValues sanity-checks the field arithmetic
// primitives against hand-computable values, independent of Split/Combine.
// If these fail, the bug is in the field layer, not the Shamir logic above it.
func TestGFArithmetic_KnownValues(t *testing.T) {
	// Addition is XOR — trivially checkable.
	if got := gfAdd(0x53, 0xCA); got != (0x53 ^ 0xCA) {
		t.Fatalf("gfAdd(0x53, 0xCA) = %x, want %x", got, 0x53^0xCA)
	}
	// Multiplicative identity: a * 1 == a for any a.
	for _, a := range []byte{0x00, 0x01, 0x53, 0xFF} {
		if got := gfMul(a, 1); got != a {
			t.Fatalf("gfMul(%x, 1) = %x, want %x", a, got, a)
		}
	}
	// a * 0 == 0 for any a.
	if got := gfMul(0x53, 0); got != 0 {
		t.Fatalf("gfMul(0x53, 0) = %x, want 0", got)
	}
	// Inverse round-trip: a * inverse(a) == 1 for all nonzero a.
	for a := 1; a < 256; a++ {
		inv := gfInverse(byte(a))
		if got := gfMul(byte(a), inv); got != 1 {
			t.Fatalf("gfMul(%x, gfInverse(%x)) = %x, want 1", a, a, got)
		}
	}
}

