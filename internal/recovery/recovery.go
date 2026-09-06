// Package recovery implements the guardian-side ceremony that combines
// all three Shamir shares back into the original release secret.
//
// Shamir's math alone provides no integrity check: combining a corrupted
// or mismatched share still produces output, just silently wrong output
// (see internal/shamir's TestCombine_DetectsCorruptedShare, which
// documents this explicitly). Kinga hit exactly this problem with BIP39
// checksums — a checksum recomputed from bad input always "validates"
// against itself, so it can't catch corruption on its own. The fix there
// was an independent fingerprint of the original entropy, checked before
// trusting a reconstruction. This package applies the same fix here: a
// SHA-256 fingerprint of the secret, generated once at distribution time
// and carried alongside every guardian's share, checked at recovery time
// before the reconstructed secret is ever trusted or used.
package recovery

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/xbuyan/orizu/internal/shamir"
)

// SharePayload is what each guardian actually receives (via a Share
// alert) and stores: their own Shamir share, plus the secret's public
// fingerprint. The fingerprint is safe to distribute in the open — SHA-256
// is preimage-resistant, so it reveals nothing about the secret itself —
// but lets Recover detect a bad reconstruction instead of silently
// returning wrong bytes.
type SharePayload struct {
	Share       shamir.Share `json:"share"`
	Fingerprint []byte       `json:"fingerprint"`
}

// Fingerprint returns the SHA-256 fingerprint of secret, computed once at
// distribution time (see cmd/orizu's distribute step) and embedded in
// every guardian's SharePayload.
func Fingerprint(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// Sentinel errors returned by this package.
var (
	// ErrWrongPayloadCount is returned when Recover is given anything
	// other than exactly 3 payloads, matching Orizu's 3-of-3 threshold.
	ErrWrongPayloadCount = errors.New("recovery: exactly 3 share payloads are required")

	// ErrFingerprintDisagreement is returned when the supplied payloads
	// don't all carry the same fingerprint — a sign of tampering, a
	// mismatched setup (shares from two different distributions), or a
	// guardian's payload being corrupted independently of their share.
	ErrFingerprintDisagreement = errors.New("recovery: guardians' fingerprints do not all match — possible tampering or mismatched setup")

	// ErrFingerprintMismatch is returned when the reconstructed secret's
	// own fingerprint doesn't match the one the guardians agreed on —
	// meaning at least one share was corrupted or the wrong shares were
	// combined, even though they all had matching fingerprints going in.
	ErrFingerprintMismatch = errors.New("recovery: reconstructed secret does not match the expected fingerprint — a share may be corrupted or wrong")
)

// Recover reconstructs the original secret from all three guardians'
// SharePayloads. Before returning a secret, it verifies:
//  1. All three payloads carry an identical fingerprint — the guardians
//     are recovering the same secret, not silently combining shares from
//     different setups.
//  2. The reconstructed secret's own fingerprint matches that agreed
//     value — the combination actually produced the right secret, not
//     wrong bytes from a corrupted share.
//
// Either check failing returns an error rather than a secret nobody
// should trust.
func Recover(payloads []SharePayload) ([]byte, error) {
	if len(payloads) != 3 {
		return nil, ErrWrongPayloadCount
	}

	expected := payloads[0].Fingerprint
	for _, p := range payloads[1:] {
		if !bytes.Equal(p.Fingerprint, expected) {
			return nil, ErrFingerprintDisagreement
		}
	}

	shares := make([]shamir.Share, len(payloads))
	for i, p := range payloads {
		shares[i] = p.Share
	}

	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("recovery: combining shares: %w", err)
	}

	if !bytes.Equal(Fingerprint(secret), expected) {
		return nil, ErrFingerprintMismatch
	}

	return secret, nil
}

