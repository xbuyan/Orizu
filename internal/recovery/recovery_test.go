package recovery

import (
	"bytes"
	"testing"

	"github.com/xbuyan/orizu/internal/shamir"
)

func buildValidPayloads(t *testing.T, secret []byte) []SharePayload {
	t.Helper()
	shares, err := shamir.Split(secret)
	if err != nil {
		t.Fatalf("shamir.Split failed: %v", err)
	}
	fp := Fingerprint(secret)

	payloads := make([]SharePayload, len(shares))
	for i, s := range shares {
		payloads[i] = SharePayload{Share: s, Fingerprint: fp}
	}
	return payloads
}

func TestRecover_SuccessfulRoundTrip(t *testing.T) {
	secret := []byte("0123456789ABCDEF0123456789ABCDE") // 32 bytes
	payloads := buildValidPayloads(t, secret)

	got, err := Recover(payloads)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Recover() = %x, want %x", got, secret)
	}
}

func TestRecover_RejectsWrongPayloadCount(t *testing.T) {
	secret := []byte("0123456789ABCDEF0123456789ABCDE")
	payloads := buildValidPayloads(t, secret)

	cases := [][]SharePayload{
		nil,
		{},
		payloads[:1],
		payloads[:2],
	}
	for _, c := range cases {
		if _, err := Recover(c); err != ErrWrongPayloadCount {
			t.Errorf("Recover(%d payloads): expected ErrWrongPayloadCount, got %v", len(c), err)
		}
	}
}

func TestRecover_RejectsFingerprintDisagreement(t *testing.T) {
	secret := []byte("0123456789ABCDEF0123456789ABCDE")
	payloads := buildValidPayloads(t, secret)

	// Tamper with one payload's fingerprint, as if it came from a
	// different distribution or was corrupted independently of its share.
	tampered := append([]byte(nil), payloads[1].Fingerprint...)
	tampered[0] ^= 0xFF
	payloads[1].Fingerprint = tampered

	if _, err := Recover(payloads); err != ErrFingerprintDisagreement {
		t.Fatalf("expected ErrFingerprintDisagreement, got %v", err)
	}
}

func TestRecover_RejectsCorruptedShare(t *testing.T) {
	secret := []byte("0123456789ABCDEF0123456789ABCDE")
	payloads := buildValidPayloads(t, secret)

	// Corrupt one share's y-values directly. All three fingerprints still
	// agree with each other (they were computed from the real secret
	// before corruption), so this must be caught by the second check —
	// the reconstructed secret not matching the agreed fingerprint —
	// not the first.
	corruptedYVal := append([]byte(nil), payloads[0].Share.YVal...)
	corruptedYVal[0] ^= 0xFF
	payloads[0].Share.YVal = corruptedYVal

	if _, err := Recover(payloads); err != ErrFingerprintMismatch {
		t.Fatalf("expected ErrFingerprintMismatch, got %v", err)
	}
}

func TestRecover_PropagatesShamirCombineErrors(t *testing.T) {
	secret := []byte("0123456789ABCDEF0123456789ABCDE")
	payloads := buildValidPayloads(t, secret)

	// Duplicate x-coordinates: shamir.Combine itself rejects this before
	// any fingerprint check runs.
	payloads[1].Share.X = payloads[0].Share.X

	_, err := Recover(payloads)
	if err == nil {
		t.Fatal("expected an error for duplicate share x-coordinates")
	}
	if err == ErrFingerprintDisagreement || err == ErrFingerprintMismatch {
		t.Fatalf("expected the underlying shamir.Combine error to propagate, got %v", err)
	}
}

func TestFingerprint_DeterministicForSameSecret(t *testing.T) {
	secret := []byte("some-secret-bytes")
	fp1 := Fingerprint(secret)
	fp2 := Fingerprint(secret)
	if !bytes.Equal(fp1, fp2) {
		t.Fatal("expected Fingerprint to be deterministic for the same input")
	}
}

func TestFingerprint_DiffersForDifferentSecrets(t *testing.T) {
	fp1 := Fingerprint([]byte("secret-one"))
	fp2 := Fingerprint([]byte("secret-two"))
	if bytes.Equal(fp1, fp2) {
		t.Fatal("expected different secrets to produce different fingerprints")
	}
}

