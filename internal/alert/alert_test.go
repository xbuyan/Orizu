package alert

import (
	"errors"
	"testing"
	"time"

	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
)

func TestSealOpen_RoundTrip(t *testing.T) {
	guardianPub, guardianPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	now := time.Now().Truncate(time.Second) // JSON round-trips to second precision
	original := NewDuressAlert(now)

	sealed, err := Seal(original, guardianPub)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	opened, err := Open(sealed, guardianPub, guardianPriv)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if opened.Type != Duress {
		t.Errorf("expected Type=%q, got %q", Duress, opened.Type)
	}
	if !opened.Timestamp.Equal(now) {
		t.Errorf("expected Timestamp=%v, got %v", now, opened.Timestamp)
	}
}

func TestOpen_FailsWithWrongGuardianKey(t *testing.T) {
	guardianPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	_, wrongPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	sealed, err := Seal(NewDuressAlert(time.Now()), guardianPub)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Opening with the right public key but a mismatched private key must
	// fail — this stands in for a different guardian trying to read an
	// alert not intended for them.
	_, err = Open(sealed, guardianPub, wrongPriv)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestOpen_FailsOnCorruptedCiphertext(t *testing.T) {
	guardianPub, guardianPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	sealed, err := Seal(NewDuressAlert(time.Now()), guardianPub)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Flip a byte in the middle of the ciphertext.
	corrupted := append([]byte(nil), sealed...)
	corrupted[len(corrupted)/2] ^= 0xFF

	_, err = Open(corrupted, guardianPub, guardianPriv)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed for corrupted ciphertext, got %v", err)
	}
}

func TestSeal_ProducesDifferentCiphertextEachTime(t *testing.T) {
	guardianPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	a := NewDuressAlert(time.Now())

	sealed1, err := Seal(a, guardianPub)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	sealed2, err := Seal(a, guardianPub)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// SealAnonymous generates a fresh ephemeral keypair per call, so
	// identical plaintext sealed twice must not produce identical
	// ciphertext — otherwise a relay could correlate repeated alerts by
	// comparing bytes, defeating part of the point of anonymity.
	if string(sealed1) == string(sealed2) {
		t.Fatal("expected different ciphertext for repeated seals of identical plaintext")
	}
}

func TestNewDuressAlert_SetsTypeAndTimestamp(t *testing.T) {
	now := time.Now()
	a := NewDuressAlert(now)
	if a.Type != Duress {
		t.Errorf("expected Type=%q, got %q", Duress, a.Type)
	}
	if !a.Timestamp.Equal(now) {
		t.Errorf("expected Timestamp=%v, got %v", now, a.Timestamp)
	}
}