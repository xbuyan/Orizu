// Package alert constructs and seals Orizu's duress notification.
//
// The alert is encrypted to each guardian's public key using NaCl's
// anonymous sealed box (golang.org/x/crypto/nacl/box), an audited primitive
// chosen deliberately over hand-rolled crypto — consistent with Kinga and
// Aegis's preference for audited libraries.
//
// The anonymous sealed box property matters here specifically: the relay
// server that stores and forwards these blobs (see the relay package) must
// learn nothing from them. SealAnonymous embeds no sender identity in the
// ciphertext, so even if the relay is seized or subpoenaed, it can hand
// over only opaque bytes meaningless without a guardian's private key —
// not who sent an alert, not when it was truly created beyond what's
// inside the ciphertext, and not that it is a duress signal versus any
// other message.
package alert

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Type identifies the kind of alert. Only Duress exists today; the type is
// still encoded (inside the encrypted payload, never in the clear) so the
// format can carry other alert kinds later without a breaking change.
type Type string

// Duress is the only alert type currently defined.
const Duress Type = "duress"

// Alert is the plaintext payload, sealed before it ever leaves the device.
type Alert struct {
	Type      Type      `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

// Sentinel errors returned by this package.
var (
	ErrDecryptionFailed = errors.New("alert: failed to open sealed alert (wrong key or corrupted data)")
)

// Seal encodes a into JSON and encrypts it to guardianPubKey using an
// anonymous sealed box. The returned bytes are safe to hand to an untrusted
// relay: they reveal nothing about their contents or sender.
func Seal(a Alert, guardianPubKey *[32]byte) ([]byte, error) {
	plaintext, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return box.SealAnonymous(nil, plaintext, guardianPubKey, rand.Reader)
}

// NewDuressAlert builds a Duress-type Alert stamped with the given time.
// Kept as a small helper so callers (e.g. cmd/orizu) don't construct the
// struct by hand and risk typo'ing the Type field.
func NewDuressAlert(now time.Time) Alert {
	return Alert{Type: Duress, Timestamp: now}
}

// Open decrypts a sealed alert using the guardian's key pair. This runs on
// the guardian's side, never on the relay or the owner's device.
func Open(sealed []byte, guardianPubKey, guardianPrivKey *[32]byte) (Alert, error) {
	plaintext, ok := box.OpenAnonymous(nil, sealed, guardianPubKey, guardianPrivKey)
	if !ok {
		return Alert{}, ErrDecryptionFailed
	}

	var a Alert
	if err := json.Unmarshal(plaintext, &a); err != nil {
		return Alert{}, err
	}
	return a, nil
}