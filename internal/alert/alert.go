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

// Duress is signaled when the owner enters their duress passphrase.
const Duress Type = "duress"

// Liveness is signaled on every ordinary successful check-in (including a
// duress one — see NewDuressAlert). It's what lets a guardian detect
// total silence, not just an active duress signal: if no Liveness alert
// arrives within checkin.Interval+GracePeriod, the owner is overdue by
// the same definition their own device would compute, but observed
// independently by guardians rather than relying on that device at all.
const Liveness Type = "liveness"

// Share carries one guardian's Shamir share, delivered once during
// initial setup (see cmd/orizu's distribute step). Unlike Duress and
// Liveness, which are recurring status signals with no secret content,
// a Share alert's Data field carries part of the actual secret being
// protected. It receives no different treatment from the relay's point
// of view — the same anonymous sealed box gives the same confidentiality
// guarantee regardless of alert type — but callers should be more
// deliberate about retention: a Share alert should generally be fetched,
// recorded by the guardian, and not left sitting on the relay
// indefinitely, unlike a routine Liveness ping.
const Share Type = "share"

// Alert is the plaintext payload, sealed before it ever leaves the device.
// Data is only populated for Share alerts; it's empty for Duress and
// Liveness, which carry no payload beyond their type and timestamp.
type Alert struct {
	Type      Type      `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Data      []byte    `json:"data,omitempty"`
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

// NewLivenessAlert builds a Liveness-type Alert stamped with the given
// time. Sent on every ordinary check-in so guardians can detect an owner
// going silent, not just an active duress signal.
func NewLivenessAlert(now time.Time) Alert {
	return Alert{Type: Liveness, Timestamp: now}
}

// NewShareAlert builds a Share-type Alert carrying one Shamir share's
// serialized bytes as Data. Delivered once per guardian during setup, not
// repeated like Duress or Liveness.
func NewShareAlert(data []byte, now time.Time) Alert {
	return Alert{Type: Share, Timestamp: now, Data: data}
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

