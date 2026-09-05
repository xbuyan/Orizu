// Package checkin implements Orizu's proof-of-life mechanism: a passphrase
// based check-in with a separate, outwardly-identical duress passphrase.
//
// Design decisions (see THREAT_MODEL.md for full rationale):
//   - Passphrase/PIN only, no second factor — chosen for field usability
//     under stress or limited connectivity, at the cost of not protecting
//     against an attacker who has captured both device and passphrase.
//   - A duress passphrase checks in identically from an observer's point of
//     view, but signals internally that the check-in was coerced. This
//     package only reports that signal (DuressDetected) — it does not send
//     any network alert itself; that is the caller's responsibility, kept
//     separate so this package has no network dependency and stays testable
//     in isolation.
//   - Check-in interval: 30 days, with a 7-day grace period before a missed
//     check-in is considered overdue (see IsOverdue).
package checkin

import (
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Interval is the required check-in cadence.
const Interval = 30 * 24 * time.Hour

// GracePeriod is the additional time allowed after Interval elapses before
// a check-in is considered overdue.
const GracePeriod = 7 * 24 * time.Hour

// Sentinel errors returned by this package.
var (
	// ErrEmptyPassphrase is returned when a passphrase or duress passphrase
	// is empty at creation time.
	ErrEmptyPassphrase = errors.New("checkin: passphrase must not be empty")

	// ErrSamePassphrase is returned when the normal and duress passphrases
	// are identical — they must be distinguishable or duress detection is
	// meaningless.
	ErrSamePassphrase = errors.New("checkin: duress passphrase must differ from normal passphrase")

	// ErrInvalidPassphrase is returned by Record when the supplied
	// passphrase matches neither the normal nor the duress hash.
	ErrInvalidPassphrase = errors.New("checkin: passphrase does not match")
)

// CheckIn holds the hashed credentials and check-in state for a single
// owner. It never stores plaintext passphrases.
type CheckIn struct {
	passphraseHash       []byte
	duressPassphraseHash []byte
	lastCheckIn          time.Time
}

// New creates a CheckIn from a normal passphrase and a duress passphrase.
// Both are hashed with bcrypt immediately; the plaintext values are not
// retained. lastCheckIn is initialized to now, so a freshly created switch
// starts in a checked-in state.
func New(passphrase, duressPassphrase string, now time.Time) (*CheckIn, error) {
	if passphrase == "" || duressPassphrase == "" {
		return nil, ErrEmptyPassphrase
	}
	if passphrase == duressPassphrase {
		return nil, ErrSamePassphrase
	}

	pHash, err := bcrypt.GenerateFromPassword([]byte(passphrase), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	dHash, err := bcrypt.GenerateFromPassword([]byte(duressPassphrase), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &CheckIn{
		passphraseHash:       pHash,
		duressPassphraseHash: dHash,
		lastCheckIn:          now,
	}, nil
}

// Result reports the outcome of a Record call.
type Result struct {
	// DuressDetected is true if the supplied passphrase matched the duress
	// hash rather than the normal one. The caller is responsible for acting
	// on this (e.g. silently notifying guardians) — this package performs
	// no network activity itself.
	DuressDetected bool
}

// Record verifies the supplied passphrase against both the normal and
// duress hashes. On a match against either, it updates lastCheckIn to now
// and returns a Result indicating whether the duress passphrase was used.
// On a match against neither, it returns ErrInvalidPassphrase and leaves
// lastCheckIn unchanged.
//
// Deliberately, both a normal and a duress match look identical to any
// caller that only inspects whether an error was returned — callers that
// need to react to duress must explicitly check Result.DuressDetected.
func (c *CheckIn) Record(passphrase string, now time.Time) (Result, error) {
	if bcrypt.CompareHashAndPassword(c.passphraseHash, []byte(passphrase)) == nil {
		c.lastCheckIn = now
		return Result{DuressDetected: false}, nil
	}
	if bcrypt.CompareHashAndPassword(c.duressPassphraseHash, []byte(passphrase)) == nil {
		c.lastCheckIn = now
		return Result{DuressDetected: true}, nil
	}
	return Result{}, ErrInvalidPassphrase
}

// LastCheckIn returns the time of the most recent successful check-in
// (normal or duress).
func (c *CheckIn) LastCheckIn() time.Time {
	return c.lastCheckIn
}

// IsOverdue reports whether, as of now, more than Interval+GracePeriod has
// elapsed since the last successful check-in. This is the condition Orizu's
// trigger logic watches for.
func (c *CheckIn) IsOverdue(now time.Time) bool {
	deadline := c.lastCheckIn.Add(Interval).Add(GracePeriod)
	return now.After(deadline)
}

// checkInJSON is the on-disk shape. It is safe to persist as-is: both
// hashes are bcrypt output, never plaintext passphrases. This lets a
// caller (e.g. cmd/orizu) save and reload a CheckIn's state across
// process restarts without this package needing any filesystem or
// network dependency itself.
type checkInJSON struct {
	PassphraseHash       []byte    `json:"passphrase_hash"`
	DuressPassphraseHash []byte    `json:"duress_passphrase_hash"`
	LastCheckIn          time.Time `json:"last_check_in"`
}

// MarshalJSON implements json.Marshaler, serializing the (already-hashed)
// credential state and last check-in time.
func (c *CheckIn) MarshalJSON() ([]byte, error) {
	return json.Marshal(checkInJSON{
		PassphraseHash:       c.passphraseHash,
		DuressPassphraseHash: c.duressPassphraseHash,
		LastCheckIn:          c.lastCheckIn,
	})
}

// UnmarshalJSON implements json.Unmarshaler, restoring a CheckIn
// previously produced by MarshalJSON. It does not re-derive or validate
// the hashes — it trusts the persisted state was written by this package.
func (c *CheckIn) UnmarshalJSON(data []byte) error {
	var aux checkInJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.passphraseHash = aux.PassphraseHash
	c.duressPassphraseHash = aux.DuressPassphraseHash
	c.lastCheckIn = aux.LastCheckIn
	return nil
}

