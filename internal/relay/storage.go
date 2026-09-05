// Package relay implements the HTTP relay that carries sealed duress
// alerts from an owner's device to guardians. The relay stores only opaque
// bytes it cannot decrypt (see internal/alert) — by design it never learns
// who sent an alert, what it says, or that it is specifically a duress
// signal rather than any other message.
//
// Known, deliberately deferred gap (see THREAT_MODEL.md): the relay
// accepts any POST to a valid guardian ID with no sender authentication.
// Because alerts are anonymously sealed (no sender identity to check),
// the relay cannot distinguish a genuine alert from spam pointed at a
// guardian's known public key. A malicious blob only wastes a guardian's
// attention on a failed decryption — it cannot be read or forged as
// content — but this is still a real spam/DoS surface, not yet hardened.
package relay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// DefaultExpiry is how long a stored alert remains available to guardians,
// regardless of whether it has already been fetched. Chosen to match the
// checkin package's 30-day check-in interval, so an alert stays visible for
// at least one full check-in cycle.
const DefaultExpiry = 30 * 24 * time.Hour

// guardianIDPattern restricts guardian IDs to a safe, predictable charset.
// This also prevents path traversal, since guardian IDs become directory
// names on disk.
var guardianIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// Sentinel errors returned by this package.
var (
	ErrInvalidGuardianID = errors.New("relay: guardian ID contains invalid characters or is empty")
)

// Store persists sealed alert blobs to disk, one directory per guardian.
type Store struct {
	baseDir string
	expiry  time.Duration
}

// NewStore creates a Store rooted at baseDir, creating it if needed.
// expiry controls how long a stored blob remains available; pass
// DefaultExpiry unless there's a specific reason to differ.
func NewStore(baseDir string, expiry time.Duration) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("relay: creating base directory: %w", err)
	}
	return &Store{baseDir: baseDir, expiry: expiry}, nil
}

// record is the on-disk envelope around a sealed blob. StoredAt drives
// expiry; Blob is the opaque ciphertext produced by alert.Seal.
type record struct {
	StoredAt time.Time `json:"stored_at"`
	Blob     []byte    `json:"blob"`
}

func (s *Store) guardianDir(guardianID string) (string, error) {
	if !guardianIDPattern.MatchString(guardianID) {
		return "", ErrInvalidGuardianID
	}
	return filepath.Join(s.baseDir, guardianID), nil
}

// Put stores blob for guardianID, stamped with now, and returns a random
// opaque ID for the stored record. Multiple alerts for the same guardian
// coexist independently — Put never overwrites or deletes prior alerts.
func (s *Store) Put(guardianID string, blob []byte, now time.Time) (id string, err error) {
	dir, err := s.guardianDir(guardianID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("relay: creating guardian directory: %w", err)
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("relay: generating record id: %w", err)
	}
	id = hex.EncodeToString(idBytes)

	rec := record{StoredAt: now, Blob: blob}
	data, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("relay: encoding record: %w", err)
	}

	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("relay: writing record: %w", err)
	}
	return id, nil
}

// List returns the blobs of every non-expired alert stored for guardianID,
// as of now. A guardian with no alerts (or an unknown guardian ID with a
// valid format) gets an empty slice, not an error — an empty inbox isn't a
// failure. Expired records are skipped but not deleted here; disk cleanup
// of expired records is a separate concern (not yet built).
func (s *Store) List(guardianID string, now time.Time) ([][]byte, error) {
	dir, err := s.guardianDir(guardianID)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return [][]byte{}, nil
		}
		return nil, fmt.Errorf("relay: reading guardian directory: %w", err)
	}

	var blobs [][]byte
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue // best-effort: skip unreadable records rather than fail the whole list
		}
		var rec record
		if err := json.Unmarshal(data, &rec); err != nil {
			continue // skip corrupted records rather than fail the whole list
		}
		if now.Sub(rec.StoredAt) > s.expiry {
			continue // expired
		}
		blobs = append(blobs, rec.Blob)
	}
	if blobs == nil {
		blobs = [][]byte{}
	}
	return blobs, nil
}