// Package config loads Orizu's local configuration: the relay's URL, the
// shared POST authentication token, and the three guardians' identities
// and public keys. This is deliberately a single flat JSON file rather
// than flags or environment variables, since it doesn't change often and
// is easier to review/back up as one artifact.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// GuardianCount is fixed at the project's 3-of-3 threshold decision. A
// config with any other number of guardians is rejected — see Load.
const GuardianCount = 3

// Guardian identifies one guardian: an opaque ID (used as the relay path
// segment, see internal/relay) and their NaCl box public key.
type Guardian struct {
	ID     string   `json:"id"`
	PubKey [32]byte `json:"-"`
}

// guardianJSON is the on-disk shape; PubKey is base64 in the file but a
// fixed-size array in memory (what alert.Seal expects).
type guardianJSON struct {
	ID     string `json:"id"`
	PubKey string `json:"pub_key"`
}

// Config is Orizu's local configuration.
type Config struct {
	RelayURL  string     `json:"relay_url"`
	PostToken string     `json:"-"`
	Guardians []Guardian `json:"-"`
}

type configJSON struct {
	RelayURL  string         `json:"relay_url"`
	PostToken string         `json:"post_token"`
	Guardians []guardianJSON `json:"guardians"`
}

// Sentinel errors returned by this package.
var (
	ErrMissingRelayURL    = errors.New("config: relay_url must not be empty")
	ErrMissingPostToken   = errors.New("config: post_token must not be empty — required to authenticate with the relay, see relay.Server's package doc")
	ErrWrongGuardianCount = fmt.Errorf("config: exactly %d guardians are required", GuardianCount)
	ErrInvalidPubKey      = errors.New("config: guardian public key must be 32 bytes, base64-encoded")
	ErrDuplicateGuardian  = errors.New("config: guardian ids must be unique")
)

// Load reads and validates a Config from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	var raw configJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}

	if raw.RelayURL == "" {
		return nil, ErrMissingRelayURL
	}
	if raw.PostToken == "" {
		return nil, ErrMissingPostToken
	}
	if len(raw.Guardians) != GuardianCount {
		return nil, ErrWrongGuardianCount
	}

	seen := make(map[string]bool, len(raw.Guardians))
	guardians := make([]Guardian, len(raw.Guardians))
	for i, g := range raw.Guardians {
		if seen[g.ID] {
			return nil, ErrDuplicateGuardian
		}
		seen[g.ID] = true

		keyBytes, err := base64.StdEncoding.DecodeString(g.PubKey)
		if err != nil || len(keyBytes) != 32 {
			return nil, ErrInvalidPubKey
		}
		var pubKey [32]byte
		copy(pubKey[:], keyBytes)

		guardians[i] = Guardian{ID: g.ID, PubKey: pubKey}
	}

	return &Config{RelayURL: raw.RelayURL, PostToken: raw.PostToken, Guardians: guardians}, nil
}

// Fingerprint computes a short, human-comparable representation of a
// public key: the first 16 bytes of its SHA-256 hash, formatted as 8
// groups of 4 uppercase hex characters.
//
// This exists because guardian public-key exchange is, and fundamentally
// has to be, trust-on-first-use — there is no code-level fix for a
// substituted key exchanged over a compromised channel. What every
// mature system facing this same problem actually does (SSH host keys,
// Signal's safety numbers, PGP fingerprints) is give both parties a
// short value they can read aloud and compare over an independent
// channel, so a substitution is at least detectable rather than silent.
// This is that value for Orizu. See cmd/orizu/distribute.go, which
// requires the owner to explicitly confirm they've done this comparison
// before shares are ever sent.
func Fingerprint(pubKey [32]byte) string {
	sum := sha256.Sum256(pubKey[:])
	hexStr := strings.ToUpper(hex.EncodeToString(sum[:16]))

	var groups []string
	for i := 0; i < len(hexStr); i += 4 {
		groups = append(groups, hexStr[i:i+4])
	}
	return strings.Join(groups, " ")
}

// Fingerprint returns this guardian's public-key fingerprint — see the
// package-level Fingerprint function.
func (g Guardian) Fingerprint() string {
	return Fingerprint(g.PubKey)
}

