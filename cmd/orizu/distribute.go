package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/config"
	"github.com/xbuyan/orizu/internal/recovery"
	"github.com/xbuyan/orizu/internal/relay"
	"github.com/xbuyan/orizu/internal/shamir"
	"golang.org/x/crypto/nacl/box"
)

// distributionMarkerPath returns the path to a small on-disk marker
// recording that distribution has already happened. It stores no secret
// material — only that the step was completed — so `orizu distribute`
// can refuse to silently run twice (which would generate and send a
// second, different keypair, silently orphaning the first) without ever
// persisting anything sensitive.
func distributionMarkerPath() (string, error) {
	dir, err := orizuDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "distribution.json"), nil
}

type distributionMarker struct {
	DistributedAt time.Time `json:"distributed_at"`
	GuardianIDs   []string  `json:"guardian_ids"`
}

// evidencePubKeyPath returns the path where the owner's evidence
// encryption public key is stored — the ONE piece of key material this
// command persists. It's safe to keep openly: encrypting to a public key
// requires no secret, so this file lets the owner protect evidence
// indefinitely without ever holding the matching private key.
func evidencePubKeyPath() (string, error) {
	dir, err := orizuDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "evidence-pubkey.json"), nil
}

type evidencePubKeyFile struct {
	PubKey string `json:"pub_key"` // base64
}

// runDistribute generates a fresh NaCl keypair, persists the PUBLIC half
// for the owner's own ongoing use, splits the PRIVATE half into exactly 3
// Shamir shares (Orizu's 3-of-3 threshold — see internal/shamir), and
// delivers one share to each configured guardian via the relay, sealed to
// their public key exactly like a Duress or Liveness alert.
//
// This is an asymmetric design deliberately chosen to resolve a real
// conflict: the owner needs an ongoing way to encrypt new evidence as
// it's captured (see the Sentinel bridge), which requires holding
// something usable at any time — but Orizu's core guarantee is that the
// owner alone must never be able to decrypt or release evidence, only
// guardians acting together. A keypair satisfies both: the owner keeps
// the PUBLIC key forever (harmless — sealed-box encryption to a pubkey
// needs no secret), while the PRIVATE key is split 3-of-3 among guardians
// and never touches disk on the owner's machine at all.
func runDistribute() error {
	markerPath, err := distributionMarkerPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(markerPath); err == nil {
		return fmt.Errorf("a keypair was already distributed (see %s) — refusing to generate and "+
			"send a new one, which would orphan the private-key shares guardians already hold and "+
			"invalidate the public key already in use for encryption. "+
			"If you genuinely need to redo this, remove that file first and understand "+
			"that all three guardians must discard their old share", markerPath)
	}

	cfgPath, err := configPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading guardian config: %w", err)
	}

	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	shares, err := shamir.Split(privKey[:])
	if err != nil {
		return fmt.Errorf("splitting private key: %w", err)
	}
	if len(shares) != len(cfg.Guardians) {
		return fmt.Errorf("internal error: %d shares for %d guardians — these must match", len(shares), len(cfg.Guardians))
	}

	// Computed once, before the private key goes out of scope, and
	// embedded in every guardian's payload. Safe to distribute openly: a
	// SHA-256 fingerprint reveals nothing about the key itself, but lets
	// a future recovery ceremony detect a corrupted or mismatched share
	// instead of silently reconstructing the wrong key — see
	// internal/recovery's package doc for why this matters.
	fingerprint := recovery.Fingerprint(privKey[:])

	client := relay.NewClient(cfg.RelayURL)
	now := time.Now()
	var sent []string

	for i, guardian := range cfg.Guardians {
		payload := recovery.SharePayload{Share: shares[i], Fingerprint: fingerprint}
		shareData, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encoding share for %s: %w", guardian.ID, err)
		}

		a := alert.NewShareAlert(shareData, now)
		sealed, err := alert.Seal(a, &guardian.PubKey)
		if err != nil {
			return fmt.Errorf("sealing share for %s: %w", guardian.ID, err)
		}

		if err := client.Post(guardian.ID, sealed); err != nil {
			// Unlike a routine Liveness ping, a failed Share delivery is
			// NOT swallowed — the owner needs to know a guardian didn't
			// receive their share, since without it the 3-of-3 threshold
			// can never be satisfied. Stop rather than silently
			// half-distribute.
			return fmt.Errorf("delivering share to %s failed: %w (already sent to: %v — do not assume they can be combined; consider re-running once the issue is fixed, after checking whether already-sent guardians should discard their share)", guardian.ID, err, sent)
		}
		sent = append(sent, guardian.ID)
	}

	// privKey and shares fall out of scope here — this is the only place
	// the private key ever exists on the owner's machine, and this
	// function never writes it to disk. Only pubKey is persisted below.

	pubKeyPath, err := evidencePubKeyPath()
	if err != nil {
		return err
	}
	pubKeyData, err := json.MarshalIndent(evidencePubKeyFile{PubKey: base64.StdEncoding.EncodeToString(pubKey[:])}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding public key: %w", err)
	}
	if err := os.WriteFile(pubKeyPath, pubKeyData, 0o644); err != nil {
		// 0644, not 0600: this file contains only a public key, safe to
		// be world-readable — it needs to be, since Sentinel's encrypt
		// step reads it routinely.
		return fmt.Errorf("writing public key: %w", err)
	}

	marker := distributionMarker{DistributedAt: now, GuardianIDs: sent}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding distribution marker: %w", err)
	}
	if err := os.WriteFile(markerPath, data, 0o600); err != nil {
		return fmt.Errorf("writing distribution marker: %w", err)
	}

	fmt.Println("Keypair generated. Private-key shares distributed to all guardians:", sent)
	fmt.Println("Public key saved at", pubKeyPath, "— use this for encrypting evidence going forward.")
	fmt.Println("The private key has not been retained anywhere, including on this machine.")
	return nil
}

