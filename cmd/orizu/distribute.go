package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/config"
	"github.com/xbuyan/orizu/internal/relay"
	"github.com/xbuyan/orizu/internal/shamir"
)

// releaseSecretSize is the size of the generated secret, in bytes. This
// secret is what the 3-of-3 guardian threshold ultimately protects — it
// stands in for whatever eventually authorizes an evidence release once
// Sentinel exists. It is not derived from anything the owner already
// holds; it is fresh, random, and generated only in memory here.
const releaseSecretSize = 32

// distributionMarkerPath returns the path to a small on-disk marker
// recording that distribution has already happened. It stores no secret
// material — only that the step was completed — so `orizu distribute`
// can refuse to silently run twice (which would generate and send a
// second, different secret, silently orphaning the first) without ever
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

// runDistribute generates a fresh release secret, splits it into exactly
// 3 Shamir shares (Orizu's 3-of-3 threshold — see internal/shamir), and
// delivers one share to each configured guardian via the relay, sealed to
// their public key exactly like a Duress or Liveness alert.
//
// Deliberately, the secret and its shares exist only in memory for the
// duration of this function. Nothing is written to disk except the
// no-secret marker recording that distribution happened — the owner
// retaining a copy would defeat the entire point of requiring all three
// guardians to combine their shares.
func runDistribute() error {
	markerPath, err := distributionMarkerPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(markerPath); err == nil {
		return fmt.Errorf("shares were already distributed (see %s) — refusing to generate and "+
			"send a new secret, which would orphan the one guardians already hold. "+
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

	secret := make([]byte, releaseSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generating release secret: %w", err)
	}

	shares, err := shamir.Split(secret)
	if err != nil {
		return fmt.Errorf("splitting secret: %w", err)
	}
	if len(shares) != len(cfg.Guardians) {
		return fmt.Errorf("internal error: %d shares for %d guardians — these must match", len(shares), len(cfg.Guardians))
	}

	client := relay.NewClient(cfg.RelayURL)
	now := time.Now()
	var sent []string

	for i, guardian := range cfg.Guardians {
		shareData, err := json.Marshal(shares[i])
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

	// secret and shares fall out of scope here — this is the only place
	// they ever exist, and this function never writes them to disk.

	marker := distributionMarker{DistributedAt: now, GuardianIDs: sent}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding distribution marker: %w", err)
	}
	if err := os.WriteFile(markerPath, data, 0o600); err != nil {
		return fmt.Errorf("writing distribution marker: %w", err)
	}

	fmt.Println("Shares distributed to all guardians:", sent)
	fmt.Println("The release secret has not been retained anywhere, including on this machine.")
	return nil
}

