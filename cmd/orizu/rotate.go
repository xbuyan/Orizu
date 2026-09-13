package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/xbuyan/orizu/internal/config"
)

// runRotate replaces an existing distributed keypair with a brand new
// one — for when a guardian relationship genuinely breaks down (a
// guardian becomes unreachable, is no longer trusted, or the owner wants
// to change who holds shares), or as deliberate periodic hygiene.
//
// What rotation does NOT do, stated plainly rather than glossed over:
// it does not retroactively re-encrypt any evidence already sealed under
// the OLD public key. Under Orizu's 3-of-3 design, that old evidence
// remains decryptable only by whoever could reconstruct the OLD private
// key — the OLD guardians, cooperating, exactly as before. Rotating does
// not change that; it only affects evidence encrypted AFTER rotation. If
// existing evidence genuinely needs to move to the new key, that requires
// an explicit, separate step: recover the old key (old guardians
// cooperate one final time), `sentinel decrypt` each piece of evidence
// with it, then `sentinel encrypt` each one again with the new public
// key. This command does not do that automatically, since it would
// require briefly reconstructing the very key rotation is meant to
// retire, and deciding whether that's worth doing is a real judgment
// call for the owner, not something to automate silently.
func runRotate() error {
	markerPath, err := distributionMarkerPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(markerPath); err != nil {
		return fmt.Errorf("no keypair has been distributed yet — use `orizu distribute` for first-time setup, not rotate")
	}

	cfgPath, err := configPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading guardian config: %w", err)
	}

	fmt.Println("=== Key rotation ===")
	fmt.Println("This will generate a NEW keypair and send NEW private-key shares to the")
	fmt.Println("guardians in your current config.json (edit that file first if you're")
	fmt.Println("replacing a guardian, before continuing).")
	fmt.Println()
	fmt.Println("IMPORTANT — read before continuing:")
	fmt.Println("  - The OLD guardians should securely delete their old share.json once you")
	fmt.Println("    confirm this new distribution succeeded — otherwise the old shares still")
	fmt.Println("    technically exist and could theoretically still be combined.")
	fmt.Println("  - Evidence already encrypted under the OLD public key is NOT automatically")
	fmt.Println("    migrated. It remains decryptable only via the OLD key (old guardians'")
	fmt.Println("    cooperation), exactly as before rotation. See this command's own doc")
	fmt.Println("    comment (rotate.go) if you need to manually migrate old evidence.")
	fmt.Println()

	confirmation, err := promptVisible("Type 'rotate' to confirm you understand this and want to proceed: ")
	if err != nil {
		return err
	}
	if confirmation != "rotate" {
		return fmt.Errorf("rotation not confirmed — aborting before any new shares were generated or sent")
	}

	if err := confirmGuardianFingerprints(cfg); err != nil {
		return err
	}

	pubKey, sent, err := generateAndDistributeKeypair(cfg)
	if err != nil {
		return fmt.Errorf("rotation failed partway through: %w (do not assume the old key is safely retired — "+
			"check which guardians received a new share before deciding how to proceed)", err)
	}

	pubKeyPath, err := evidencePubKeyPath()
	if err != nil {
		return err
	}
	pubKeyData, err := json.MarshalIndent(evidencePubKeyFile{PubKey: base64.StdEncoding.EncodeToString(pubKey[:])}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding public key: %w", err)
	}
	if err := os.WriteFile(pubKeyPath, pubKeyData, 0o644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	marker := distributionMarker{DistributedAt: time.Now(), GuardianIDs: sent}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding distribution marker: %w", err)
	}
	if err := os.WriteFile(markerPath, data, 0o600); err != nil {
		return fmt.Errorf("writing distribution marker: %w", err)
	}

	fmt.Println()
	fmt.Println("Rotation complete. New keypair generated; new shares sent to:", sent)
	fmt.Println("New public key saved at", pubKeyPath)
	fmt.Println("Remember: tell the old guardians to delete their old share.json now.")
	fmt.Println("Evidence encrypted under the previous key was NOT migrated — see the notes above.")
	return nil
}

