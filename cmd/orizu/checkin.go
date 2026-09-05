package main

import (
	"fmt"
	"os"
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/config"
	"github.com/xbuyan/orizu/internal/relay"
)

// runCheckIn prompts for a passphrase, records the check-in, and notifies
// all three guardians via the relay on every successful check-in — a
// Liveness alert normally, or a Duress alert if the duress passphrase was
// used. Posting on every check-in (not just duress) is deliberate: it lets
// guardians detect total silence, not just an active duress signal, and
// it means the network traffic pattern is identical either way, so it
// cannot itself be used to infer that a duress event occurred.
//
// The printed output is identical whether the check-in was normal or
// under duress: anyone watching the screen (a coercer included) must not
// be able to tell which happened. Only a genuinely wrong passphrase
// produces different output, since that is not a duress-relevant
// distinction to hide.
func runCheckIn() error {
	c, err := loadState()
	if err != nil {
		return err
	}

	passphrase, err := promptHidden("Passphrase: ")
	if err != nil {
		return err
	}

	now := time.Now()
	result, err := c.Record(passphrase, now)
	if err != nil {
		// Wrong passphrase — this is a distinct, visible failure by
		// necessity (the owner needs to know they mistyped it), not a
		// duress-related signal to hide.
		return err
	}

	if err := saveState(c); err != nil {
		return err
	}

	// Best-effort: a relay/network failure here must not change what is
	// printed, or the screen output itself would leak information to
	// anyone watching. Failures are swallowed from the user-visible path;
	// see the design note on the retry gap below.
	notifyGuardians(result.DuressDetected, now)

	fmt.Println("Checked in.")
	return nil
}

// notifyGuardians seals and posts an alert to every configured guardian —
// a Duress alert if duress is true, otherwise a Liveness alert. Errors are
// logged to stderr only, never surfaced to stdout — see runCheckIn — since
// a coercer watching the primary terminal output must see no difference,
// while stderr still gives the owner an after-the-fact record if they
// check logs later.
//
// Known limitation, not yet addressed: if the relay is unreachable at
// check-in time (e.g. no network), this alert is silently lost with no
// retry. Since Liveness alerts now drive guardian-side overdue detection
// (see internal/trigger), a lost Liveness ping risks a guardian eventually
// seeing a false "overdue" status even though the owner genuinely checked
// in — this is a real cost of not yet having a retry queue, not just a
// cosmetic gap.
func notifyGuardians(duress bool, now time.Time) {
	cfgPath, err := configPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardian notify: could not resolve config path:", err)
		return
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardian notify: could not load guardian config:", err)
		return
	}

	var a alert.Alert
	if duress {
		a = alert.NewDuressAlert(now)
	} else {
		a = alert.NewLivenessAlert(now)
	}

	client := relay.NewClient(cfg.RelayURL)
	for _, guardian := range cfg.Guardians {
		sealed, err := alert.Seal(a, &guardian.PubKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "guardian notify: sealing for", guardian.ID, "failed:", err)
			continue
		}
		if err := client.Post(guardian.ID, sealed); err != nil {
			fmt.Fprintln(os.Stderr, "guardian notify: notifying", guardian.ID, "failed:", err)
			continue
		}
	}
}

