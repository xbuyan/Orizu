package main

import (
	"fmt"
	"os"
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/config"
	"github.com/xbuyan/orizu/internal/relay"
)

// runCheckIn prompts for a passphrase, records the check-in, and — if the
// duress passphrase was used — silently notifies all three guardians via
// the relay. Deliberately, the printed output is identical whether the
// check-in was normal or under duress: anyone watching the screen (a
// coercer included) must not be able to tell which happened. Only a
// genuinely wrong passphrase produces different output, since that is not
// a duress-relevant distinction to hide.
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

	if result.DuressDetected {
		// Best-effort: a relay/network failure here must not change what
		// is printed, or the screen output itself would leak the duress
		// signal to anyone watching. Failures are swallowed from the
		// user-visible path; see the design note below on what that costs.
		notifyGuardiansOfDuress(now)
	}

	fmt.Println("Checked in.")
	return nil
}

// notifyGuardiansOfDuress seals and posts a duress alert to every
// configured guardian. Errors are intentionally not surfaced to stdout —
// see runCheckIn — but are logged to stderr, which a coercer is less
// likely to be watching than the primary terminal output, and which still
// gives the owner an after-the-fact record if they check logs later.
//
// Known limitation, not yet addressed: if the relay is unreachable at the
// moment of duress (e.g. no network), this alert is silently lost with no
// retry. A background retry queue would close this gap but isn't built.
func notifyGuardiansOfDuress(now time.Time) {
	cfgPath, err := configPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "duress alert: could not resolve config path:", err)
		return
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "duress alert: could not load guardian config:", err)
		return
	}

	client := relay.NewClient(cfg.RelayURL)
	a := alert.NewDuressAlert(now)

	for _, guardian := range cfg.Guardians {
		sealed, err := alert.Seal(a, &guardian.PubKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "duress alert: sealing for", guardian.ID, "failed:", err)
			continue
		}
		if err := client.Post(guardian.ID, sealed); err != nil {
			fmt.Fprintln(os.Stderr, "duress alert: notifying", guardian.ID, "failed:", err)
			continue
		}
	}
}

