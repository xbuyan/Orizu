package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/config"
	"github.com/xbuyan/orizu/internal/relay"
	"github.com/xbuyan/orizu/internal/retryqueue"
)

// runCheckIn prompts for a passphrase, records the check-in, and notifies
// all three guardians via the relay on every successful check-in — a
// Liveness alert normally, or a Duress alert if the duress passphrase was
// used. Posting on every check-in (not just duress) is deliberate: it lets
// guardians detect total silence, not just an active duress signal, and
// it means the network traffic pattern is identical either way, so it
// cannot itself be used to infer that a duress event occurred.
//
// Before sending the new alert, this also opportunistically flushes any
// previously-failed notifications still sitting in the retry queue (see
// internal/retryqueue) — a real fix for a real gap: a check-in that fails
// to reach the relay used to be silently lost, which could eventually
// produce a false OVERDUE signal for guardians even though the owner
// genuinely checked in.
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
	// anyone watching. Failures are queued for retry rather than lost —
	// see notifyGuardians.
	notifyGuardians(result.DuressDetected, now)

	fmt.Println("Checked in.")
	return nil
}

func retryQueueDir() (string, error) {
	dir, err := orizuDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "retry-queue"), nil
}

// notifyGuardians seals and posts an alert to every configured guardian —
// a Duress alert if duress is true, otherwise a Liveness alert. Before
// sending, it first attempts to flush any previously-queued failed
// notifications, so a transient outage self-heals on the next check-in
// rather than requiring the owner to notice and act.
//
// Delivery errors (for both the flush and the new alert) are logged to
// stderr only, never surfaced to stdout — see runCheckIn — since a
// coercer watching the primary terminal output must see no difference.
// A failed new alert is enqueued for the next attempt rather than
// discarded, closing the gap that previously existed here.
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

	queueDir, err := retryQueueDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardian notify: could not resolve retry queue path:", err)
		return
	}
	queue, err := retryqueue.NewQueue(queueDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardian notify: could not open retry queue:", err)
		return
	}

	client := relay.NewClient(cfg.RelayURL, cfg.PostToken)

	// Opportunistic self-healing: attempt to deliver anything left over
	// from a previous failure before sending today's alert.
	if flushResult, err := queue.Flush(client, now); err != nil {
		fmt.Fprintln(os.Stderr, "guardian notify: retry queue flush failed:", err)
	} else if flushResult.Delivered > 0 || flushResult.Dropped > 0 {
		fmt.Fprintf(os.Stderr, "guardian notify: retry queue — delivered %d, dropped %d (too old), %d still pending\n",
			flushResult.Delivered, flushResult.Dropped, flushResult.Remaining)
	}

	var a alert.Alert
	if duress {
		a = alert.NewDuressAlert(now)
	} else {
		a = alert.NewLivenessAlert(now)
	}

	for _, guardian := range cfg.Guardians {
		sealed, err := alert.Seal(a, &guardian.PubKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "guardian notify: sealing for", guardian.ID, "failed:", err)
			continue
		}
		if err := client.Post(guardian.ID, sealed); err != nil {
			fmt.Fprintln(os.Stderr, "guardian notify: notifying", guardian.ID, "failed, queuing for retry:", err)
			if qerr := queue.Enqueue(guardian.ID, sealed, now); qerr != nil {
				fmt.Fprintln(os.Stderr, "guardian notify: FAILED TO QUEUE for", guardian.ID, "— this notification is lost:", qerr)
			}
			continue
		}
	}
}

