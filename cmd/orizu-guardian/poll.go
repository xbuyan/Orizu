package main

import (
	"fmt"
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/relay"
	"github.com/xbuyan/orizu/internal/trigger"
)

// runPoll fetches every alert waiting at the relay for this guardian,
// decrypts each one, and reports overdue status computed from the most
// recent Liveness alert seen. Unlike the owner's checkin output, there is
// no concealment concern here — the guardian is the intended, trusted
// recipient, so both a duress alert and an overdue status are reported
// plainly. That plainness is the entire point of this tool.
//
// Overdue detection here is observation-only: it never combines Shamir
// shares or initiates anything automatically. What to do about an overdue
// or duress signal remains the guardian's decision — see
// internal/trigger's package doc.
func runPoll() error {
	kf, err := loadKeyFile()
	if err != nil {
		return err
	}

	pubKey, err := decode32(kf.PubKey)
	if err != nil {
		return fmt.Errorf("stored public key is invalid: %w", err)
	}
	privKey, err := decode32(kf.PrivKey)
	if err != nil {
		return fmt.Errorf("stored private key is invalid: %w", err)
	}

	client := relay.NewClient(kf.RelayURL)
	blobs, err := client.Fetch(kf.ID)
	if err != nil {
		return fmt.Errorf("fetching from relay: %w", err)
	}

	if len(blobs) == 0 {
		fmt.Println("No alerts yet — nothing has been received from the owner.")
		return nil
	}

	var opened []alert.Alert
	fmt.Printf("%d alert(s):\n", len(blobs))
	for i, blob := range blobs {
		a, err := alert.Open(blob, pubKey, privKey)
		if err != nil {
			// Consistent with the relay's documented spam/DoS gap: an
			// unauthenticated blob that isn't meant for this key (spam, or
			// corruption) simply fails to decrypt. Reported, not fatal —
			// one bad entry shouldn't hide genuine alerts alongside it.
			fmt.Printf("  [%d] could not decrypt (%v) — possibly not intended for you, or corrupted\n", i+1, err)
			continue
		}
		opened = append(opened, a)
		switch a.Type {
		case alert.Duress:
			fmt.Printf("  [%d] *** DURESS ALERT *** at %s\n", i+1, a.Timestamp.Format("2006-01-02 15:04:05 MST"))
		case alert.Liveness:
			fmt.Printf("  [%d] liveness check-in at %s\n", i+1, a.Timestamp.Format("2006-01-02 15:04:05 MST"))
		default:
			fmt.Printf("  [%d] alert type %q at %s\n", i+1, a.Type, a.Timestamp.Format("2006-01-02 15:04:05 MST"))
		}
	}

	fmt.Println()
	lastSeen, hasSeen := trigger.LatestLiveness(opened)
	status := trigger.Evaluate(lastSeen, hasSeen, time.Now())
	switch {
	case !status.HasSeenLiveness:
		fmt.Println("Status: no liveness signal received yet.")
	case status.Overdue:
		fmt.Printf("Status: *** OVERDUE *** — no liveness since %s\n", status.LastSeen.Format("2006-01-02 15:04:05 MST"))
	default:
		fmt.Printf("Status: OK — last liveness at %s\n", status.LastSeen.Format("2006-01-02 15:04:05 MST"))
	}

	return nil
}

