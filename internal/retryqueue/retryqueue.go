// Package retryqueue closes a real correctness gap: previously, if the
// relay was unreachable at check-in time, the alert (Liveness or Duress)
// was logged to stderr and silently lost. Since guardians' overdue
// detection depends entirely on receiving Liveness pings, a lost ping
// from a transient network failure — not actual danger — could produce a
// false OVERDUE signal for guardians even though the owner genuinely
// checked in. That is a real bug in a dead-man's-switch, not a cosmetic
// gap.
//
// The fix: persist a failed notification to disk instead of discarding
// it, and retry delivery opportunistically on every subsequent command
// (checkin, or the dedicated `orizu retry`), until it succeeds or the
// item's own age exceeds a bound past which retrying is no longer
// meaningful (see MaxAge).
package retryqueue

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/xbuyan/orizu/internal/relay"
)

// MaxAge bounds how long a queued item is retried before being dropped.
// Set to match checkin's Interval+GracePeriod: past that point, the
// owner is already genuinely overdue by definition, so continuing to
// silently retry an old alert no longer serves the "absorb a transient
// failure" purpose this queue exists for — it would just be quietly
// masking a real, prolonged outage. Kept as a named constant here rather
// than importing internal/checkin, to avoid a needless cross-package
// dependency for one constant; the two are deliberately kept in sync by
// comment, not by shared code.
const MaxAge = 37 * 24 * time.Hour // checkin.Interval (30d) + checkin.GracePeriod (7d)

var guardianIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// item is the on-disk shape of one queued, undelivered notification.
type item struct {
	GuardianID string    `json:"guardian_id"`
	Blob       []byte    `json:"blob"`
	QueuedAt   time.Time `json:"queued_at"`
}

// Queue persists undelivered guardian notifications to disk, one file
// per item, so they survive across process invocations (a single
// `orizu checkin` run can't usefully retry in a loop without blocking —
// the retry has to happen on a later invocation instead).
type Queue struct {
	dir string
}

// NewQueue creates a Queue rooted at dir, creating it if needed.
func NewQueue(dir string) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("retryqueue: creating directory: %w", err)
	}
	return &Queue{dir: dir}, nil
}

// Enqueue persists a failed notification for later retry.
func (q *Queue) Enqueue(guardianID string, blob []byte, now time.Time) error {
	if !guardianIDPattern.MatchString(guardianID) {
		return fmt.Errorf("retryqueue: invalid guardian id")
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("retryqueue: generating item id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	it := item{GuardianID: guardianID, Blob: blob, QueuedAt: now}
	data, err := json.Marshal(it)
	if err != nil {
		return fmt.Errorf("retryqueue: encoding item: %w", err)
	}

	path := filepath.Join(q.dir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("retryqueue: writing item: %w", err)
	}
	return nil
}

// Result summarizes the outcome of a Flush call.
type Result struct {
	Delivered int // successfully sent and removed from the queue
	Remaining int // still queued (delivery failed again, or will be retried later)
	Dropped   int // discarded for exceeding MaxAge, never delivered
}

// Flush attempts to deliver every queued item via client. Delivered items
// are removed from the queue. Items still failing remain queued for the
// next Flush call. Items older than MaxAge are dropped rather than
// retried indefinitely — see MaxAge's doc comment for why.
//
// Flush is designed to be called opportunistically and often (every
// checkin, plus a standalone `orizu retry`), not run as a persistent
// background loop — this fits how the CLI is actually used, without
// requiring a long-running daemon process.
func (q *Queue) Flush(client *relay.Client, now time.Time) (Result, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return Result{}, fmt.Errorf("retryqueue: reading queue directory: %w", err)
	}

	var res Result
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(q.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue // best-effort: skip unreadable items rather than fail the whole flush
		}
		var it item
		if err := json.Unmarshal(data, &it); err != nil {
			continue // skip corrupted items rather than fail the whole flush
		}

		if now.Sub(it.QueuedAt) > MaxAge {
			os.Remove(path)
			res.Dropped++
			continue
		}

		if err := client.Post(it.GuardianID, it.Blob); err != nil {
			res.Remaining++
			continue
		}
		os.Remove(path)
		res.Delivered++
	}
	return res, nil
}

