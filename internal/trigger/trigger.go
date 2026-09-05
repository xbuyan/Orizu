// Package trigger computes overdue status from the guardian's point of
// view: given the most recent Liveness alert a guardian has actually
// received, is the owner now overdue by the same definition their own
// device would use?
//
// This is deliberately observation-only. It never combines Shamir shares,
// never initiates release, and never acts automatically — detecting
// silence is mechanical, but deciding what to do about it stays a human
// guardian decision, consistent with Orizu's guardians-as-humans design
// throughout (see THREAT_MODEL.md). The Sentinel handoff for an actual
// conditional release is future work, built once Sentinel exists.
package trigger

import (
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/checkin"
)

// Status is what a guardian can determine from alerts alone.
type Status struct {
	// LastSeen is the timestamp of the most recent Liveness alert
	// observed. Zero if none have ever been seen.
	LastSeen time.Time

	// Overdue is true once now is past LastSeen + checkin.Interval +
	// checkin.GracePeriod — the same deadline definition checkin.CheckIn
	// uses on the owner's own device, computed independently here.
	Overdue bool

	// HasSeenLiveness distinguishes "never received any liveness signal
	// at all" from "received one, but it's now stale." The former usually
	// means guardian setup isn't complete yet, not that the owner is in
	// danger — callers should treat it differently from a genuine overdue
	// status.
	HasSeenLiveness bool
}

// LatestLiveness returns the timestamp of the most recent Liveness-type
// alert in alerts, and whether any were found. Duress-type alerts are
// ignored here — they're surfaced separately (see cmd/orizu-guardian),
// since a duress signal is actionable in its own right regardless of
// overdue status.
func LatestLiveness(alerts []alert.Alert) (time.Time, bool) {
	var latest time.Time
	found := false
	for _, a := range alerts {
		if a.Type != alert.Liveness {
			continue
		}
		if !found || a.Timestamp.After(latest) {
			latest = a.Timestamp
			found = true
		}
	}
	return latest, found
}

// Evaluate computes Status as of now, given the most recent Liveness
// timestamp a guardian has observed (see LatestLiveness). If hasSeen is
// false, Overdue is always false — there's nothing to be overdue relative
// to yet.
func Evaluate(lastSeen time.Time, hasSeen bool, now time.Time) Status {
	if !hasSeen {
		return Status{HasSeenLiveness: false}
	}
	deadline := lastSeen.Add(checkin.Interval).Add(checkin.GracePeriod)
	return Status{
		LastSeen:        lastSeen,
		HasSeenLiveness: true,
		Overdue:         now.After(deadline),
	}
}

