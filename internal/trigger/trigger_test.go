package trigger

import (
	"testing"
	"time"

	"github.com/xbuyan/orizu/internal/alert"
	"github.com/xbuyan/orizu/internal/checkin"
)

func TestLatestLiveness_FindsMostRecentAmongMultiple(t *testing.T) {
	base := time.Now()
	alerts := []alert.Alert{
		{Type: alert.Liveness, Timestamp: base.Add(-2 * time.Hour)},
		{Type: alert.Liveness, Timestamp: base}, // most recent
		{Type: alert.Liveness, Timestamp: base.Add(-1 * time.Hour)},
	}

	latest, found := LatestLiveness(alerts)
	if !found {
		t.Fatal("expected found=true")
	}
	if !latest.Equal(base) {
		t.Errorf("expected latest=%v, got %v", base, latest)
	}
}

func TestLatestLiveness_IgnoresDuressAlerts(t *testing.T) {
	base := time.Now()
	alerts := []alert.Alert{
		{Type: alert.Duress, Timestamp: base}, // more recent, but wrong type
		{Type: alert.Liveness, Timestamp: base.Add(-time.Hour)},
	}

	latest, found := LatestLiveness(alerts)
	if !found {
		t.Fatal("expected found=true")
	}
	if !latest.Equal(base.Add(-time.Hour)) {
		t.Errorf("expected the liveness timestamp, got %v", latest)
	}
}

func TestLatestLiveness_NotFoundWhenNoLivenessAlerts(t *testing.T) {
	alerts := []alert.Alert{
		{Type: alert.Duress, Timestamp: time.Now()},
	}

	_, found := LatestLiveness(alerts)
	if found {
		t.Fatal("expected found=false when only duress alerts are present")
	}
}

func TestLatestLiveness_NotFoundForEmptyInput(t *testing.T) {
	_, found := LatestLiveness(nil)
	if found {
		t.Fatal("expected found=false for empty input")
	}
}

func TestEvaluate_NotOverdueWithinInterval(t *testing.T) {
	lastSeen := time.Now()
	now := lastSeen.Add(15 * 24 * time.Hour) // well within 30-day interval

	status := Evaluate(lastSeen, true, now)
	if status.Overdue {
		t.Fatal("expected not overdue within interval")
	}
	if !status.HasSeenLiveness {
		t.Fatal("expected HasSeenLiveness=true")
	}
}

func TestEvaluate_NotOverdueDuringGracePeriod(t *testing.T) {
	lastSeen := time.Now()
	now := lastSeen.Add(checkin.Interval).Add(3 * 24 * time.Hour) // inside 7-day grace

	status := Evaluate(lastSeen, true, now)
	if status.Overdue {
		t.Fatal("expected not overdue during grace period")
	}
}

func TestEvaluate_NotOverdueExactlyAtDeadline(t *testing.T) {
	lastSeen := time.Now()
	deadline := lastSeen.Add(checkin.Interval).Add(checkin.GracePeriod)

	status := Evaluate(lastSeen, true, deadline)
	if status.Overdue {
		t.Fatal("expected not overdue exactly at the deadline boundary")
	}
}

func TestEvaluate_OverdueAfterGracePeriodElapses(t *testing.T) {
	lastSeen := time.Now()
	pastDeadline := lastSeen.Add(checkin.Interval).Add(checkin.GracePeriod).Add(time.Second)

	status := Evaluate(lastSeen, true, pastDeadline)
	if !status.Overdue {
		t.Fatal("expected overdue once grace period has elapsed")
	}
}

func TestEvaluate_NeverOverdueWithoutAnyLivenessSeen(t *testing.T) {
	// A guardian who has never received a liveness alert (e.g. setup
	// isn't complete, or the relay hasn't relayed anything yet) must not
	// be told the owner is overdue — that would be a false alarm from
	// guardian-side incompleteness, not owner silence.
	status := Evaluate(time.Time{}, false, time.Now())
	if status.Overdue {
		t.Fatal("expected Overdue=false when no liveness has ever been seen")
	}
	if status.HasSeenLiveness {
		t.Fatal("expected HasSeenLiveness=false")
	}
}

func TestEvaluate_MatchesOwnerSideCheckinDeadline(t *testing.T) {
	// The guardian-side deadline computation must agree exactly with the
	// owner's own checkin.IsOverdue — otherwise a guardian and the owner
	// could disagree about whether the switch has fired.
	created := time.Now()
	c, err := checkin.New("pass", "duress", created)
	if err != nil {
		t.Fatalf("checkin.New failed: %v", err)
	}

	pastDeadline := created.Add(checkin.Interval).Add(checkin.GracePeriod).Add(time.Minute)

	ownerSide := c.IsOverdue(pastDeadline)
	guardianSide := Evaluate(created, true, pastDeadline).Overdue

	if ownerSide != guardianSide {
		t.Fatalf("owner-side IsOverdue=%v disagrees with guardian-side Overdue=%v", ownerSide, guardianSide)
	}
}

