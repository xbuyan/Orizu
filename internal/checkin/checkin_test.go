package checkin

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestNew_RejectsEmptyPassphrase(t *testing.T) {
	now := time.Now()
	if _, err := New("", "duress", now); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("expected ErrEmptyPassphrase for empty normal passphrase, got %v", err)
	}
	if _, err := New("normal", "", now); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("expected ErrEmptyPassphrase for empty duress passphrase, got %v", err)
	}
}

func TestNew_RejectsIdenticalPassphrases(t *testing.T) {
	now := time.Now()
	if _, err := New("same-secret", "same-secret", now); !errors.Is(err, ErrSamePassphrase) {
		t.Fatalf("expected ErrSamePassphrase, got %v", err)
	}
}

func TestNew_InitializesLastCheckInToNow(t *testing.T) {
	now := time.Now()
	c, err := New("normal-pass", "duress-pass", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.LastCheckIn().Equal(now) {
		t.Fatalf("expected LastCheckIn to equal creation time %v, got %v", now, c.LastCheckIn())
	}
}

func TestRecord_NormalPassphraseChecksInWithoutDuress(t *testing.T) {
	created := time.Now()
	c, err := New("normal-pass", "duress-pass", created)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	later := created.Add(24 * time.Hour)
	result, err := c.Record("normal-pass", later)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DuressDetected {
		t.Fatal("expected DuressDetected=false for normal passphrase")
	}
	if !c.LastCheckIn().Equal(later) {
		t.Fatalf("expected LastCheckIn updated to %v, got %v", later, c.LastCheckIn())
	}
}

func TestRecord_DuressPassphraseChecksInAndFlagsDuress(t *testing.T) {
	created := time.Now()
	c, err := New("normal-pass", "duress-pass", created)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	later := created.Add(24 * time.Hour)
	result, err := c.Record("duress-pass", later)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.DuressDetected {
		t.Fatal("expected DuressDetected=true for duress passphrase")
	}
	// The check-in timestamp updates identically regardless of which
	// passphrase was used — an observer watching only LastCheckIn cannot
	// tell duress from normal.
	if !c.LastCheckIn().Equal(later) {
		t.Fatalf("expected LastCheckIn updated to %v, got %v", later, c.LastCheckIn())
	}
}

func TestRecord_InvalidPassphraseLeavesStateUnchanged(t *testing.T) {
	created := time.Now()
	c, err := New("normal-pass", "duress-pass", created)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	later := created.Add(24 * time.Hour)
	_, err = c.Record("wrong-pass", later)
	if !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("expected ErrInvalidPassphrase, got %v", err)
	}
	if !c.LastCheckIn().Equal(created) {
		t.Fatalf("expected LastCheckIn to remain %v after failed check-in, got %v", created, c.LastCheckIn())
	}
}

func TestIsOverdue_FalseWithinInterval(t *testing.T) {
	created := time.Now()
	c, _ := New("normal-pass", "duress-pass", created)

	check := created.Add(15 * 24 * time.Hour) // well within the 30-day interval
	if c.IsOverdue(check) {
		t.Fatal("expected not overdue within the check-in interval")
	}
}

func TestIsOverdue_FalseDuringGracePeriod(t *testing.T) {
	created := time.Now()
	c, _ := New("normal-pass", "duress-pass", created)

	// 3 days past the 30-day interval, still inside the 7-day grace period.
	check := created.Add(Interval).Add(3 * 24 * time.Hour)
	if c.IsOverdue(check) {
		t.Fatal("expected not overdue while still within grace period")
	}
}

func TestIsOverdue_FalseExactlyAtDeadline(t *testing.T) {
	created := time.Now()
	c, _ := New("normal-pass", "duress-pass", created)

	deadline := created.Add(Interval).Add(GracePeriod)
	if c.IsOverdue(deadline) {
		t.Fatal("expected not overdue exactly at the deadline boundary (only After is overdue)")
	}
}

func TestIsOverdue_TrueAfterGracePeriodElapses(t *testing.T) {
	created := time.Now()
	c, _ := New("normal-pass", "duress-pass", created)

	pastDeadline := created.Add(Interval).Add(GracePeriod).Add(time.Second)
	if !c.IsOverdue(pastDeadline) {
		t.Fatal("expected overdue once grace period has elapsed")
	}
}

func TestIsOverdue_ResetByFreshCheckIn(t *testing.T) {
	created := time.Now()
	c, _ := New("normal-pass", "duress-pass", created)

	// Check in again just before the original deadline would have hit.
	almostOverdue := created.Add(Interval).Add(GracePeriod).Add(-time.Hour)
	if _, err := c.Record("normal-pass", almostOverdue); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The old deadline has now passed, but a fresh check-in should have
	// pushed the real deadline forward.
	oldDeadline := created.Add(Interval).Add(GracePeriod).Add(time.Hour)
	if c.IsOverdue(oldDeadline) {
		t.Fatal("expected not overdue — check-in should have reset the deadline")
	}
}

func TestIsOverdue_DuressCheckInAlsoResetsDeadline(t *testing.T) {
	created := time.Now()
	c, _ := New("normal-pass", "duress-pass", created)

	almostOverdue := created.Add(Interval).Add(GracePeriod).Add(-time.Hour)
	result, err := c.Record("duress-pass", almostOverdue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.DuressDetected {
		t.Fatal("expected duress to be detected")
	}

	oldDeadline := created.Add(Interval).Add(GracePeriod).Add(time.Hour)
	if c.IsOverdue(oldDeadline) {
		t.Fatal("expected not overdue — a duress check-in must reset the deadline identically to a normal one")
	}
}

func TestMarshalUnmarshalJSON_RoundTrip(t *testing.T) {
	created := time.Now().Truncate(time.Second) // JSON round-trips to second precision
	original, err := New("normal-pass", "duress-pass", created)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var restored CheckIn
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if !restored.LastCheckIn().Equal(created) {
		t.Errorf("expected LastCheckIn=%v, got %v", created, restored.LastCheckIn())
	}

	// The restored CheckIn must still accept the original passphrases —
	// proof that the hashes themselves, not just the timestamp, survived
	// the round trip.
	if _, err := restored.Record("normal-pass", created.Add(time.Hour)); err != nil {
		t.Errorf("restored CheckIn rejected the original normal passphrase: %v", err)
	}
}

func TestMarshalUnmarshalJSON_PreservesDuressDetection(t *testing.T) {
	created := time.Now().Truncate(time.Second)
	original, err := New("normal-pass", "duress-pass", created)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var restored CheckIn
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	result, err := restored.Record("duress-pass", created.Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.DuressDetected {
		t.Fatal("expected restored CheckIn to still detect the duress passphrase after round trip")
	}
}

