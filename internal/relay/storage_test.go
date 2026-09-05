package relay

import (
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir, DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	return store
}

func TestPutList_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()

	id, err := store.Put("guardian-1", []byte("sealed-bytes"), now)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty id")
	}

	blobs, err := store.List("guardian-1", now)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 1 {
		t.Fatalf("expected 1 blob, got %d", len(blobs))
	}
	if string(blobs[0]) != "sealed-bytes" {
		t.Errorf("expected %q, got %q", "sealed-bytes", blobs[0])
	}
}

func TestList_UnknownGuardianReturnsEmptyNotError(t *testing.T) {
	store := newTestStore(t)

	blobs, err := store.List("never-seen", time.Now())
	if err != nil {
		t.Fatalf("expected no error for unknown guardian, got %v", err)
	}
	if len(blobs) != 0 {
		t.Fatalf("expected empty slice, got %d blobs", len(blobs))
	}
}

func TestList_RejectsInvalidGuardianID(t *testing.T) {
	store := newTestStore(t)

	invalidIDs := []string{"", "../escape", "has spaces", "slash/in/id"}
	for _, id := range invalidIDs {
		if _, err := store.List(id, time.Now()); err != ErrInvalidGuardianID {
			t.Errorf("List(%q): expected ErrInvalidGuardianID, got %v", id, err)
		}
		if _, err := store.Put(id, []byte("x"), time.Now()); err != ErrInvalidGuardianID {
			t.Errorf("Put(%q): expected ErrInvalidGuardianID, got %v", id, err)
		}
	}
}

func TestPut_MultipleAlertsCoexistForSameGuardian(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()

	if _, err := store.Put("guardian-1", []byte("first"), now); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if _, err := store.Put("guardian-1", []byte("second"), now.Add(time.Minute)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	blobs, err := store.List("guardian-1", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 2 {
		t.Fatalf("expected 2 blobs, got %d", len(blobs))
	}
}

func TestList_ExcludesExpiredAlerts(t *testing.T) {
	store := newTestStore(t)
	stored := time.Now()

	if _, err := store.Put("guardian-1", []byte("old"), stored); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Just within the expiry window.
	withinWindow := stored.Add(DefaultExpiry - time.Hour)
	blobs, err := store.List("guardian-1", withinWindow)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 1 {
		t.Fatalf("expected 1 blob within expiry window, got %d", len(blobs))
	}

	// Past the expiry window.
	pastWindow := stored.Add(DefaultExpiry + time.Hour)
	blobs, err = store.List("guardian-1", pastWindow)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 0 {
		t.Fatalf("expected 0 blobs past expiry window, got %d", len(blobs))
	}
}

func TestList_DoesNotDeleteOnFetch(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()

	if _, err := store.Put("guardian-1", []byte("persistent"), now); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Fetch twice; the second fetch should still see the alert, since
	// retention is expiry-based, not delete-on-read.
	if blobs, err := store.List("guardian-1", now); err != nil || len(blobs) != 1 {
		t.Fatalf("first List: got %d blobs, err %v", len(blobs), err)
	}
	if blobs, err := store.List("guardian-1", now); err != nil || len(blobs) != 1 {
		t.Fatalf("second List: got %d blobs, err %v", len(blobs), err)
	}
}

func TestPut_DifferentGuardiansAreIsolated(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()

	if _, err := store.Put("guardian-1", []byte("for-one"), now); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if _, err := store.Put("guardian-2", []byte("for-two"), now); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	blobs1, _ := store.List("guardian-1", now)
	blobs2, _ := store.List("guardian-2", now)

	if len(blobs1) != 1 || string(blobs1[0]) != "for-one" {
		t.Errorf("guardian-1: expected [\"for-one\"], got %v", blobs1)
	}
	if len(blobs2) != 1 || string(blobs2[0]) != "for-two" {
		t.Errorf("guardian-2: expected [\"for-two\"], got %v", blobs2)
	}
}

func TestNewStore_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	store1, err := NewStore(dir, DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if _, err := store1.Put("guardian-1", []byte("survives-restart"), now); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Simulate a relay restart: open a fresh Store over the same directory.
	store2, err := NewStore(dir, DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore (reopen) failed: %v", err)
	}
	blobs, err := store2.List("guardian-1", now)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 1 || string(blobs[0]) != "survives-restart" {
		t.Fatalf("expected alert to survive reopen, got %v", blobs)
	}
}