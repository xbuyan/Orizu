package retryqueue

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/xbuyan/orizu/internal/relay"
)

func newTestRelay(t *testing.T) (*httptest.Server, *relay.Store) {
	t.Helper()
	store, err := relay.NewStore(t.TempDir(), relay.DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	server := relay.NewServer(store, "test-token")
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

func TestEnqueue_RejectsInvalidGuardianID(t *testing.T) {
	q, err := NewQueue(t.TempDir())
	if err != nil {
		t.Fatalf("NewQueue failed: %v", err)
	}
	if err := q.Enqueue("has spaces", []byte("blob"), time.Now()); err == nil {
		t.Fatal("expected error for invalid guardian id")
	}
}

func TestFlush_DeliversQueuedItemAndRemovesIt(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(dir)
	if err != nil {
		t.Fatalf("NewQueue failed: %v", err)
	}

	now := time.Now()
	if err := q.Enqueue("guardian-1", []byte("queued-blob"), now); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	ts, store := newTestRelay(t)
	client := relay.NewClient(ts.URL, "test-token")

	result, err := q.Flush(client, now)
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if result.Delivered != 1 || result.Remaining != 0 {
		t.Fatalf("expected 1 delivered, 0 remaining, got %+v", result)
	}

	// Confirm it actually reached the relay.
	blobs, err := store.List("guardian-1", now)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 1 || string(blobs[0]) != "queued-blob" {
		t.Fatalf("expected delivered blob at relay, got %v", blobs)
	}

	// A second flush should find nothing left to do.
	result2, err := q.Flush(client, now)
	if err != nil {
		t.Fatalf("second Flush failed: %v", err)
	}
	if result2.Delivered != 0 || result2.Remaining != 0 {
		t.Fatalf("expected empty queue on second flush, got %+v", result2)
	}
}

func TestFlush_LeavesItemQueuedOnContinuedFailure(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(dir)
	if err != nil {
		t.Fatalf("NewQueue failed: %v", err)
	}

	now := time.Now()
	if err := q.Enqueue("guardian-1", []byte("stuck-blob"), now); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Point at an address nothing is listening on.
	client := relay.NewClient("http://127.0.0.1:1", "test-token")

	result, err := q.Flush(client, now)
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if result.Delivered != 0 || result.Remaining != 1 {
		t.Fatalf("expected 0 delivered, 1 remaining, got %+v", result)
	}

	// The item must still be there for a future retry.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading queue dir failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 item still queued on disk, got %d", len(entries))
	}
}

func TestFlush_RecoversAfterRelayComesBack(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(dir)
	if err != nil {
		t.Fatalf("NewQueue failed: %v", err)
	}

	now := time.Now()
	if err := q.Enqueue("guardian-1", []byte("eventually-delivered"), now); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// First flush: relay is down.
	deadClient := relay.NewClient("http://127.0.0.1:1", "test-token")
	result1, err := q.Flush(deadClient, now)
	if err != nil {
		t.Fatalf("first Flush failed: %v", err)
	}
	if result1.Remaining != 1 {
		t.Fatalf("expected item still queued after failed flush, got %+v", result1)
	}

	// Relay comes back — this is the scenario the whole package exists for.
	ts, store := newTestRelay(t)
	liveClient := relay.NewClient(ts.URL, "test-token")
	result2, err := q.Flush(liveClient, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("second Flush failed: %v", err)
	}
	if result2.Delivered != 1 || result2.Remaining != 0 {
		t.Fatalf("expected successful delivery once relay is back, got %+v", result2)
	}

	blobs, _ := store.List("guardian-1", now)
	if len(blobs) != 1 || string(blobs[0]) != "eventually-delivered" {
		t.Fatalf("expected the originally-queued blob to arrive, got %v", blobs)
	}
}

func TestFlush_DropsItemsOlderThanMaxAge(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(dir)
	if err != nil {
		t.Fatalf("NewQueue failed: %v", err)
	}

	queuedAt := time.Now()
	if err := q.Enqueue("guardian-1", []byte("stale-blob"), queuedAt); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Even with a live relay, an item past MaxAge should be dropped, not delivered.
	ts, store := newTestRelay(t)
	client := relay.NewClient(ts.URL, "test-token")

	pastMaxAge := queuedAt.Add(MaxAge + time.Hour)
	result, err := q.Flush(client, pastMaxAge)
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if result.Dropped != 1 || result.Delivered != 0 {
		t.Fatalf("expected 1 dropped, 0 delivered, got %+v", result)
	}

	blobs, _ := store.List("guardian-1", pastMaxAge)
	if len(blobs) != 0 {
		t.Fatalf("expected stale item NOT delivered to relay, got %v", blobs)
	}
}

func TestFlush_HandlesMultipleItemsForDifferentGuardians(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQueue(dir)
	if err != nil {
		t.Fatalf("NewQueue failed: %v", err)
	}

	now := time.Now()
	if err := q.Enqueue("guardian-1", []byte("blob-1"), now); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	if err := q.Enqueue("guardian-2", []byte("blob-2"), now); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	ts, store := newTestRelay(t)
	client := relay.NewClient(ts.URL, "test-token")

	result, err := q.Flush(client, now)
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if result.Delivered != 2 {
		t.Fatalf("expected 2 delivered, got %+v", result)
	}

	b1, _ := store.List("guardian-1", now)
	b2, _ := store.List("guardian-2", now)
	if len(b1) != 1 || len(b2) != 1 {
		t.Fatalf("expected both guardians to receive their blob, got %v / %v", b1, b2)
	}
}

