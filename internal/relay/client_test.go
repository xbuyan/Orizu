package relay

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_PostSucceedsAndStoresBlob(t *testing.T) {
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	server := NewServer(store)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := NewClient(ts.URL)
	if err := client.Post("guardian-1", []byte("client-sent-blob")); err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	blobs, err := store.List("guardian-1", time.Now())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 1 || string(blobs[0]) != "client-sent-blob" {
		t.Fatalf("expected stored blob %q, got %v", "client-sent-blob", blobs)
	}
}

func TestClient_PostFailsOnInvalidGuardianID(t *testing.T) {
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	server := NewServer(store)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := NewClient(ts.URL)
	if err := client.Post("has spaces", []byte("blob")); err == nil {
		t.Fatal("expected error for invalid guardian id")
	}
}

func TestClient_PostFailsWhenRelayUnreachable(t *testing.T) {
	client := NewClient("http://127.0.0.1:1") // deliberately unreachable
	if err := client.Post("guardian-1", []byte("blob")); err == nil {
		t.Fatal("expected error when relay is unreachable")
	}
}

func TestClient_FetchReturnsDecodedBlobs(t *testing.T) {
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	server := NewServer(store)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	if _, err := store.Put("guardian-1", []byte("fetched-blob"), time.Now()); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	client := NewClient(ts.URL)
	blobs, err := client.Fetch("guardian-1")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if len(blobs) != 1 || string(blobs[0]) != "fetched-blob" {
		t.Fatalf("expected [\"fetched-blob\"], got %v", blobs)
	}
}

func TestClient_FetchEmptyForUnknownGuardian(t *testing.T) {
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	server := NewServer(store)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := NewClient(ts.URL)
	blobs, err := client.Fetch("never-seen")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if len(blobs) != 0 {
		t.Fatalf("expected empty result, got %v", blobs)
	}
}

func TestClient_PostThenFetchEndToEnd(t *testing.T) {
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	server := NewServer(store)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := NewClient(ts.URL)
	if err := client.Post("guardian-1", []byte("round-trip-blob")); err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	blobs, err := client.Fetch("guardian-1")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if len(blobs) != 1 || string(blobs[0]) != "round-trip-blob" {
		t.Fatalf("expected [\"round-trip-blob\"], got %v", blobs)
	}
}

