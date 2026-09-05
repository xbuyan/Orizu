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

