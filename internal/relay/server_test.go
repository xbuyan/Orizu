package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	return NewServer(store), store
}

func TestPostAlert_StoresAndReturnsID(t *testing.T) {
	server, store := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/alerts/guardian-1", "application/octet-stream", strings.NewReader("sealed-blob"))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response failed: %v", err)
	}
	if body["id"] == "" {
		t.Fatal("expected non-empty id in response")
	}

	// Confirm it actually landed in the store, not just an HTTP-level echo.
	blobs, err := store.List("guardian-1", time.Now())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(blobs) != 1 || string(blobs[0]) != "sealed-blob" {
		t.Fatalf("expected stored blob %q, got %v", "sealed-blob", blobs)
	}
}

func TestPostAlert_RejectsEmptyBody(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/alerts/guardian-1", "application/octet-stream", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", resp.StatusCode)
	}
}

func TestPostAlert_RejectsOversizedBody(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	oversized := strings.Repeat("x", maxAlertBodySize+1)
	resp, err := http.Post(ts.URL+"/alerts/guardian-1", "application/octet-stream", strings.NewReader(oversized))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", resp.StatusCode)
	}
}

func TestPostAlert_RejectsInvalidGuardianID(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	// Path segments containing "/" can't reach PathValue as one piece via a
	// simple POST to this URL, so we exercise the invalid-charset case
	// instead (space is not URL-safe unescaped, so use a char the pattern
	// rejects but is still transportable, e.g. "@").
	resp, err := http.Post(ts.URL+"/alerts/invalid@id", "application/octet-stream", strings.NewReader("blob"))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid guardian id, got %d", resp.StatusCode)
	}
}

func TestGetAlerts_ReturnsBase64EncodedBlobs(t *testing.T) {
	server, store := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	now := time.Now()
	if _, err := store.Put("guardian-1", []byte("raw-sealed-bytes"), now); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	resp, err := http.Get(ts.URL + "/alerts/guardian-1")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body alertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response failed: %v", err)
	}
	if len(body.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(body.Alerts))
	}

	decoded, err := base64.StdEncoding.DecodeString(body.Alerts[0])
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if string(decoded) != "raw-sealed-bytes" {
		t.Fatalf("expected %q, got %q", "raw-sealed-bytes", decoded)
	}
}

func TestGetAlerts_UnknownGuardianReturnsEmptyList(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/alerts/never-seen")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for unknown guardian, got %d", resp.StatusCode)
	}

	var body alertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response failed: %v", err)
	}
	if len(body.Alerts) != 0 {
		t.Fatalf("expected empty alerts list, got %d", len(body.Alerts))
	}
}

func TestEndToEnd_PostThenGetRoundTrips(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	postResp, err := http.Post(ts.URL+"/alerts/guardian-1", "application/octet-stream", strings.NewReader("end-to-end-blob"))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	postResp.Body.Close()

	getResp, err := http.Get(ts.URL + "/alerts/guardian-1")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer getResp.Body.Close()

	var body alertsResponse
	if err := json.NewDecoder(getResp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response failed: %v", err)
	}
	if len(body.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(body.Alerts))
	}
	decoded, _ := base64.StdEncoding.DecodeString(body.Alerts[0])
	if string(decoded) != "end-to-end-blob" {
		t.Fatalf("expected %q, got %q", "end-to-end-blob", decoded)
	}
}