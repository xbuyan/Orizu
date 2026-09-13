package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

const testPostToken = "test-shared-token-abc123"

func newTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	// Generous rate limit for tests that aren't specifically testing
	// rate-limiting behavior, so unrelated tests don't flake under load.
	return NewServerWithRateLimit(store, testPostToken, rate.Limit(1000), 1000), store
}

func authedPost(t *testing.T, url string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("building request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+testPostToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	return resp
}

func TestPostAlert_StoresAndReturnsID(t *testing.T) {
	server, store := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := authedPost(t, ts.URL+"/alerts/guardian-1", "sealed-blob")
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

func TestPostAlert_RejectsMissingAuth(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	// Plain http.Post sends no Authorization header at all.
	resp, err := http.Post(ts.URL+"/alerts/guardian-1", "application/octet-stream", strings.NewReader("sealed-blob"))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing auth, got %d", resp.StatusCode)
	}
}

func TestPostAlert_RejectsWrongToken(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/alerts/guardian-1", strings.NewReader("sealed-blob"))
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", resp.StatusCode)
	}
}

func TestPostAlert_RejectsMalformedAuthHeader(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/alerts/guardian-1", strings.NewReader("sealed-blob"))
	req.Header.Set("Authorization", testPostToken) // missing "Bearer " prefix
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for malformed auth header, got %d", resp.StatusCode)
	}
}

func TestGetAlerts_RequiresNoAuth(t *testing.T) {
	server, store := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	if _, err := store.Put("guardian-1", []byte("raw-sealed-bytes"), time.Now()); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Plain http.Get, no Authorization header — must succeed, by design.
	resp, err := http.Get(ts.URL + "/alerts/guardian-1")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for unauthenticated GET, got %d", resp.StatusCode)
	}
}

func TestPostAlert_RejectsEmptyBody(t *testing.T) {
	server, _ := newTestServer(t)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	resp := authedPost(t, ts.URL+"/alerts/guardian-1", "")
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
	resp := authedPost(t, ts.URL+"/alerts/guardian-1", oversized)
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
	resp := authedPost(t, ts.URL+"/alerts/invalid@id", "blob")
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

	postResp := authedPost(t, ts.URL+"/alerts/guardian-1", "end-to-end-blob")
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

func TestRateLimit_BlocksBurstExceedingLimit(t *testing.T) {
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	// A tiny, deterministic limit: burst of 2, then throttled — no need
	// to wait on real time to observe this.
	server := NewServerWithRateLimit(store, testPostToken, rate.Limit(0.001), 2)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	var statuses []int
	for i := 0; i < 4; i++ {
		resp, err := http.Get(ts.URL + "/alerts/guardian-1")
		if err != nil {
			t.Fatalf("GET failed: %v", err)
		}
		statuses = append(statuses, resp.StatusCode)
		resp.Body.Close()
	}

	// First 2 (the burst) should succeed; at least one after that must be
	// throttled.
	if statuses[0] != http.StatusOK || statuses[1] != http.StatusOK {
		t.Fatalf("expected first 2 requests within burst to succeed, got %v", statuses)
	}
	throttled := false
	for _, s := range statuses[2:] {
		if s == http.StatusTooManyRequests {
			throttled = true
		}
	}
	if !throttled {
		t.Fatalf("expected at least one request beyond the burst to be rate-limited, got %v", statuses)
	}
}

func TestRateLimit_TracksDifferentIPsIndependently(t *testing.T) {
	// This test documents the intended behavior (per-IP, not global)
	// without simulating multiple real source IPs — httptest.Server
	// requests all arrive from the same loopback address, so a true
	// multi-IP test would need a different harness. Instead, this
	// confirms the limiter map keys by RemoteAddr's host, which is the
	// mechanism that makes per-IP isolation possible.
	store, err := NewStore(t.TempDir(), DefaultExpiry)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	server := NewServerWithRateLimit(store, testPostToken, rate.Limit(1000), 1000)

	req1 := httptest.NewRequest(http.MethodGet, "/alerts/guardian-1", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	req2 := httptest.NewRequest(http.MethodGet, "/alerts/guardian-1", nil)
	req2.RemoteAddr = "10.0.0.2:5678"

	w1 := httptest.NewRecorder()
	server.Handler().ServeHTTP(w1, req1)
	w2 := httptest.NewRecorder()
	server.Handler().ServeHTTP(w2, req2)

	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("expected both distinct-IP requests to succeed, got %d and %d", w1.Code, w2.Code)
	}

	server.limiterMu.Lock()
	numLimiters := len(server.limiters)
	server.limiterMu.Unlock()
	if numLimiters != 2 {
		t.Fatalf("expected 2 independent per-IP limiters to have been created, got %d", numLimiters)
	}
}

