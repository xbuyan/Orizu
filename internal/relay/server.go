package relay

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

// maxAlertBodySize caps the accepted POST body. A sealed anonymous box for
// this package's tiny Alert struct runs well under 200 bytes; this limit
// is deliberately generous while still preventing an unbounded body from
// being read into memory.
const maxAlertBodySize = 4096

// Server exposes Store over HTTP. It is a thin layer only — all storage,
// validation, and expiry logic lives in Store; this type just translates
// HTTP requests into Store calls and Store results into HTTP responses.
type Server struct {
	store *Store
	now   func() time.Time // overridable for tests; defaults to time.Now
}

// NewServer wraps store for HTTP access.
func NewServer(store *Store) *Server {
	return &Server{store: store, now: time.Now}
}

// Handler returns the http.Handler for this server. Wire it into an
// http.Server (or httptest.Server in tests) directly.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /alerts/{guardianID}", s.handlePost)
	mux.HandleFunc("GET /alerts/{guardianID}", s.handleGet)
	return mux
}

// handlePost accepts a sealed alert blob for a guardian. The body is
// stored exactly as received — this server never inspects, decrypts, or
// interprets it. See the package doc for the known lack of sender
// authentication.
func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	guardianID := r.PathValue("guardianID")

	body, err := io.ReadAll(io.LimitReader(r.Body, maxAlertBodySize+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if len(body) > maxAlertBodySize {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	id, err := s.store.Put(guardianID, body, s.now())
	if err != nil {
		if err == ErrInvalidGuardianID {
			http.Error(w, "invalid guardian id", http.StatusBadRequest)
			return
		}
		log.Printf("relay: storing alert failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
}

// alertsResponse is the JSON shape returned by handleGet. Blobs are opaque
// ciphertext, so they're base64-encoded for safe transport in JSON — this
// server does not decode or interpret them.
type alertsResponse struct {
	Alerts []string `json:"alerts"`
}

// handleGet returns every non-expired alert blob stored for a guardian.
// A guardian with no alerts (or an unrecognized but validly-formatted ID)
// gets an empty list, not an error — an empty inbox isn't a failure.
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	guardianID := r.PathValue("guardianID")

	blobs, err := s.store.List(guardianID, s.now())
	if err != nil {
		if err == ErrInvalidGuardianID {
			http.Error(w, "invalid guardian id", http.StatusBadRequest)
			return
		}
		log.Printf("relay: listing alerts failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := alertsResponse{Alerts: make([]string, len(blobs))}
	for i, b := range blobs {
		resp.Alerts[i] = base64.StdEncoding.EncodeToString(b)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}