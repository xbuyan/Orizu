package relay

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxAlertBodySize caps the accepted POST body. A sealed anonymous box for
// this package's tiny Alert struct runs well under 200 bytes; this limit
// is deliberately generous while still preventing an unbounded body from
// being read into memory.
const maxAlertBodySize = 4096

// defaultRateLimit and defaultRateBurst set a sensible production
// default. This relay serves exactly one owner and three guardians, not
// a multi-tenant service, so all legitimate traffic from a given source
// IP is bursty by nature: a single check-in can generate up to 6 rapid
// requests (up to 3 retry-queue flush attempts, plus 3 new per-guardian
// posts), essentially simultaneously. The burst is set generously above
// that — 20 — specifically because an initial, tighter value of 5 was
// tried and found, via real integration testing, to throttle entirely
// legitimate single-owner traffic. The sustained rate (~20/minute) still
// meaningfully bounds an attacker who'd need to flood far beyond normal
// usage to fill storage or cause load.
const (
	defaultRateLimit = rate.Limit(1.0 / 3.0) // ~20/minute sustained
	defaultRateBurst = 20
)

// Server exposes Store over HTTP. It is a thin layer only — all storage,
// validation, and expiry logic lives in Store; this type just translates
// HTTP requests into Store calls and Store results into HTTP responses.
//
// Two hardening measures live here, closing gaps this package's earlier
// version documented as accepted but unaddressed:
//
//  1. POST authentication. Alerts are anonymously sealed by design (no
//     sender identity inside the ciphertext to check), so without a
//     separate check, anyone who knows a guardian's ID could POST
//     spam that fills their inbox with garbage the guardian must sift
//     through. Given this relay's real usage model — one owner, one
//     relay instance, exactly three guardians, not a multi-tenant
//     service — a single shared POST token (known to the owner's
//     device, verified by the relay) is the right-sized fix. GET
//     remains unauthenticated deliberately: guardians only ever poll,
//     never post, and requiring guardians to also hold a secret token
//     would add real key-distribution complexity for a lower-severity
//     problem (an attacker who knows a guardian ID can at most learn
//     that some encrypted blobs exist and roughly when, not read them).
//     This asymmetry is a conscious trade-off, not an oversight.
//  2. Per-IP rate limiting on every request, POST and GET alike, using
//     golang.org/x/time/rate — an audited, standard token-bucket
//     implementation, not hand-rolled throttling logic.
type Server struct {
	store     *Store
	now       func() time.Time // overridable for tests; defaults to time.Now
	postToken string

	limiterMu sync.Mutex
	limiters  map[string]*rate.Limiter
	rateLimit rate.Limit
	rateBurst int
}

// NewServer wraps store for HTTP access, requiring postToken for all POST
// requests and applying sensible default rate limits. postToken must be
// non-empty — see the package doc for why authentication is required at
// all despite the relay's zero-knowledge design.
func NewServer(store *Store, postToken string) *Server {
	return newServerWithRateLimit(store, postToken, defaultRateLimit, defaultRateBurst)
}

// NewServerWithRateLimit is like NewServer but allows overriding the rate
// limit and burst — primarily for tests that need fast, deterministic
// throttling rather than waiting on real time.
func NewServerWithRateLimit(store *Store, postToken string, limit rate.Limit, burst int) *Server {
	return newServerWithRateLimit(store, postToken, limit, burst)
}

func newServerWithRateLimit(store *Store, postToken string, limit rate.Limit, burst int) *Server {
	return &Server{
		store:     store,
		now:       time.Now,
		postToken: postToken,
		limiters:  make(map[string]*rate.Limiter),
		rateLimit: limit,
		rateBurst: burst,
	}
}

// Handler returns the http.Handler for this server, wrapped with rate
// limiting. Wire it into an http.Server (or httptest.Server in tests)
// directly.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /alerts/{guardianID}", s.handlePost)
	mux.HandleFunc("GET /alerts/{guardianID}", s.handleGet)
	return s.rateLimitMiddleware(mux)
}

// rateLimitMiddleware applies a per-source-IP token bucket to every
// request, POST and GET alike. The identifying IP is taken from
// r.RemoteAddr, not an X-Forwarded-For-style header — trusting such a
// header by default would let any client spoof a different rate-limit
// identity unless this server is known to sit behind a trusted proxy
// that sets it. If this relay is ever deployed behind a reverse proxy,
// that proxy's real-IP header needs to be wired in deliberately; using
// RemoteAddr unconditionally is the safer default in the meantime.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr // fall back to the raw value rather than failing open silently
		}

		s.limiterMu.Lock()
		limiter, ok := s.limiters[ip]
		if !ok {
			limiter = rate.NewLimiter(s.rateLimit, s.rateBurst)
			s.limiters[ip] = limiter
		}
		s.limiterMu.Unlock()

		if !limiter.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkPostAuth verifies the Authorization: Bearer <token> header against
// the configured postToken using a constant-time comparison, so response
// timing can't be used to guess the token byte-by-byte.
func (s *Server) checkPostAuth(r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return false
	}
	provided := header[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.postToken)) == 1
}

// handlePost accepts a sealed alert blob for a guardian, after verifying
// the caller presented the correct shared POST token. The body is stored
// exactly as received — this server never inspects, decrypts, or
// interprets it.
func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	if !s.checkPostAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

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
// Deliberately unauthenticated — see the package doc's rationale.
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

