// Command orizu-relay runs Orizu's relay as a standalone, deployable
// service — the piece that was previously only a library (internal/relay)
// proven in tests, never something that actually ran in production.
//
// Three modes, chosen by which flags are set:
//
//  1. Automatic HTTPS via Let's Encrypt (recommended for real deployment):
//     -autocert-domain example.com
//     No manual certificate management — golang.org/x/crypto/acme/autocert
//     provisions and renews certificates automatically, as long as this
//     process is reachable on port 443 for the ACME HTTP-01 challenge.
//
//  2. Manually-provided TLS certificate:
//     -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem
//     For deployments behind infrastructure that already issues certs
//     some other way.
//
//  3. Plain HTTP, no TLS — for local development only. This mode prints a
//     loud warning and should never be used for a real deployment: even
//     though relay payloads are opaque (see internal/relay's package
//     doc), plain HTTP still leaks metadata — which guardian ID is being
//     posted to or polled, and when — to anyone observing the connection.
//     This is exactly the gap Orizu's THREAT_MODEL.md has flagged since
//     the relay was first built; this command's HTTPS modes are what
//     finally close it, but only if one of them is actually used.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xbuyan/orizu/internal/relay"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	addr := flag.String("addr", ":8443", "address to listen on")
	dataDir := flag.String("data", "./orizu-relay-data", "directory for persisted alert storage")
	autocertDomain := flag.String("autocert-domain", "", "domain name for automatic Let's Encrypt HTTPS (recommended for real deployment)")
	autocertCacheDir := flag.String("autocert-cache", "./orizu-relay-certs", "directory to cache Let's Encrypt certificates")
	tlsCert := flag.String("tls-cert", "", "path to a TLS certificate file (alternative to -autocert-domain)")
	tlsKey := flag.String("tls-key", "", "path to a TLS private key file (alternative to -autocert-domain)")
	insecureHTTP := flag.Bool("insecure-http", false, "run without TLS — DEVELOPMENT ONLY, never for real deployment")
	flag.Parse()

	if *autocertDomain != "" && (*tlsCert != "" || *tlsKey != "") {
		log.Fatal("orizu-relay: specify either -autocert-domain or -tls-cert/-tls-key, not both")
	}
	if *autocertDomain == "" && *tlsCert == "" && *tlsKey == "" && !*insecureHTTP {
		log.Fatal("orizu-relay: refusing to start without TLS. Use -autocert-domain, " +
			"-tls-cert/-tls-key, or explicitly pass -insecure-http if you understand " +
			"the risk and this is genuinely local development only.")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("orizu-relay: -tls-cert and -tls-key must both be set, or neither")
	}

	store, err := relay.NewStore(*dataDir, relay.DefaultExpiry)
	if err != nil {
		log.Fatalf("orizu-relay: initializing storage: %v", err)
	}
	server := relay.NewServer(store)

	srv := &http.Server{
		Addr:         *addr,
		Handler:      server.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serveErr := make(chan error, 1)

	switch {
	case *autocertDomain != "":
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*autocertDomain),
			Cache:      autocert.DirCache(*autocertCacheDir),
		}
		srv.TLSConfig = manager.TLSConfig()
		srv.Addr = ":443"
		if *addr != ":8443" {
			log.Println("orizu-relay: -addr is ignored in autocert mode; binding :443 as required for ACME")
		}
		log.Printf("orizu-relay: starting with automatic HTTPS for %s (Let's Encrypt), storage at %s", *autocertDomain, *dataDir)
		go func() { serveErr <- srv.ListenAndServeTLS("", "") }()

	case *tlsCert != "":
		log.Printf("orizu-relay: starting HTTPS on %s with provided certificate, storage at %s", srv.Addr, *dataDir)
		go func() { serveErr <- srv.ListenAndServeTLS(*tlsCert, *tlsKey) }()

	default:
		log.Println("=======================================================================")
		log.Println("WARNING: running WITHOUT TLS (-insecure-http). This is for local")
		log.Println("development only. Never expose this mode on a real network — guardian")
		log.Println("IDs and alert timing are visible to anyone observing the connection.")
		log.Println("=======================================================================")
		log.Printf("orizu-relay: starting plain HTTP on %s, storage at %s", srv.Addr, *dataDir)
		go func() { serveErr <- srv.ListenAndServe() }()
	}

	// Graceful shutdown: on SIGINT/SIGTERM, stop accepting new connections
	// and give in-flight requests a bounded window to finish, rather than
	// dropping them mid-response.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("orizu-relay: server error: %v", err)
		}
	case sig := <-stop:
		log.Printf("orizu-relay: received %s, shutting down gracefully", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("orizu-relay: graceful shutdown failed: %v", err)
		} else {
			log.Println("orizu-relay: shut down cleanly")
		}
	}
}

