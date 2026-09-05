package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// runKeygen generates a fresh NaCl keypair for this guardian, prompts for
// their chosen ID and the relay URL, and saves everything to
// ~/.orizu-guardian/key.json. Refuses to overwrite an existing key —
// regenerating would silently invalidate whatever public key was already
// shared with (and configured by) the owner.
func runKeygen() error {
	path, err := keyFilePath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("a key already exists at %s — refusing to overwrite. "+
			"If you genuinely need a new key, tell the owner first so they can "+
			"update their config with your new public key", path)
	}

	fmt.Fprintln(os.Stderr, "Setting up your Orizu guardian key.")
	fmt.Fprintln(os.Stderr, "Your private key stays on this machine and is never shared with anyone.")
	fmt.Fprintln(os.Stderr, "Only the public key printed at the end should be given to the owner —")
	fmt.Fprintln(os.Stderr, "and it should go over a channel where you can verify it's really them")
	fmt.Fprintln(os.Stderr, "(in person, a call, or a channel you already trust).")
	fmt.Fprintln(os.Stderr)

	id, err := promptVisible("Choose a guardian ID (share this with the owner too): ")
	if err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("guardian ID must not be empty")
	}

	relayURL, err := promptVisible("Relay URL (given to you by the owner): ")
	if err != nil {
		return err
	}
	if relayURL == "" {
		return fmt.Errorf("relay URL must not be empty")
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	kf := &keyFile{
		ID:       id,
		RelayURL: relayURL,
		PubKey:   base64.StdEncoding.EncodeToString(pub[:]),
		PrivKey:  base64.StdEncoding.EncodeToString(priv[:]),
	}
	if err := saveKeyFile(kf); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Key generated and saved.")
	fmt.Fprintln(os.Stderr, "Give the owner BOTH of these values (public key only — never the private key):")
	fmt.Fprintln(os.Stderr, "  Guardian ID:", id)
	fmt.Fprintln(os.Stderr, "  Public key: ", kf.PubKey)
	return nil
}

