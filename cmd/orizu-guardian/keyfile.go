package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keyFile is the on-disk shape of a guardian's identity: their chosen ID
// (must match what they give the owner to put in config.json), the relay
// URL they poll, and their NaCl keypair.
type keyFile struct {
	ID       string `json:"id"`
	RelayURL string `json:"relay_url"`
	PubKey   string `json:"pub_key"`  // base64
	PrivKey  string `json:"priv_key"` // base64 — never shared with anyone
}

func guardianDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	dir := filepath.Join(home, ".orizu-guardian")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	return dir, nil
}

func keyFilePath() (string, error) {
	dir, err := guardianDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "key.json"), nil
}

func loadKeyFile() (*keyFile, error) {
	path, err := keyFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no key found at %s — run `orizu-guardian keygen` first", path)
		}
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parsing key file: %w", err)
	}
	return &kf, nil
}

func saveKeyFile(kf *keyFile) error {
	path, err := keyFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding key file: %w", err)
	}
	// 0600: contains the private key.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing key file: %w", err)
	}
	return nil
}

// promptVisible reads a line of plain (non-secret) input, echoed normally.
// Used for the guardian ID and relay URL, neither of which is sensitive.
func promptVisible(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// decode32 base64-decodes a 32-byte key, validating its length.
func decode32(s string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return &out, nil
}

