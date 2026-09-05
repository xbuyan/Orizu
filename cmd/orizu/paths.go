package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xbuyan/orizu/internal/checkin"
)

// orizuDir returns ~/.orizu, creating it if needed.
func orizuDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	dir := filepath.Join(home, ".orizu")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	return dir, nil
}

func statePath() (string, error) {
	dir, err := orizuDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "state.json"), nil
}

func configPath() (string, error) {
	dir, err := orizuDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// loadState reads and deserializes the persisted CheckIn from state.json.
func loadState() (*checkin.CheckIn, error) {
	path, err := statePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no state found at %s — run `orizu init` first", path)
		}
		return nil, fmt.Errorf("reading state: %w", err)
	}

	var c checkin.CheckIn
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing state: %w", err)
	}
	return &c, nil
}

// saveState serializes c to state.json. Written with 0600 permissions
// since it contains bcrypt hashes of both passphrases.
func saveState(c *checkin.CheckIn) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	return nil
}

