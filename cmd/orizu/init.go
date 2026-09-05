package main

import (
	"fmt"
	"os"
	"time"

	"github.com/xbuyan/orizu/internal/checkin"
)

// runInit creates a fresh CheckIn from a normal and duress passphrase
// entered interactively, and persists it to ~/.orizu/state.json. Refuses
// to overwrite an existing state file — re-initializing would silently
// discard whatever check-in history and guardian relationship already
// exists.
func runInit() error {
	path, err := statePath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("state already exists at %s — refusing to overwrite", path)
	}

	fmt.Fprintln(os.Stderr, "Setting up Orizu. You will set two passphrases:")
	fmt.Fprintln(os.Stderr, "  1. Your normal check-in passphrase.")
	fmt.Fprintln(os.Stderr, "  2. A duress passphrase — use this if you are ever forced to check in.")
	fmt.Fprintln(os.Stderr, "     It checks in identically, but silently alerts your guardians.")
	fmt.Fprintln(os.Stderr, "Both must be memorable without writing them down, and must differ from each other.")
	fmt.Fprintln(os.Stderr)

	passphrase, err := promptHidden("Normal passphrase: ")
	if err != nil {
		return err
	}
	duress, err := promptHidden("Duress passphrase: ")
	if err != nil {
		return err
	}

	c, err := checkin.New(passphrase, duress, time.Now())
	if err != nil {
		return err
	}

	if err := saveState(c); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Orizu initialized. Checked in as of now.")
	fmt.Fprintln(os.Stderr, "Remember to place your guardian config at", mustConfigPath())
	return nil
}

func mustConfigPath() string {
	p, err := configPath()
	if err != nil {
		return "~/.orizu/config.json"
	}
	return p
}

