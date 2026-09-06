package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/term"
)

// stdinReader is a single, shared bufio.Reader over os.Stdin, used by
// promptHidden's non-terminal fallback path.
//
// This matters more than it looks: a bufio.Reader created fresh per call
// buffers greedily from the underlying stream on its first Read — if
// stdin delivers multiple lines back-to-back (piped input, an automation
// script, or two prompts in quick succession, as `orizu init` does for its
// normal and duress passphrases), a throwaway reader can consume a later
// prompt's line into a buffer that then gets discarded when the reader
// goes out of scope, causing the next prompt to see an unexpected EOF.
// Sharing one reader across all prompts in a command avoids losing that
// buffered-but-unconsumed input. This only affects the non-terminal
// fallback — term.ReadPassword reads directly from the terminal fd
// byte-by-byte and isn't subject to this.
var stdinReader = bufio.NewReader(os.Stdin)

// promptHidden prints label and reads a line from stdin without echoing
// it to the terminal — used for passphrase entry so it isn't visible on
// screen or in shell history. Falls back to a visible bufio read if stdin
// isn't a real terminal (e.g. piped input in tests or scripts).
func promptHidden(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		bytes, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading passphrase: %w", err)
		}
		return string(bytes), nil
	}

	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	// Trim trailing newline (and carriage return on some platforms).
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line, nil
}

