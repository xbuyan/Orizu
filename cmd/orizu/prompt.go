package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/term"
)

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

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	// Trim trailing newline (and carriage return on some platforms).
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line, nil
}

