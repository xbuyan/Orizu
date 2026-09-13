package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/xbuyan/orizu/internal/recovery"
)

// runRecover combines exactly 3 guardians' saved share payloads — however
// they were physically brought together — into the original release
// secret, with the fingerprint integrity check described in
// internal/recovery.
//
// This deliberately does not attempt to fetch the other two guardians'
// shares over any network. Bringing three independently-held shares into
// one place for a ceremony like this is inherently a human, out-of-band
// step (in person, a call, a trusted messenger) — the same category of
// gap Kinga's recovery flow already accepted ("no built-in mechanism for
// a guardian to send their share back... currently manual"). Automating
// that exchange would mean building yet another channel these shares
// travel over, which is a bigger decision than this command should make
// silently; naming it here keeps it visible rather than hidden behind a
// convenience that quietly reintroduces risk.
//
// The reconstructed key itself is handled deliberately: it is the ONLY
// thing this command ever writes to stdout, on its own line, with no
// surrounding text — every human-readable message goes to stderr instead.
// This makes the command pipeable directly into `sentinel decrypt`'s `-`
// stdin mode without the key ever appearing as a command-line argument
// (which would otherwise be visible to any other user on the machine via
// `ps` while the command runs — a real exposure the previous
// print-and-manually-copy approach had, not just an inconvenience) or
// sitting in shell history.
//
// Usage:
//
//	orizu-guardian recover <payload1.json> <payload2.json> <payload3.json>
//
// Each file is the contents of one guardian's ~/.orizu-guardian/share.json.
// Piped usage (recommended, avoids the key ever touching argv or disk):
//
//	orizu-guardian recover p1.json p2.json p3.json | sentinel decrypt sealed.json - output.txt
func runRecover() error {
	if len(os.Args) != 5 {
		return fmt.Errorf("usage: orizu-guardian recover <payload1.json> <payload2.json> <payload3.json>")
	}

	paths := os.Args[2:5]
	payloads := make([]recovery.SharePayload, len(paths))
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &payloads[i]); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	secret, err := recovery.Recover(payloads)
	if err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Recovery successful.")
	fmt.Fprintln(os.Stderr, "The reconstructed key is printed to STDOUT ONLY, nothing else — pipe it")
	fmt.Fprintln(os.Stderr, "directly into `sentinel decrypt ... -` rather than copying it manually:")
	fmt.Fprintln(os.Stderr, "  orizu-guardian recover p1.json p2.json p3.json | sentinel decrypt sealed.json - output.txt")
	fmt.Fprintln(os.Stderr, "This tool never writes the key to disk itself.")

	// The ONLY line on stdout. Nothing else must ever go here.
	fmt.Println(base64.StdEncoding.EncodeToString(secret))
	return nil
}

