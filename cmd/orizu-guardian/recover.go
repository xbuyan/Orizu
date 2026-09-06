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
// Usage: orizu-guardian recover <payload1.json> <payload2.json> <payload3.json>
// Each file is the contents of one guardian's ~/.orizu-guardian/share.json.
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

	// Known limitation, stated plainly rather than glossed over: printing
	// the reconstructed secret to the terminal is itself an exposure —
	// visible in scrollback, terminal recording software, or a
	// screen-share. Sentinel doesn't exist yet, so there is nowhere else
	// for this secret to go; once Sentinel is built, this should feed
	// directly into whatever consumes it there, without ever touching a
	// terminal. Printing it here is a placeholder for that integration,
	// not the intended final form.
	fmt.Println("Recovery successful. Reconstructed secret (base64):")
	fmt.Println(base64.StdEncoding.EncodeToString(secret))
	fmt.Println()
	fmt.Println("This secret has not been saved anywhere by this tool. Once Sentinel exists,")
	fmt.Println("this step should feed the secret directly to it instead of printing it here.")
	return nil
}

