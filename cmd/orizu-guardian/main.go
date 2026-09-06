// Command orizu-guardian is the tool a guardian runs — deliberately
// separate from cmd/orizu, which is the owner's tool. A guardian only
// ever needs their own keypair and the ability to poll and decrypt
// alerts; they have no use for (and should not need to trust) the
// owner-side init/checkin/status logic.
//
// State lives at ~/.orizu-guardian/key.json, created by `orizu-guardian
// keygen`. The private key never leaves this file.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen()
	case "poll":
		err = runPoll()
	case "recover":
		err = runRecover()
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: orizu-guardian <keygen|poll|recover>")
}

