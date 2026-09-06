// Command orizu is the CLI wiring together checkin, alert, relay, and
// config into a usable tool.
//
// State lives at ~/.orizu/: config.json (guardian pubkeys + relay URL,
// created by hand — see README) and state.json (the persisted check-in
// state, created by `orizu init`).
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
	case "init":
		err = runInit()
	case "checkin":
		err = runCheckIn()
	case "status":
		err = runStatus()
	case "distribute":
		err = runDistribute()
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
	fmt.Fprintln(os.Stderr, "Usage: orizu <init|checkin|status|distribute>")
}

