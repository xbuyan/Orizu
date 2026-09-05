package main

import (
	"fmt"
	"time"

	"github.com/xbuyan/orizu/internal/checkin"
)

// runStatus reports the last check-in time and whether the switch is
// currently overdue. Unlike runCheckIn, there is no duress concern here —
// status is read-only and never accepts a passphrase, so there is nothing
// for this command to leak by varying its output.
func runStatus() error {
	c, err := loadState()
	if err != nil {
		return err
	}

	now := time.Now()
	last := c.LastCheckIn()
	overdue := c.IsOverdue(now)

	fmt.Println("Last check-in:", last.Format(time.RFC3339))
	fmt.Println("Check-in interval:", checkin.Interval)
	fmt.Println("Grace period:", checkin.GracePeriod)

	deadline := last.Add(checkin.Interval).Add(checkin.GracePeriod)
	if overdue {
		fmt.Println("Status: OVERDUE since", deadline.Format(time.RFC3339))
	} else {
		fmt.Println("Status: OK — deadline", deadline.Format(time.RFC3339))
	}
	return nil
}

