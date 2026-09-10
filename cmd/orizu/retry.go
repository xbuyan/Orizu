package main

import (
	"fmt"
	"time"

	"github.com/xbuyan/orizu/internal/config"
	"github.com/xbuyan/orizu/internal/relay"
	"github.com/xbuyan/orizu/internal/retryqueue"
)

// runRetry attempts to flush any notifications still stuck in the retry
// queue, without requiring a full check-in. Useful when connectivity
// returns before the next scheduled check-in — e.g. cron this alongside
// `orizu status`, or run it manually after regaining a signal.
func runRetry() error {
	cfgPath, err := configPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading guardian config: %w", err)
	}

	queueDir, err := retryQueueDir()
	if err != nil {
		return err
	}
	queue, err := retryqueue.NewQueue(queueDir)
	if err != nil {
		return fmt.Errorf("opening retry queue: %w", err)
	}

	client := relay.NewClient(cfg.RelayURL)
	result, err := queue.Flush(client, time.Now())
	if err != nil {
		return fmt.Errorf("flushing retry queue: %w", err)
	}

	fmt.Printf("Delivered: %d, dropped (too old): %d, still pending: %d\n",
		result.Delivered, result.Dropped, result.Remaining)
	return nil
}

