package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"scanner-platform/internal/models"
	"scanner-platform/internal/queue"
	"scanner-platform/internal/worker"
)

const (
	// backoff limits: 1s → 30s before we spin at full speed against a dead Redis.
	initialBackoff = time.Second
	maxBackoff     = 30 * time.Second
)

func main() {
	ctx := context.Background()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	scan_type := os.Getenv("WORKER_TYPE")
	if scan_type == "" {
		scan_type = "main"
	}

	fq := queue.NewFixQueue(addr)
	mq := queue.NewMainQueue(addr)

	log.Println("Scanner worker started")
	backoff := initialBackoff

	for {
		var (
			result interface{}
			err    error
		)

		if scan_type == "fix" {
			fmt.Println("Running fix worker")

			var job *models.FixScanJob
			job, err = fq.PopFixQueue(ctx)
			if err == nil {
				result, err = worker.RunFix(ctx, job)
			}
		} else {
			fmt.Println("Running main worker")

			var job *models.ScanJob
			job, err = mq.PopMainQueue(ctx)
			if err == nil {
				result, err = worker.RunMain(ctx, job)
			}
		}

		if err != nil {
			log.Printf("Worker error: %v (backing off %s)", err, backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Success — reset backoff for the next transient failure.
		backoff = initialBackoff
		fmt.Printf("Webhook response: %v\n", result)
	}
}
