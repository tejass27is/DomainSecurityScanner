package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
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
		log.Fatal("REDIS_ADDR environment variable is not set. Set it to your Redis server address (e.g. redis:6379).")
	}
	scan_type := os.Getenv("WORKER_TYPE")
	if scan_type == "" {
		scan_type = "main"
	}

	if target := strings.TrimSpace(os.Getenv("SCAN_TARGET")); target != "" {
		scanID := strings.TrimSpace(os.Getenv("SCAN_ID"))
		if scanID == "" {
			scanID = "single-domain-scan"
		}
		log.Printf("Launching single-domain scan for %s (%s)", target, scanID)
		result, err := worker.RunMain(ctx, &models.ScanJob{ScanID: scanID, Target: target})
		if err != nil {
			log.Printf("Single-domain scan failed for %s: %v", target, err)
			os.Exit(1)
		}
		fmt.Printf("Single-domain scan completed: %v\n", result)
		return
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
				err = worker.RunTemporaryScanContainer(ctx, job)
				result = map[string]string{"status": "container_run_complete", "target": job.Target}
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
