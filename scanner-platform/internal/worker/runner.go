package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"scanner-platform/internal/models"
	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/fix"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"

	"github.com/redis/go-redis/v9"
)

func getCancelSignal(job *models.ScanJob) bool {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()

	key := fmt.Sprintf("scan_cancel:%s:%s", job.ScanID, job.Target)
	val, err := client.Get(context.Background(), key).Result()
	if err != nil {
		return false
	}
	return val == "1"
}

func normalizePublicStage(stage string) string {
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case "discovery", "subdomain_discovery":
		return "dns"
	case "filter", "subdomain_filter", "collection", "subdomain_collection", "data_collection":
		return "headers"
	case "completed", "scan_complete", "scan_completed":
		return "report_generation"
	case "", "initializing":
		return "queued"
	default:
		return strings.ToLower(strings.TrimSpace(stage))
	}
}

func syncPublicScanProgress(job *models.ScanJob, stage string, progress int, message string, status string) {
	if job == nil || job.ScanID == "" || job.Target == "" {
		return
	}

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()

	payload := map[string]any{
		"progress": progress,
		"status":   status,
		"stage":    normalizePublicStage(stage),
		"message":  message,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal progress payload: %v", err)
		return
	}

	key := fmt.Sprintf("scan_progress:%s:%s", job.ScanID, strings.ToLower(job.Target))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Set(ctx, key, string(data), time.Hour).Err(); err != nil {
		log.Printf("Failed to update public progress for %s: %v", key, err)
	}
}

func updateScanProgress(job *models.ScanJob, stage string, progress int, message string, status string, lastError string, checkpoint map[string]any) {
	job.CurrentStage = stage
	job.Progress = progress
	job.Message = message
	job.Status = status
	job.UpdatedAt = time.Now()
	if lastError != "" {
		job.LastError = lastError
	}
	if checkpoint != nil {
		job.Checkpoint = checkpoint
	}
	syncPublicScanProgress(job, stage, progress, message, status)
}

func emitScanEvent(job *models.ScanJob, event string, status string, progress int, message string, evidence []map[string]any) error {
	payload := models.ScanNotification{
		ScanID:        job.ScanID,
		Target:        job.Target,
		Event:         event,
		Status:        status,
		Stage:         job.CurrentStage,
		Progress:      progress,
		Message:       message,
		Evidence:      evidence,
		Checkpoint:    job.Checkpoint,
		EvidenceCount: len(evidence),
	}
	_, err := send_webhook_notification(payload)
	if err != nil {
		log.Printf("Failed to send webhook notification for %s: %v", job.ScanID, err)
	}
	return err
}

func RunFix(ctx context.Context, job *models.FixScanJob) (any, error) {

	null := models.FixScanResult{}

	log.Println("================================")
	log.Println("Received fix job")
	log.Println("================================")

	log.Printf("Scan ID: %s", job.ScanID)
	log.Printf("Domain: %s", job.Domain)
	log.Printf("Fix Type: %s", job.FixType)

	log.Printf("Fix started: %s (%s)", job.ScanID, job.Domain)

	result := models.FixScanResult{}
	var err error

	if job.FixType == "port" {

		fmt.Println("================================")
		fmt.Println("Processing fix request")
		fmt.Println("================================")

		fmt.Println("Fix Port-Scanner Running...")

		fmt.Println("Running verification")

		result, err = fix.PortFix(ctx, job)
		if err != nil {
			log.Println("Fix failed:", err)
			return null, err
		}

		fmt.Println("Verification completed")
		fmt.Println("Fix Port-Scanner Completed.")
	}

	// ========================================
	// SEND WEBHOOK
	// ========================================

	fmt.Println("Sending webhook result")

	res, err := send_fix_result_webhook(result)
	if err != nil {
		log.Println("Webhook failed:", err)
		return nil, err
	}

	fmt.Println("Fix workflow completed successfully")

	return res, nil
}

func RunMain(ctx context.Context, job *models.ScanJob) (any, error) {
	if job.StartedAt.IsZero() {
		job.StartedAt = time.Now()
	}
	job.UpdatedAt = time.Now()
	job.Status = "running"
	job.CurrentStage = "initializing"
	job.Progress = 5
	job.Message = "Starting scan pipeline"
	syncPublicScanProgress(job, "initializing", 5, "Starting scan pipeline", "running")

	log.Printf("Scan started: %s (%s)", job.ScanID, job.Target)

	fmt.Println("Pipeline started for domain:", job.Target)

	fmt.Println("Pipeline 1 : subdomain discovery")
	updateScanProgress(job, "discovery", 10, "Running discovery scanners", "running", "", nil)
	_ = emitScanEvent(job, "subdomain_discovery_started", "running", 10, "Running discovery scanners", nil)
	if getCancelSignal(job) {
		updateScanProgress(job, "cancelled", 10, "Scan cancelled before discovery started", "cancelled", "", nil)
		_ = emitScanEvent(job, "scan_cancel_requested", "cancelled", 10, "Scan cancelled before discovery started", nil)
		return nil, context.Canceled
	}

	registry := core.NewRegistry()

	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewDiscoveryPipeline(registry)

	if err := ctx.Err(); err != nil {
		updateScanProgress(job, "discovery", 10, "Scan cancelled before discovery completed", "cancelled", err.Error(), nil)
		return nil, err
	}
	if getCancelSignal(job) {
		updateScanProgress(job, "discovery", 10, "Scan cancelled during discovery", "cancelled", "", nil)
		_ = emitScanEvent(job, "scan_cancel_requested", "cancelled", 10, "Scan cancelled during discovery", nil)
		return nil, context.Canceled
	}

	results, err := pipeline.ExecuteDiscoveryScanner(ctx, job.Target)
	if err != nil {
		if ctx.Err() != nil {
			updateScanProgress(job, "discovery", 10, "Scan cancelled during discovery", "cancelled", ctx.Err().Error(), nil)
			return nil, ctx.Err()
		}
		updateScanProgress(job, "discovery", 10, "Discovery completed with errors", "failed", err.Error(), nil)
		return nil, err
	}

	updateScanProgress(job, "discovery", 35, "Discovery completed", "running", "", map[string]any{"subdomains_found": len(results.Data.([]string))})
	discovery_payload := models.ScanNotification{
		ScanID:     job.ScanID,
		Target:     job.Target,
		Event:      "subdomain_discovery_completed",
		Status:     "completed",
		Stage:      "discovery",
		Progress:   35,
		Checkpoint: map[string]any{"subdomains_found": len(results.Data.([]string))},
	}

	discovery_res, err := send_webhook_notification(discovery_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}
	_ = emitScanEvent(job, "subdomain_discovery_completed", "completed", 35, "Discovery completed", nil)

	fmt.Println("Total Subdomains Found:", len(results.Data.([]string)), discovery_res)

	fmt.Println("Pipeline 2 : filter subdomain")
	updateScanProgress(job, "filter", 45, "Filtering discovered subdomains", "running", "", map[string]any{"subdomains_found": len(results.Data.([]string))})
	_ = emitScanEvent(job, "subdomain_filter_started", "running", 45, "Filtering discovered subdomains", nil)

	filter_registry := core.NewFilterScannerRegistry()

	filter_registry.RegisterFilterScanner(filters.NewDedupFilter())
	filter_registry.RegisterFilterScanner(filters.NewDNSFilter())
	filter_registry.RegisterFilterScanner(filters.NewHTTPFilter())

	filter_pipeline := core.NewFilterPipeline(filter_registry)

	filter_pipeline_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, job.Target)
	if err != nil {
		if ctx.Err() != nil {
			updateScanProgress(job, "filter", 45, "Scan cancelled during filtering", "cancelled", ctx.Err().Error(), nil)
			return nil, ctx.Err()
		}
		if getCancelSignal(job) {
			updateScanProgress(job, "filter", 45, "Scan cancelled during filtering", "cancelled", "", nil)
			_ = emitScanEvent(job, "scan_cancel_requested", "cancelled", 45, "Scan cancelled during filtering", nil)
			return nil, context.Canceled
		}
		updateScanProgress(job, "filter", 45, "Filtering failed", "failed", err.Error(), nil)
		return nil, err
	}

	updateScanProgress(job, "filter", 65, "Filtering completed", "running", "", map[string]any{"filtered_subdomains": len(filter_pipeline_results.Data.([]interface{}))})
	filter_payload := models.ScanNotification{
		ScanID:     job.ScanID,
		Target:     job.Target,
		Event:      "subdomain_filter_completed",
		Status:     "completed",
		Stage:      "filter",
		Progress:   65,
		Checkpoint: map[string]any{"filtered_subdomains": len(filter_pipeline_results.Data.([]interface{}))},
	}

	filter_res, err := send_webhook_notification(filter_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}
	_ = emitScanEvent(job, "subdomain_filter_completed", "completed", 65, "Filtering completed", nil)

	fmt.Println("Total Filtered Subdomains Found:", len(filter_pipeline_results.Data.([]interface{})), filter_res)

	fmt.Println("Scanner 3 : Data collection")
	updateScanProgress(job, "collection", 70, "Running collection scanners", "running", "", map[string]any{"filtered_subdomains": len(filter_pipeline_results.Data.([]interface{}))})
	_ = emitScanEvent(job, "subdomain_collection_started", "running", 70, "Running collection scanners", nil)

	collection_registry := core.NewCollectionRegistry()

	collection_registry.RegisterCollectionScanner(collection.NewDNSDataOutput())
	collection_registry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
	collection_registry.RegisterCollectionScanner(collection.NewPortFilter())
	collection_registry.RegisterCollectionScanner(collection.NewTLSDataCollection())
	collection_registry.RegisterCollectionScanner(collection.NewMailSecurityDataCollection())

	collection_pipeline := core.NewCollectionPipeline(collection_registry)

	collection_data_results, err := collection_pipeline.ExecuteCollectionScanenrs(ctx, filter_pipeline_results, job.Target)
	if err != nil {
		if ctx.Err() != nil {
			updateScanProgress(job, "collection", 70, "Scan cancelled during collection", "cancelled", ctx.Err().Error(), nil)
			return nil, ctx.Err()
		}
		if getCancelSignal(job) {
			updateScanProgress(job, "collection", 70, "Scan cancelled during collection", "cancelled", "", nil)
			_ = emitScanEvent(job, "scan_cancel_requested", "cancelled", 70, "Scan cancelled during collection", nil)
			return nil, context.Canceled
		}
		updateScanProgress(job, "collection", 70, "Collection failed", "failed", err.Error(), nil)
		return nil, err
	}

	updateScanProgress(job, "collection", 90, "Collection completed", "running", "", map[string]any{"collection_items": len(collection_data_results.Data.(map[string]interface{}))})
	collection_payload := models.ScanNotification{
		ScanID:     job.ScanID,
		Target:     job.Target,
		Event:      "subdomain_collection_completed",
		Status:     "completed",
		Stage:      "collection",
		Progress:   90,
		Checkpoint: map[string]any{"collection_items": len(collection_data_results.Data.(map[string]interface{}))},
	}

	collection_res, err := send_webhook_notification(collection_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}
	_ = emitScanEvent(job, "subdomain_collection_completed", "completed", 90, "Collection completed", nil)

	fmt.Println("Total Results Found:", len(collection_data_results.Data.(map[string]interface{})), collection_res)

	scanResult := models.ScanResult{
		ScanID:       job.ScanID,
		Target:       job.Target,
		Status:       "completed",
		Data:         collection_data_results.Data,
		Timestamp:    time.Now(),
		Progress:     100,
		CurrentStage: "completed",
		Metadata: map[string]any{
			"subdomains": len(collection_data_results.Data.(map[string]interface{})["subdomains"].([]interface{})),
		},
	}

	fmt.Println("Final Results:",
		len(scanResult.Data.(map[string]interface{})["subdomains"].([]interface{})))

	res, err := send_scan_result_webhook(scanResult)
	if err != nil {
		return nil, err
	}

	updateScanProgress(job, "completed", 100, "Scan completed successfully", "completed", "", map[string]any{"subdomains": len(scanResult.Data.(map[string]interface{})["subdomains"].([]interface{}))})
	_ = emitScanEvent(job, "scan_completed", "completed", 100, "Scan completed successfully", nil)

	return res, nil
}
