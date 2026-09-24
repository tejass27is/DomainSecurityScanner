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

	"github.com/redis/go-redis/v9"
)

const (
	defaultAcunetixPollIntervalSec = 20
	defaultAcunetixMaxWaitSec      = 43200 // 12 hours
	defaultAcunetixHTTPTimeoutSec  = 60
	// Acunetix reports 0-100. We present a 2-95 band while running so the UI
	// never shows "done" until the findings have actually been stored.
	webScanProgressBase = 2
	webScanProgressMax  = 95
)

// RunWebScan polls Acunetix until the scan finishes, then pulls the findings,
// enriches them with their vulnerability_type metadata and posts the result to
// the backend, which normalizes and stores them.
func RunWebScan(ctx context.Context, job *models.WebScanJob) (any, error) {
	if job == nil {
		return nil, fmt.Errorf("web scan job is nil")
	}
	if strings.TrimSpace(job.AcunetixScanID) == "" {
		return nil, fmt.Errorf("web scan job %s has no Acunetix scan id", job.ScanID)
	}

	log.Printf("Web scan started: %s (%s, acunetix=%s)", job.ScanID, job.TargetURL, job.AcunetixScanID)

	client, err := newAcunetixClientFromEnv()
	if err != nil {
		_ = sendWebScanFailure(job, err.Error())
		return nil, err
	}

	pollInterval := time.Duration(envInt("ACUNETIX_POLL_INTERVAL_SEC", defaultAcunetixPollIntervalSec)) * time.Second
	maxWait := time.Duration(envInt("ACUNETIX_MAX_WAIT_SEC", defaultAcunetixMaxWaitSec)) * time.Second
	deadline := time.Now().Add(maxWait)
	scanStartedAt := time.Now()

	_ = notifyWebScan(job, "running", webScanProgressBase, "queued", "Waiting for Acunetix to start the scan")

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if getWebScanCancelSignal(job.ScanID) {
			log.Printf("Web scan %s cancelled by the platform", job.ScanID)
			_ = sendWebScanCancelled(job)
			return nil, context.Canceled
		}

		if time.Now().After(deadline) {
			reason := fmt.Sprintf("Acunetix scan %s did not finish within %s", job.AcunetixScanID, maxWait)
			_ = sendWebScanFailure(job, reason)
			return nil, fmt.Errorf("%s", reason)
		}

		status, progress, stage, message, err := fetchAcunetixScanStatus(client, job.AcunetixScanID, time.Since(scanStartedAt))
		if err != nil {
			// A transient API hiccup must not kill a scan that runs for hours.
			log.Printf("Polling Acunetix scan %s failed (will retry): %v", job.AcunetixScanID, err)
			if !sleepOrDone(ctx, pollInterval) {
				return nil, ctx.Err()
			}
			continue
		}

		log.Printf("Web scan %s: status=%s progress=%d", job.ScanID, status, progress)

		switch status {
		case "completed":
			result, err := collectWebScanFindings(client, job)
			if err != nil {
				_ = sendWebScanFailure(job, err.Error())
				return nil, err
			}
			if _, err := send_webscan_result_webhook(*result); err != nil {
				return nil, err
			}
			log.Printf("Web scan %s completed with %d finding(s)", job.ScanID, len(result.Vulnerabilities))
			return result, nil

		case "failed", "aborted":
			reason := fmt.Sprintf("Acunetix reported scan %s as %s", job.AcunetixScanID, status)
			_ = sendWebScanFailure(job, reason)
			return nil, fmt.Errorf("%s", reason)

		default:
			_ = notifyWebScan(job, "running", clampWebScanProgress(progress), stage, message)
		}

		if !sleepOrDone(ctx, pollInterval) {
			return nil, ctx.Err()
		}
	}
}

// sleepOrDone waits for the interval, returning false when the context is done.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// fetchAcunetixScanStatus reads a scan's lifecycle state from Acunetix.
//
// Acunetix reports progress under the current_session object; a few builds
// expose the status at the top level instead, so both are checked.
func fetchAcunetixScanStatus(client *acunetixClient, scanID string, elapsed time.Duration) (status string, progress int, stage string, message string, err error) {
	payload, err := client.getScan(scanID)
	if err != nil {
		return "", 0, "", "", err
	}

	session, _ := payload["current_session"].(map[string]any)

	rawStatus := firstNonEmpty(stringField(session, "status"), stringField(payload, "status"))
	status = normalizeAcunetixStatus(rawStatus)

	// Try every field name/location Acunetix is known to use across versions,
	// and every numeric shape (int, float64, numeric string) intField might
	// otherwise miss.
	progress = firstNonZeroProgress(
		anyField(session, "progress"),
		anyField(payload, "progress"),
		anyField(session, "progress_percent"),
		anyField(payload, "progress_percent"),
		anyField(session, "percentage"),
		anyField(payload, "percentage"),
	)
	if progress == 0 {
		progress = estimatedAcunetixProgress(payload, elapsed)
	}

	stage = firstNonEmpty(stringField(session, "current_stage"), stringField(payload, "current_stage"), rawStatus)
	if stage == "" {
		stage = "running"
	}

	message = fmt.Sprintf("Acunetix status: %s", firstNonEmpty(stringField(session, "current_stage"), rawStatus, "running"))
	return status, progress, stage, message, nil
}

// estimatedAcunetixProgress keeps the UI moving when an Acunetix profile
// reports live activity but never populates its progress field. It deliberately
// stays below the completion ceiling; only an Acunetix completed state may end
// the scan at 100%.
func estimatedAcunetixProgress(payload map[string]any, elapsed time.Duration) int {
	activity := 0
	session, _ := payload["current_session"].(map[string]any)
	for _, source := range []map[string]any{session, payload} {
		if source == nil {
			continue
		}
		for _, key := range []string{"threat", "threats", "results_count", "vulnerabilities_count"} {
			if value := firstNonZeroProgress(source[key]); value > activity {
				activity = value
			}
		}
		if counts, ok := source["severity_counts"].(map[string]any); ok {
			count := 0
			for _, value := range counts {
				count += firstNonZeroProgress(value)
			}
			if count > activity {
				activity = count
			}
		}
	}

	minutes := int(elapsed / time.Minute)
	estimate := webScanProgressBase + minutes
	if activity > 0 {
		estimate += minInt(activity, 20)
	}
	return clampWebScanProgress(estimate)
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// anyField returns the raw value at key in m, or nil if m is nil or the key
// is absent — used so firstNonZeroProgress can inspect the real type instead
// of assuming int.
func anyField(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

// firstNonZeroProgress returns the first candidate that converts to a
// non-zero int, checking int, float64 and numeric-string representations
// (covers every shape Acunetix has been seen to return progress in).
func firstNonZeroProgress(candidates ...any) int {
	for _, c := range candidates {
		switch v := c.(type) {
		case int:
			if v != 0 {
				return v
			}
		case int64:
			if v != 0 {
				return int(v)
			}
		case float64:
			if v != 0 {
				return int(v)
			}
		case string:
			if n, ok := toInt(v); ok && n != 0 {
				return n
			}
		}
	}
	return 0
}

// normalizeAcunetixStatus collapses Acunetix' many states onto the four the
// backend stores: running, completed, failed, aborted.
func normalizeAcunetixStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "completed", "complete", "done":
		return "completed"
	case "failed", "error":
		return "failed"
	case "aborted", "stopped", "cancelled", "canceled":
		return "aborted"
	case "queued", "starting", "scheduled", "processing", "running":
		return "running"
	default:
		return "running"
	}
}

func clampWebScanProgress(progress int) int {
	if progress < webScanProgressBase {
		return webScanProgressBase
	}
	if progress > webScanProgressMax {
		return webScanProgressMax
	}
	return progress
}

// getWebScanCancelSignal reports whether the platform asked to stop this scan.
func getWebScanCancelSignal(scanID string) bool {
	addr := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if addr == "" {
		return false
	}

	client := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("REDIS_PASSWORD")})
	defer client.Close()

	val, err := client.Get(context.Background(), fmt.Sprintf("webscan_cancel:%s", scanID)).Result()
	if err != nil {
		return false
	}
	return val == "1"
}

// ─── Findings collection ──────────────────────────────────────────────────────

// collectWebScanFindings gathers every vulnerability of a finished scan,
// enriching each with its vulnerability_type metadata (fetched once per vt_id).
func collectWebScanFindings(client *acunetixClient, job *models.WebScanJob) (*models.WebScanResult, error) {
	scanPayload, err := client.getScan(job.AcunetixScanID)
	if err != nil {
		return nil, fmt.Errorf("fetching scan metadata for %s: %w", job.AcunetixScanID, err)
	}
	results, err := client.listScanResults(job.AcunetixScanID)
	if err != nil {
		return nil, fmt.Errorf("fetching scan results for %s: %w", job.AcunetixScanID, err)
	}

	typeCache := make(map[string]map[string]any)
	findings := make([]map[string]any, 0)

	for _, result := range results {
		resultID := stringField(result, "result_id")
		if resultID == "" {
			continue
		}

		vulns, err := client.listVulnerabilities(job.AcunetixScanID, resultID)
		if err != nil {
			return nil, fmt.Errorf("fetching vulnerabilities for result %s: %w", resultID, err)
		}

		for _, vuln := range vulns {
			vtID := stringField(vuln, "vt_id")

			vulnType, cached := typeCache[vtID]
			if !cached && vtID != "" {
				// Best effort — a missing type only costs us the metadata.
				vulnType, err = client.getVulnerabilityType(vtID)
				if err != nil {
					log.Printf("Could not fetch Acunetix vulnerability type %s: %v", vtID, err)
					vulnType = nil
				}
				typeCache[vtID] = vulnType
			}

			findings = append(findings, buildWebScanFinding(client, job, resultID, vuln, vulnType))
		}
	}

	return &models.WebScanResult{
		ScanID:          job.ScanID,
		OrgID:           job.OrgID,
		TargetURL:       job.TargetURL,
		Status:          "completed",
		Vulnerabilities: findings,
		Timestamp:       time.Now(),
		Metadata: map[string]any{
			"acunetix_scan_id": job.AcunetixScanID,
			"result_count":     len(results),
			"finding_count":    len(findings),
			"scan_metadata":    extractScanMetadata(scanPayload),
			"reconnaissance":   extractReconnaissance(scanPayload, results),
			"best_practices":   extractCollection(scanPayload, "best_practices", "best_practice_recommendations"),
			"compliance":       extractCollection(scanPayload, "compliance", "compliance_summary", "compliance_findings"),
		},
	}, nil
}

func extractScanMetadata(payload map[string]any) map[string]any {
	metadata := map[string]any{}
	for _, key := range []string{"target_id", "target_url", "start_date", "start_time", "end_date", "end_time", "duration", "description", "total_requests", "requests_count", "average_speed", "tags", "risk_level", "criticality"} {
		if value, ok := payload[key]; ok && value != nil {
			metadata[key] = value
		}
	}
	if session, ok := payload["current_session"].(map[string]any); ok {
		for _, key := range []string{"start_date", "start_time", "end_date", "end_time", "duration", "total_requests", "requests_count", "average_speed", "risk_level"} {
			if value, ok := session[key]; ok && value != nil {
				metadata[key] = value
			}
		}
	}
	return metadata
}

func extractReconnaissance(payload map[string]any, results []map[string]any) map[string]any {
	reconnaissance := map[string]any{}
	for _, key := range []string{"long_response_times", "files_with_long_response_times", "external_links", "emails", "email_addresses", "client_side_scripts", "scripts", "external_hosts"} {
		if value, ok := payload[key]; ok && value != nil {
			reconnaissance[key] = value
		}
	}
	for _, result := range results {
		for _, key := range []string{"external_links", "emails", "email_addresses", "client_side_scripts", "scripts", "external_hosts"} {
			if value, ok := result[key]; ok && value != nil && reconnaissance[key] == nil {
				reconnaissance[key] = value
			}
		}
	}
	return reconnaissance
}

func extractCollection(payload map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := payload[key]; ok && value != nil {
			return value
		}
	}
	return []any{}
}

// buildWebScanFinding flattens an Acunetix vulnerability + its type metadata
// into the payload the backend expects.
func buildWebScanFinding(client *acunetixClient, job *models.WebScanJob, resultID string, vuln, vulnType map[string]any) map[string]any {
	vulnType = unwrapVulnerabilityType(vulnType)
	vtID := stringField(vuln, "vt_id")

	affectsURL := stringField(vuln, "affects_url")
	affectsDetail := stringField(vuln, "affects_detail")
	evidence := stringField(vuln, "evidence")

	// The list endpoint omits the affected URL on some builds, so fall back to
	// the per-vulnerability detail endpoint.
	if vulnID := stringField(vuln, "vuln_id"); vulnID != "" {
		if affectsURL == "" || (vuln["request"] == nil && vuln["http_request"] == nil && vuln["response"] == nil && vuln["http_response"] == nil) {
			if detail, err := client.getVulnerability(job.AcunetixScanID, resultID, vulnID); err == nil {
				affectsURL = stringField(detail, "affects_url")
				if affectsDetail == "" {
					affectsDetail = stringField(detail, "affects_detail")
				}
				if evidence == "" {
					evidence = stringField(detail, "evidence")
				}
				for _, key := range []string{"request", "response", "http_request", "http_response", "request_headers", "response_headers", "request_body", "response_body"} {
					if value, ok := detail[key]; ok && value != nil {
						vuln[key] = value
					}
				}
			}
		}
	}
	if affectsURL == "" {
		affectsURL = job.TargetURL
	}

	cvssScore, cvssVector := extractCVSS(vulnType)
	vulnerabilityID := stringField(vuln, "vuln_id")
	references := stringSlice(vulnType["references"])
	if len(references) == 0 {
		references = stringSlice(vuln["references"])
	}
	cves := stringSlice(vulnType["cves"])
	if len(cves) == 0 {
		cves = stringSlice(vuln["cves"])
	}

	return map[string]any{
		"vt_id":            vtID,
		"vuln_id":          vulnerabilityID,
		"result_id":        resultID,
		"name":             firstNonEmpty(stringField(vulnType, "name"), stringField(vuln, "name"), vtID),
		"severity":         severityValue(vuln, vulnType),
		"confidence":       intField(vuln, "confidence"),
		"affects_url":      affectsURL,
		"affects_detail":   affectsDetail,
		"description":      firstNonEmpty(stringField(vulnType, "description"), stringField(vulnType, "long_description"), stringField(vulnType, "summary"), stringField(vuln, "description")),
		"recommendation":   firstNonEmpty(stringField(vulnType, "recommendation"), stringField(vulnType, "remediation"), stringField(vulnType, "remediation_guidance"), stringField(vulnType, "solution"), stringField(vuln, "recommendation"), stringField(vuln, "solution")),
		"cvss_score":       cvssScore,
		"cvss_vector":      cvssVector,
		"cwe":              extractCWE(vulnType),
		"references":       references,
		"cves":             cves,
		"evidence":         firstNonEmpty(evidence, stringField(vuln, "proof"), stringField(vuln, "output"), stringField(vulnType, "evidence")),
		"http_request":     mapValueText(vuln, "http_request", "request"),
		"http_response":    mapValueText(vuln, "http_response", "response"),
		"request_headers":  mapValueText(vuln, "request_headers"),
		"response_headers": mapValueText(vuln, "response_headers"),
		"request_body":     mapValueText(vuln, "request_body"),
		"response_body":    mapValueText(vuln, "response_body"),
		"status":           stringField(vuln, "status"),
		"last_seen":        stringField(vuln, "last_seen"),
		"target_id":        stringField(vuln, "target_id"),
		"port":             vuln["port"],
		"protocol":         stringField(vuln, "protocol"),
		"service":          stringField(vuln, "service"),
	}
}

func unwrapVulnerabilityType(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	for _, key := range []string{"vulnerability_type", "vulnerabilityType", "data"} {
		if nested, ok := payload[key].(map[string]any); ok {
			return nested
		}
	}
	return payload
}

func mapValueText(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok || value == nil {
			continue
		}
		if text, ok := value.(string); ok {
			return text
		}
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err == nil {
			return string(encoded)
		}
	}
	return ""
}

// severityValue prefers the per-vulnerability severity and falls back to the
// check's own severity, which some builds expose as a name rather than a number.
func severityValue(vuln, vulnType map[string]any) int {
	if value, ok := toInt(vuln["severity"]); ok {
		return clampSeverity(value)
	}
	if value, ok := toInt(vulnType["severity"]); ok {
		return clampSeverity(value)
	}
	if name, ok := vulnType["severity"].(string); ok {
		return severityFromName(name)
	}
	return 0
}

func clampSeverity(value int) int {
	if value < 0 {
		return 0
	}
	if value > 4 {
		return 4
	}
	return value
}

func severityFromName(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// extractCVSS pulls the CVSS score/vector from a vulnerability type, covering
// both the flat fields and the nested cvss3/cvss2 descriptors.
func extractCVSS(vulnType map[string]any) (any, string) {
	if vulnType == nil {
		return nil, ""
	}

	var score any
	if value, ok := vulnType["cvss_score"]; ok && value != nil {
		score = value
	}
	if score == nil {
		for _, key := range []string{"cvss", "cvss3_score", "cvss2_score"} {
			if value, ok := vulnType[key]; ok && value != nil {
				score = value
				break
			}
		}
	}
	vector := stringField(vulnType, "cvss_vector")
	if vector == "" {
		vector = firstNonEmpty(stringField(vulnType, "cvss3_vector"), stringField(vulnType, "cvss2_vector"))
	}

	for _, key := range []string{"cvss3", "cvss2"} {
		nested, ok := vulnType[key].(map[string]any)
		if !ok {
			continue
		}
		if score == nil {
			if value, ok := nested["score"]; ok && value != nil {
				score = value
			}
		}
		if vector == "" {
			vector = stringField(nested, "vector")
		}
	}

	return score, vector
}

func extractCWE(vulnType map[string]any) any {
	if vulnType == nil {
		return nil
	}
	if value, ok := vulnType["cwe"]; ok && value != nil {
		return value
	}
	if value, ok := vulnType["cwe_id"]; ok && value != nil {
		return value
	}
	if ids := stringSlice(vulnType["cwe_ids"]); len(ids) > 0 {
		return strings.Join(ids, ", ")
	}
	return nil
}

// ─── Backend reporting ────────────────────────────────────────────────────────

func notifyWebScan(job *models.WebScanJob, status string, progress int, stage, message string) error {
	if job == nil {
		return nil
	}

	_, err := send_webscan_notification(models.WebScanNotification{
		ScanID:    job.ScanID,
		OrgID:     job.OrgID,
		TargetURL: job.TargetURL,
		Status:    status,
		Progress:  progress,
		Stage:     stage,
		Message:   message,
	})
	if err != nil {
		log.Printf("Failed to report web scan progress for %s: %v", job.ScanID, err)
	}
	return err
}

func sendWebScanFailure(job *models.WebScanJob, reason string) error {
	if job == nil {
		return nil
	}

	_, err := send_webscan_result_webhook(models.WebScanResult{
		ScanID:          job.ScanID,
		OrgID:           job.OrgID,
		TargetURL:       job.TargetURL,
		Status:          "failed",
		Error:           reason,
		Vulnerabilities: []map[string]any{}, // fixes 422: backend requires a list, not null
		Metadata:        map[string]any{"acunetix_scan_id": job.AcunetixScanID},
		Timestamp:       time.Now(),
	})
	if err != nil {
		log.Printf("Failed to report web scan failure for %s: %v", job.ScanID, err)
	}
	return err
}

func sendWebScanCancelled(job *models.WebScanJob) error {
	if job == nil {
		return nil
	}

	_, err := send_webscan_result_webhook(models.WebScanResult{
		ScanID:          job.ScanID,
		OrgID:           job.OrgID,
		TargetURL:       job.TargetURL,
		Status:          "cancelled",
		Vulnerabilities: []map[string]any{}, // fixes 422: backend requires a list, not null
		Metadata:        map[string]any{"acunetix_scan_id": job.AcunetixScanID},
		Timestamp:       time.Now(),
	})
	if err != nil {
		log.Printf("Failed to report web scan cancellation for %s: %v", job.ScanID, err)
	}
	return err
}
