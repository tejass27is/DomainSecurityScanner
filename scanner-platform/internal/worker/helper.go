package worker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"scanner-platform/internal/models"
	"strings"
)

const (
	defaultScannerImage       = "scanner-worker-main"
	defaultBackendURL         = "http://backend:8000"
	defaultRedisAddr          = "redis:6379"
	defaultDockerNetwork      = "scanner-network"
	defaultSingleDomainScanID = "single-domain-scan"
)

func getBackendBaseURL() (string, error) {
	configured := strings.TrimSpace(os.Getenv("BACKEND_URL"))

	if configured == "" {
		return "", fmt.Errorf("BACKEND_URL is not configured")
	}

	return strings.TrimRight(configured, "/"), nil
}

func buildTemporaryScanContainerArgs(scanID string, domain string, imageName string, backendURL string, redisAddr string, networkName string) ([]string, string) {
	if strings.TrimSpace(imageName) == "" {
		imageName = defaultScannerImage
	}
	if strings.TrimSpace(backendURL) == "" {
		backendURL = defaultBackendURL
	}
	if strings.TrimSpace(redisAddr) == "" {
		redisAddr = defaultRedisAddr
	}
	if strings.TrimSpace(networkName) == "" {
		networkName = defaultDockerNetwork
	}

	re := regexp.MustCompile(`[^a-z0-9]+`)
	safeDomain := strings.Trim(re.ReplaceAllString(strings.ToLower(strings.TrimSpace(domain)), "-"), "-")
	safeScanID := strings.Trim(re.ReplaceAllString(strings.ToLower(strings.TrimSpace(scanID)), "-"), "-")
	if safeDomain == "" {
		safeDomain = "domain"
	}
	if safeScanID == "" {
		safeScanID = "scan"
	}
	containerName := fmt.Sprintf("scan-%s-%s", safeDomain, safeScanID)
	if len(containerName) > 63 {
		containerName = containerName[:63]
		containerName = strings.Trim(containerName, "-")
	}

	args := []string{
		"run",
		"--rm",
		"--name", containerName,
		"--network=" + networkName,
		"-e", "REDIS_ADDR=" + redisAddr,
		"-e", "BACKEND_URL=" + backendURL,
		"-e", "SCAN_ID=" + scanID,
		"-e", "SCAN_TARGET=" + domain,
		imageName,
	}

	return args, containerName
}

func RunTemporaryScanContainer(ctx context.Context, job *models.ScanJob) error {
	if job == nil {
		return fmt.Errorf("scan job is nil")
	}
	if strings.TrimSpace(job.Target) == "" {
		return fmt.Errorf("scan target is empty")
	}

	imageName := strings.TrimSpace(os.Getenv("SCANNER_IMAGE"))
	if imageName == "" {
		imageName = defaultScannerImage
	}
	backendURL := strings.TrimSpace(os.Getenv("BACKEND_URL"))
	if backendURL == "" {
		backendURL = defaultBackendURL
	}
	redisAddr := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if redisAddr == "" {
		redisAddr = defaultRedisAddr
	}
	networkName := strings.TrimSpace(os.Getenv("DOCKER_NETWORK"))
	if networkName == "" {
		networkName = defaultDockerNetwork
	}

	args, _ := buildTemporaryScanContainerArgs(job.ScanID, job.Target, imageName, backendURL, redisAddr, networkName)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("temporary scan container for %s failed: %w", job.Target, err)
	}

	return nil
}

// postJSON sends a JSON POST request to the specified URL.
func postJSON(url string, payload any) (string, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to build POST request to %s: %w", url, err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Sign the payload with the shared webhook secret (HMAC-SHA256) when one is
	// configured, so the backend can verify the request really came from us.
	if secret := strings.TrimSpace(os.Getenv("WEBHOOK_SECRET")); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(jsonData)
		req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to POST to %s: %w", url, err)
	}

	defer res.Body.Close()

	body, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		return "", fmt.Errorf("failed to read response from %s: %w", url, readErr)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		detail := strings.TrimSpace(string(body))

		if detail == "" {
			detail = http.StatusText(res.StatusCode)
		}

		return "", fmt.Errorf(
			"%s returned %s: %s",
			url,
			res.Status,
			detail,
		)
	}

	return res.Status, nil
}

// send_webhook_notification sends a scan notification to the backend.
func send_webhook_notification(payload models.ScanNotification) (string, error) {
	baseURL, err := getBackendBaseURL()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf(
		"%s/webhooks/scan/notification",
		baseURL,
	)

	_, err = postJSON(url, payload)
	if err != nil {
		return "", err
	}

	return "ok", nil
}

// send_scan_result_webhook sends the completed scan result to the backend.
func send_scan_result_webhook(payload models.ScanResult) (string, error) {
	baseURL, err := getBackendBaseURL()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf(
		"%s/webhooks/scan/result",
		baseURL,
	)

	_, err = postJSON(url, payload)
	if err != nil {
		return "", err
	}

	return "ok", nil
}

// send_fix_result_webhook sends the fix scan result to the backend.
func send_fix_result_webhook(result models.FixScanResult) (string, error) {
	baseURL, err := getBackendBaseURL()
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"scan_id":  result.ScanID,
		"domain":   result.Domain,
		"fix_type": "port",
		"result":   result.Data,
	}

	url := fmt.Sprintf(
		"%s/fix/result",
		baseURL,
	)

	_, err = postJSON(url, payload)
	if err != nil {
		return "", err
	}

	return "ok", nil
}
