package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"scanner-platform/internal/models"
	"strings"
)

func getBackendBaseURL() (string, error) {
	configured := strings.TrimSpace(os.Getenv("BACKEND_URL"))

	if configured == "" {
		return "", fmt.Errorf("BACKEND_URL is not configured")
	}

	return strings.TrimRight(configured, "/"), nil
}

// postJSON sends a JSON POST request to the specified URL.
func postJSON(url string, payload any) (string, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	res, err := http.Post(
		url,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
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
