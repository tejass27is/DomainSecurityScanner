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

func getBackendURLs() []string {
	configured := strings.TrimSpace(os.Getenv("BACKEND_URL"))
	candidates := []string{}
	if configured != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates,
		"http://scanner-backend:8000",
		"http://localhost:8000",
		"http://127.0.0.1:8000",
	)

	seen := make(map[string]bool, len(candidates))
	unique := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		unique = append(unique, trimmed)
	}
	return unique
}

func getBackendBaseURL() string {
	for _, candidate := range getBackendURLs() {
		return candidate
	}
	return "http://localhost:8000"
}

func postJSON(url string, payload any) (string, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	res, err := http.Post(
		url,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		return "", readErr
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		detail := strings.TrimSpace(string(body))
		if detail == "" {
			detail = http.StatusText(res.StatusCode)
		}
		return "", fmt.Errorf("%s returned %s: %s", url, res.Status, detail)
	}

	return res.Status, nil
}

func send_webhook_notification(payload models.ScanNotification) (string, error) {
	var lastErr error
	for _, baseURL := range getBackendURLs() {
		url := fmt.Sprintf("%s/webhooks/scan/notification", baseURL)
		_, err := postJSON(url, payload)
		if err == nil {
			return "ok", nil
		}
		lastErr = err
	}
	return "", lastErr
}

func send_scan_result_webhook(payload models.ScanResult) (string, error) {
	var lastErr error
	for _, baseURL := range getBackendURLs() {
		url := fmt.Sprintf("%s/webhooks/scan/result", baseURL)
		_, err := postJSON(url, payload)
		if err == nil {
			return "ok", nil
		}
		lastErr = err
	}
	return "", lastErr
}

func send_fix_result_webhook(result models.FixScanResult) (string, error) {
	payload := map[string]interface{}{
		"scan_id":  result.ScanID,
		"domain":   result.Domain,
		"fix_type": "port",
		"result":   result.Data,
	}

	var lastErr error
	for _, baseURL := range getBackendURLs() {
		url := fmt.Sprintf("%s/fix/result", baseURL)
		_, err := postJSON(url, payload)
		if err == nil {
			return "ok", nil
		}
		lastErr = err
	}
	return "", lastErr
}
