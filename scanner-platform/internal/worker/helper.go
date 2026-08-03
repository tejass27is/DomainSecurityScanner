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

func getBackendBaseURL() string {
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://scanner-backend:8000"
	}
	return backendURL
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
	url := fmt.Sprintf("%s/webhooks/scan/notification", getBackendBaseURL())
	return postJSON(url, payload)
}

func send_scan_result_webhook(payload models.ScanResult) (string, error) {
	url := fmt.Sprintf("%s/webhooks/scan/result", getBackendBaseURL())
	return postJSON(url, payload)
}

func send_fix_result_webhook(result models.FixScanResult) (string, error) {

	url := fmt.Sprintf("%s/fix/result", getBackendBaseURL())

	payload := map[string]interface{}{
		"scan_id":  result.ScanID,
		"domain":   result.Domain,
		"fix_type": "port",
		"result":   result.Data,
	}

	return postJSON(url, payload)
}
