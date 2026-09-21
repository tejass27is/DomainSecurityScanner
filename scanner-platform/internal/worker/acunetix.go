package worker

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// acunetixClient is a read-only Acunetix Premium (v13+) API client.
//
// The backend already creates the target and starts the scan; this client only
// watches the scan and pulls its findings, so it needs no write endpoints.
type acunetixClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// resolveAcunetixBaseURL resolves and normalizes the Acunetix API root.
//
// Reads ACUNETIX_URL first, then its alias ACUNETIX_BASE_URL. Accepts the bare
// console address, a trailing slash, or a browser-style fragment and always
// returns the /api/v1 root, preserving sub-path installations.
func resolveAcunetixBaseURL() string {
	raw := strings.TrimSpace(os.Getenv("ACUNETIX_URL"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("ACUNETIX_BASE_URL"))
	}
	if raw == "" {
		return ""
	}

	// Drop a browser-console fragment or query string.
	if idx := strings.IndexAny(raw, "#?"); idx >= 0 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	raw = strings.TrimRight(raw, "/")

	lowered := strings.ToLower(raw)
	switch {
	case strings.HasSuffix(lowered, "/api/v1"):
		return raw
	case strings.HasSuffix(lowered, "/api"):
		return raw + "/v1"
	default:
		return raw + "/api/v1"
	}
}

// newAcunetixClientFromEnv builds a client from ACUNETIX_URL (or
// ACUNETIX_BASE_URL) and ACUNETIX_API_KEY.
func newAcunetixClientFromEnv() (*acunetixClient, error) {
	baseURL := resolveAcunetixBaseURL()
	apiKey := strings.TrimSpace(os.Getenv("ACUNETIX_API_KEY"))

	if baseURL == "" {
		return nil, fmt.Errorf("ACUNETIX_URL environment variable is not set")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("ACUNETIX_API_KEY environment variable is not set")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// On-prem Acunetix installs normally use a self-signed certificate, so TLS
	// verification is off unless ACUNETIX_VERIFY_TLS is explicitly enabled.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: !envBool("ACUNETIX_VERIFY_TLS", false)}

	return &acunetixClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		http: &http.Client{
			Timeout:   time.Duration(envInt("ACUNETIX_HTTP_TIMEOUT_SEC", defaultAcunetixHTTPTimeoutSec)) * time.Second,
			Transport: transport,
		},
	}, nil
}

func (c *acunetixClient) get(path string, query url.Values) (map[string]any, error) {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", path, err)
	}
	req.Header.Set("X-Auth", c.apiKey)
	req.Header.Set("Accept", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer res.Body.Close()

	// 32 MB cap — a chatty scan can return a large vulnerability list.
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", path, err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("acunetix %s returned %s: %s", path, res.Status, strings.TrimSpace(string(body)))
	}

	if len(body) == 0 {
		return map[string]any{}, nil
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decoding response from %s: %w", path, err)
	}
	return payload, nil
}

// listPaginated walks Acunetix' cursor pagination for a collection endpoint.
func (c *acunetixClient) listPaginated(path, collectionKey string) ([]map[string]any, error) {
	var all []map[string]any
	query := url.Values{"l": {"100"}}

	// Hard cap so a broken cursor can never spin forever.
	for page := 0; page < 200; page++ {
		payload, err := c.get(path, query)
		if err != nil {
			return nil, err
		}

		items := asMapSlice(payload[collectionKey])
		all = append(all, items...)

		cursor := ""
		if pagination, ok := payload["pagination"].(map[string]any); ok {
			cursor = stringField(pagination, "cursor")
		}
		if cursor == "" || len(items) == 0 {
			break
		}
		query.Set("c", cursor)
	}

	return all, nil
}

func (c *acunetixClient) getScan(scanID string) (map[string]any, error) {
	return c.get("/scans/"+url.PathEscape(scanID), nil)
}

func (c *acunetixClient) listScanResults(scanID string) ([]map[string]any, error) {
	return c.listPaginated("/scans/"+url.PathEscape(scanID)+"/results", "results")
}

func (c *acunetixClient) listVulnerabilities(scanID, resultID string) ([]map[string]any, error) {
	path := "/scans/" + url.PathEscape(scanID) + "/results/" + url.PathEscape(resultID) + "/vulnerabilities"

	vulns, err := c.listPaginated(path, "vulnerabilities")
	if err != nil || len(vulns) > 0 {
		return vulns, err
	}

	// Older builds return the collection under "vulns".
	return c.listPaginated(path, "vulns")
}

// getVulnerability fetches one vulnerability's detail (affected URL, evidence).
func (c *acunetixClient) getVulnerability(scanID, resultID, vulnID string) (map[string]any, error) {
	path := "/scans/" + url.PathEscape(scanID) +
		"/results/" + url.PathEscape(resultID) +
		"/vulnerabilities/" + url.PathEscape(vulnID)
	return c.get(path, nil)
}

// getVulnerabilityType returns the check's metadata (name, CVSS, CWE, remedy).
func (c *acunetixClient) getVulnerabilityType(vtID string) (map[string]any, error) {
	return c.get("/vulnerability_types/"+url.PathEscape(vtID), nil)
}

// ─── JSON helpers ─────────────────────────────────────────────────────────────

func asMapSlice(value any) []map[string]any {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if mapped, ok := item.(map[string]any); ok {
			out = append(out, mapped)
		}
	}
	return out
}

func stringField(payload map[string]any, key string) string {
	if payload == nil {
		return ""
	}
	value, ok := payload[key]
	if !ok || value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return strings.TrimSpace(str)
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func intField(payload map[string]any, key string) int {
	if payload == nil {
		return 0
	}
	value, _ := toInt(payload[key])
	return value
}

func toInt(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func stringSlice(value any) []string {
	if value == nil {
		return nil
	}
	if str, ok := value.(string); ok {
		if strings.TrimSpace(str) == "" {
			return nil
		}
		return []string{strings.TrimSpace(str)}
	}

	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
			out = append(out, strings.TrimSpace(str))
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func envBool(name string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
