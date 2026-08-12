package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"scanner-platform/scanner-engine/core"
)

type CrtCTScanner struct{}

func NewCrtCTScanner() *CrtCTScanner {
	return &CrtCTScanner{}
}

func (c *CrtCTScanner) Name() string {
	return "subdomain_crtsh"
}

func (c *CrtCTScanner) Category() string {
	return "discovery"
}

func (c *CrtCTScanner) RunDiscoveryScanner(
	ctx context.Context,
	domain string,
) (core.Result, error) {
	url := "https://crt.sh/?q=%25." + domain + "&output=json"

	null := core.Result{}

	// crt.sh is a free, community-hosted service whose nginx edge frequently
	// returns transient 502/503 errors when its (heavily loaded) Postgres
	// backend is slow or rebuilding. The 502 is almost never about the query
	// itself, so retry a couple of times with short backoff before giving up.
	// A failed source is non-fatal anyway: the discovery pipeline logs the
	// error and continues with the other sources (certspotter, subfinder, ...).
	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	var body []byte
	resp := &http.Response{}
	retryDelays := []time.Duration{2 * time.Second, 5 * time.Second}

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return null, err
		}
		req.Header.Set("User-Agent", "scanner/1.0")
		req.Header.Set("Accept", "application/json")

		resp, err = client.Do(req)
		if err != nil {
			return null, err
		}
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return null, err
		}

		// Retry transient server errors (502/503/504) a limited number of
		// times with backoff. 4xx errors (bad query etc.) are not retried.
		if resp.StatusCode >= 500 && attempt < len(retryDelays) {
			fmt.Printf("crt.sh returned %d on attempt %d, retrying in %s...\n",
				resp.StatusCode, attempt+1, retryDelays[attempt])
			select {
			case <-time.After(retryDelays[attempt]):
				continue
			case <-ctx.Done():
				return null, ctx.Err()
			}
		}
		break
	}

	if resp.StatusCode != http.StatusOK {
		return null, fmt.Errorf("crt.sh returned status %d after retries: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return null, fmt.Errorf("crt.sh returned empty response")
	}
	if strings.HasPrefix(trimmed, "<") {
		return null, fmt.Errorf("crt.sh returned HTML instead of JSON")
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal(body, &entries); err != nil {
		return null, err
	}

	seen := make(map[string]bool)
	var results []string

	for _, entry := range entries {
		raw, ok := entry["name_value"].(string)
		if !ok {
			continue
		}

		names := strings.Split(raw, "\n")
		for _, sub := range names {
			sub = strings.TrimSpace(sub)

			if !IsValidSubdomain(sub, domain) {
				continue
			}

			if sub == "" || seen[sub] {
				continue
			}

			seen[sub] = true

			results = append(results, sub)
		}
	}

	crt_subdomains_found := core.Result{
		Scanner:   c.Name(),
		Category:  c.Category(),
		Target:    domain,
		Data:      results,
		Timestamp: time.Now(),
	}

	return crt_subdomains_found, nil
}
