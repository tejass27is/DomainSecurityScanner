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

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return null, err
	}
	req.Header.Set("User-Agent", "scanner/1.0")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return null, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return null, err
	}

	if resp.StatusCode != http.StatusOK {
		return null, fmt.Errorf("crt.sh returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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
		Scanner: c.Name(),
		Category: c.Category(),
		Target:    domain,
		Data:      results,
		Timestamp: time.Now(),
	}

	return crt_subdomains_found, nil
}
