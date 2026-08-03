package discovery

import (
	"fmt"
	"context"
	"encoding/json"
	"strings"
	"time"
	"net/http"

	"scanner-platform/scanner-engine/core"
)

type CertSpotterCTScanner struct{}

func NewCertSpotterCTScanner() *CertSpotterCTScanner { 
	return &CertSpotterCTScanner{}
}

func (c *CertSpotterCTScanner) Name() string {
	return "subdomain_certspotter"
}

func (c *CertSpotterCTScanner) Category() string {
	return "discovery"
}


func (c *CertSpotterCTScanner) RunDiscoveryScanner(
	ctx context.Context, 
	domain string,
	) (core.Result, error) {
	null := core.Result{}

	// CertSpotter API endpoint
	url := "https://api.certspotter.com/v1/issuances?domain=" + domain +
		"&include_subdomains=true&expand=dns_names"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return null, err
	}

	// Required headers
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

	if resp.StatusCode != http.StatusOK {
		return null, fmt.Errorf("certspotter returned status %d", resp.StatusCode)
	}

	// CertSpotter response structure
	type certEntry struct {
		DNSNames []string `json:"dns_names"`
	}

	var entries []certEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return null, err
	}

	if len(entries) == 0 {
		return null, fmt.Errorf("certspotter returned empty response")
	}

	seen := make(map[string]bool)
	var results []string

	for _, entry := range entries {
		for _, sub := range entry.DNSNames {
			sub = strings.TrimSpace(sub)

			if !IsValidSubdomain(sub, domain) {
				continue
			}

			seen[sub] = true

			results = append(results, sub)

			// results = append(results, core.Result{
			// 	Scanner:  c.Name(),
			// 	Category: c.Category(),
			// 	Target:   domain,
			// 	Data: map[string]string{
			// 		"subdomain": sub,
			// 		"source": "certspotter",
			// 	},
			// 	Severity:  "info",
			// 	Timestamp: time.Now(),
			// })
		}
	}

	crt_spotter_subdomains_found := core.Result{
		Scanner: c.Name(),
		Category: c.Category(),
		Target: domain,
		Data: results,
		Timestamp: time.Now(),
	}

	return crt_spotter_subdomains_found, nil
}