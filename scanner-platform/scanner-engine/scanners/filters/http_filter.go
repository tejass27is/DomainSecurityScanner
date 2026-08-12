package filters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"scanner-platform/scanner-engine/core"
)

type HTTPFilter struct{}

func NewHTTPFilter() *HTTPFilter {
	return &HTTPFilter{}
}

func (f *HTTPFilter) Name() string {
	return "HTTPFilter"
}

func (f *HTTPFilter) Category() string {
	return "FilterScanner"
}

func (f *HTTPFilter) RunFilterScanner(
	ctx context.Context,
	results core.Result,
	domain string,
) (core.Result, error) {
	null := core.Result{}

	// Explicit fast per-host timeout + no retries makes the filter
	// deterministic: with httpx defaults the probe is a slow race that gets
	// killed by the stage budget mid-scan, so different runs of the same
	// domain kept different random subsets of hosts (7 one run, 34 the next)
	// — which is what made the score flip between scans.
	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-json", "-timeout", "5", "-retries", "0")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return null, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return null, err
	}

	if err := cmd.Start(); err != nil {
		return null, err
	}

	subdomains := results.Data.([]string)
	// Feed subdomains safely
	go func() {
		defer stdin.Close()
		for _, subdomain := range subdomains {

			if subdomain == "" {
				continue
			}

			fmt.Fprintln(stdin, subdomain)
		}
	}()

	var live_subdomains []string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		var hx struct {
			Host       string `json:"host"`
			StatusCode int    `json:"status_code"`
		}

		if err := json.Unmarshal(scanner.Bytes(), &hx); err != nil {
			continue
		}

		// Keep ANY host that produced an HTTP response (httpx -silent only
		// emits hosts that answered). Restricting to 200/301/302 silently
		// dropped 403/500 hosts — real attack surface — so the score under-
		// reported the domain. Non-responders never appear here at all.
		if hx.Host != "" {
			live_subdomains = append(live_subdomains, hx.Host)
		}
	}

	http_filtered_subdomains := core.Result{
		Scanner:   f.Name(),
		Category:  f.Category(),
		Target:    domain,
		Data:      live_subdomains,
		Timestamp: time.Now(),
	}

	if err := cmd.Wait(); err != nil {
		return http_filtered_subdomains, err
	}

	return http_filtered_subdomains, nil
}
