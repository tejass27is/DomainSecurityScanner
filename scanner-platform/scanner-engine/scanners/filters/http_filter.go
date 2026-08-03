package filters


import (
	"context"
	"fmt"
	"os/exec"
	"bufio"
	"encoding/json"
	"time"

	"scanner-platform/scanner-engine/core"
)


type HTTPFilter struct {}

func  NewHTTPFilter() *HTTPFilter {
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

	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-json")

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

		if hx.Host != "" && (hx.StatusCode == 200 || hx.StatusCode == 301 || hx.StatusCode == 302) {
			live_subdomains = append(live_subdomains, hx.Host)
		}
	}

	http_filtered_subdomains := core.Result{
		Scanner: f.Name(),
		Category: f.Category(),
		Target: domain,
		Data: live_subdomains,
		Timestamp: time.Now(),
	}

	if err := cmd.Wait(); err != nil {
		return http_filtered_subdomains, err
	}

	return http_filtered_subdomains, nil
}