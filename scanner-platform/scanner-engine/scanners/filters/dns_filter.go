package filters

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"scanner-platform/scanner-engine/core"
)

type DNSFilter struct{}

func NewDNSFilter() *DNSFilter {
	return &DNSFilter{}
}

func (f *DNSFilter) Name() string {
	return "DNSFilter"
}

func (f *DNSFilter) Category() string {
	return "FilterScanner"
}

func (f *DNSFilter) RunFilterScanner(
	ctx context.Context, 
	results core.Result, 
	domain string,
	) (core.Result, error) {
	null := core.Result{}
	cmd := exec.CommandContext(
		ctx,
		"dnsx",
		"-silent",
		"-l", "-",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return null, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return null, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return null, err
	}

	if err := cmd.Start(); err != nil {
		return null, err
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println("dnsx stderr:", scanner.Text())
		}
	}()

	subdomains := results.Data.([]string)

	go func() {
		defer stdin.Close()
		for _, sub := range subdomains {
			sub = strings.TrimSpace(sub)
			if sub != "" {
				fmt.Fprintln(stdin, sub)
			}
		}
	}()

	var resolved []string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		resolved = append(resolved, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return null, err
	}

	if err := cmd.Wait(); err != nil {
		return null, err
	}

	dns_filtered_subdomains := core.Result{
		Scanner: f.Name(),
		Category: f.Category(),
		Target:    domain,
		Data:      resolved,
		Timestamp: time.Now(),
	}

	return dns_filtered_subdomains, nil
}
