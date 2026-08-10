package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	// "time"

	"scanner-platform/scanner-engine/core"
)

type DNSDataOutput struct{}

func NewDNSDataOutput() *DNSDataOutput {
	return &DNSDataOutput{}
}

func (f *DNSDataOutput) Name() string {
	return "DNS Data Collection"
}

func (f *DNSDataOutput) Category() string {
	return "DNS Data Collection"
}

func (f *DNSDataOutput) RunCollectionScanner(
	ctx context.Context,
	subdomains core.Result,
	target string,
) (core.Result, error) {
	null := core.Result{}

	subdomainsList := subdomains.Data.([]interface{})

	cmd := exec.Command(
		"dnsx",
		"-json",
		"-a",
		"-aaaa",
		"-cname",
		"-mx",
		"-ns",
		"-txt",
		"-resp",
		"-silent",
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
		defer stdin.Close()

		for _, subdomain := range subdomainsList {
			sub := subdomain.(map[string]any)["subdomain"]

			if sub == "" {
				continue
			}

			fmt.Fprintln(stdin, sub)
		}
	}()

	go func() {
		io.Copy(os.Stderr, stderr)
	}()

	subSlice := subdomains.Data.([]interface{})
	index := make(map[string]map[string]any)

	for _, item := range subSlice {
		m := item.(map[string]any)
		sub := m["subdomain"].(string)
		index[sub] = m
	}

	root := map[string]any{
		"subdomain": target,
	}

	subSlice = append(subSlice, root)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		dd := core.DNSXResult{}

		if err := json.Unmarshal(scanner.Bytes(), &dd); err != nil {
			continue
		}

		if existing, ok := index[dd.Host]; ok {
			existing["dns_collection"] = dd
		}
	}

	dnsResult := core.Result{
		Scanner:   f.Name(),
		Category:  f.Category(),
		Target:    target,
		Data:      subdomains.Data,
		Timestamp: subdomains.Timestamp,
	}

	return dnsResult, nil
}
