package discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"scanner-platform/scanner-engine/core"
)

type SubdomainBruteforceScanner struct{}

func NewSubdomainBruteforceScanner() *SubdomainBruteforceScanner {
	return &SubdomainBruteforceScanner{}
}

func (s *SubdomainBruteforceScanner) Name() string {
	return "subdomain_bruteforce"
}

func (s *SubdomainBruteforceScanner) Category() string {
	return "discovery"
}

func (s *SubdomainBruteforceScanner) RunDiscoveryScanner(
	ctx context.Context, 
	target string) (core.Result, error) {
	wordlist := []string{
		"www",
		"api",
		"admin",
		"dev",
		"test",
		"staging",
		"mail",
	}

	var results []string

	for _, word := range wordlist {
		subdomain := fmt.Sprintf("%s.%s", word, target)

		if !IsValidSubdomain(subdomain, target) {
			continue
		}

		ips, err := net.LookupIP(subdomain)
		if err != nil || len(ips) == 0 {
			continue
		}

		if ips != nil {
			results = append(results, subdomain)
			// results = append(results, core.Result{
			// 	Scanner: s.Name(),
			// 	Category: s.Category(),
			// 	Target: target,
			// 	Data: map[string]string{
			// 		"subdomain": subdomain,
			// 		"method": "dns_bruteforce",
			// 	},
			// 	Severity: "info",
			// 	Timestamp:  time.Now(),
			// 	},
			// )}
		}
	}

	brute_force_subdomains_found := core.Result{
		Scanner: s.Name(),
		Category: s.Category(),
		Target: target,
		Data: results,
		Timestamp: time.Now(),
	}

	return brute_force_subdomains_found, nil
}