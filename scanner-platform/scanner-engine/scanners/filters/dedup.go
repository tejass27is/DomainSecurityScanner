package filters

import (
	"context"
	"regexp"
	"strings"
    "time"

	"scanner-platform/scanner-engine/core"
)

type DedupFilter struct{}

func NewDedupFilter() *DedupFilter {
	return &DedupFilter{}
}

func (f *DedupFilter) Name() string {
	return "DedupFilter"
}

func (f *DedupFilter) Category() string {
	return "FilterScanner"
}

func normalizeSubdomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")

	if after, ok := strings.CutPrefix(s, "*."); ok {
		s = after
	}

	return s
}

var dnsLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9-]{1,63}$`)

func IsValidSubdomain(sub, domain string) bool {
	sub = strings.TrimSpace(sub)
	domain = strings.TrimSpace(domain)

	if sub == "" || domain == "" {
		return false
	}

	sub = strings.TrimSuffix(sub, ".")
	domain = strings.TrimSuffix(domain, ".")

	// Fast reject obvious junk
	if strings.ContainsAny(sub, "* @ <>\"'") {
		return false
	}

	// Must be a strict child of domain
	if sub == domain {
		return false
	}

	if !strings.HasSuffix(sub, "."+domain) {
		return false
	}

	labels := strings.Split(sub, ".")
	for _, label := range labels {
		if label == "" {
			return false
		}

		// RFC-compliant label validation
		if !dnsLabelRegex.MatchString(label) {
			return false
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}

	return true
}

func (d *DedupFilter) RunFilterScanner(
	ctx context.Context,
	input core.Result,
	domain string,
) (core.Result, error) {

	seen := make(map[string]string)
	normalized_subdomains := make([]string, 0)
	null := core.Result{}

	subdomains, ok := input.Data.([]string)
	if !ok {
		return null, nil
	}

	for _, sub := range subdomains {
		if sub == "" {
			continue
		}

		if !IsValidSubdomain(sub, domain) {
			continue
		}

		normalized := normalizeSubdomain(sub)

		if _, exists := seen[normalized]; exists {
			continue
		}

		seen[normalized] = sub

		normalized_subdomains = append(normalized_subdomains, normalized)
	}

	normalized_subdomains = append(normalized_subdomains, domain)

    dedupted_subdomains := core.Result{
        Scanner: d.Name(),
        Category: d.Category(),
        Target: domain,
        Data: normalized_subdomains,
        Timestamp: time.Now(),
    }

	return dedupted_subdomains, nil
}
