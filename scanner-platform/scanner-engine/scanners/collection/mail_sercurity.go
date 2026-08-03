package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"scanner-platform/scanner-engine/core"
)

type MailSecurityDataCollection struct{}

func NewMailSecurityDataCollection() *MailSecurityDataCollection {
	return &MailSecurityDataCollection{}
}

func (f *MailSecurityDataCollection) Name() string {
	return "Mail Security Data Collection"
}

func (f *MailSecurityDataCollection) Category() string {
	return "Collection"
}

func (f *MailSecurityDataCollection) RunCollectionScanner(
	ctx context.Context,
	subdomains core.Result,
	domain string,
) (core.Result, error) {
	hostData := map[string]any{
		"domain": domain,
	}

	null := core.Result{}

	spfExists := false
	spfPolicy := ""

	dmarcExists := false
	dmarcPolicy := ""

	dkimExists := false

	// -----------------------------
	// SINGLE DNSX EXECUTION
	// -----------------------------
	cmd := exec.CommandContext(
		ctx,
		"dnsx",
		"-json",
		"-txt",
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

	if err := cmd.Start(); err != nil {
		return null, err
	}

	// send all queries in ONE go
	go func() {
		defer stdin.Close()

		// SPF
		fmt.Fprintln(stdin, domain)

		// DMARC
		fmt.Fprintf(stdin, "_dmarc.%s\n", domain)

		// DKIM selectors
		selectors := []string{"default", "selector1", "selector2", "google"}

		for _, sel := range selectors {
			fmt.Fprintf(stdin, "%s._domainkey.%s\n", sel, domain)
		}
	}()

	// -----------------------------
	// PARSE OUTPUT (CRITICAL FIX)
	// -----------------------------
	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {

		var out map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			continue
		}

		host, _ := out["host"].(string)

		txtVal, ok := out["txt"]
		if !ok {
			continue
		}

		var txts []string

		switch v := txtVal.(type) {
		case []interface{}:
			for _, t := range v {
				if s, ok := t.(string); ok {
					txts = append(txts, s)
				}
			}
		case []string:
			txts = v
		}

		for _, txt := range txts {

			// ---- SPF ----
			if host == domain && strings.Contains(txt, "v=spf1") {
				spfExists = true

				if strings.Contains(txt, "-all") {
					spfPolicy = "strict"
				} else if strings.Contains(txt, "~all") {
					spfPolicy = "soft"
				}
			}

			// ---- DMARC ----
			if strings.HasPrefix(host, "_dmarc.") && strings.Contains(txt, "v=DMARC1") {
				dmarcExists = true

				if strings.Contains(txt, "p=reject") {
					dmarcPolicy = "reject"
				} else if strings.Contains(txt, "p=quarantine") {
					dmarcPolicy = "quarantine"
				} else if strings.Contains(txt, "p=none") {
					dmarcPolicy = "none"
				}
			}

			// ---- DKIM ----
			if strings.Contains(host, "._domainkey.") && strings.Contains(txt, "v=DKIM1") {
				dkimExists = true
			}
		}
	}

	_ = cmd.Wait()

	// -----------------------------
	// FINAL SCORING
	// -----------------------------
	status := "weak"
	risk := "high"

	if spfExists && dkimExists && dmarcPolicy == "reject" {
		status = "strong"
		risk = "low"
	} else if spfExists && dmarcExists {
		status = "moderate"
		risk = "medium"
	}

	// -----------------------------
	// FINAL OUTPUT
	// -----------------------------
	hostData["mail_security"] = map[string]any{
		"spf": map[string]any{
			"exists": spfExists,
			"policy": spfPolicy,
		},
		"dkim": map[string]any{
			"exists": dkimExists,
		},
		"dmarc": map[string]any{
			"exists": dmarcExists,
			"policy": dmarcPolicy,
		},
		"status": status,
		"risk":   risk,
	}

	result := core.Result{
		Scanner:  f.Name(),
		Category: f.Category(),
		Target:   domain,
		Data: map[string]interface{}{
			"host":       hostData,
			"subdomains": subdomains.Data,
		},
		Timestamp: time.Now(),
	}

	return result, nil
}
