package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"scanner-platform/scanner-engine/core"
)

type TLSDataCollection struct{}

func NewTLSDataCollection() *TLSDataCollection {
	return &TLSDataCollection{}
}

func (f *TLSDataCollection) Name() string {
	return "TLS Scanner"
}

func (f *TLSDataCollection) Category() string {
	return "Collection"
}

func isTLSCandidate(port int) bool {
	return map[int]bool{
		443: true, 8443: true, 9443: true,
		993: true, 995: true, 465: true, 587: true,
	}[port]
}

func detectWildcard(sans []string) bool {
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") {
			return true
		}
	}
	return false
}

// toPortDataList normalizes whatever shape port_collection arrives as into a
// []core.PortData. PortFilter stores []core.PortData, but older/alternate
// code paths leave []interface{}{map[string]any} — TLS used to only accept the
// latter, silently skipping every subdomain in production.
func toPortDataList(raw any) ([]core.PortData, bool) {
	switch v := raw.(type) {
	case []core.PortData:
		return v, true
	case []any:
		var out []core.PortData
		for _, p := range v {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			pf, ok := pm["port"].(float64)
			if !ok {
				continue
			}
			out = append(out, core.PortData{Port: int(pf)})
		}
		return out, len(out) > 0
	}
	return nil, false
}

func (f *TLSDataCollection) RunCollectionScanner(
	ctx context.Context,
	subdomains core.Result,
	domain string,
) (core.Result, error) {

	// 300s to match the collection stage budget (pipeline.go) — with a 120s
	// cap, tlsx got killed before probing every host's TLS ports, and hosts
	// without TLS data scored as "clean" even when their certs were expired.
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()

	empty := core.Result{
		Scanner:   f.Name(),
		Category:  f.Category(),
		Target:    domain,
		Data:      []any{},
		Timestamp: time.Now(),
	}

	cmd := exec.CommandContext(
		ctx,
		"tlsx",
		"-silent",
		"-json",
		"-jarm",
		"-tls-version",
		"-cipher",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return empty, fmt.Errorf("stdin error: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return empty, fmt.Errorf("stdout error: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return empty, fmt.Errorf("tlsx start error: %w", err)
	}

	// -----------------------------
	// INPUT FEEDER (SAFE VERSION)
	// -----------------------------
	go func() {
		defer stdin.Close()

		items, ok := subdomains.Data.([]any)
		if !ok || items == nil {
			fmt.Println("[TLS] invalid input data format")
			return
		}

		for _, item := range items {

			m, ok := item.(map[string]any)
			if !ok {
				continue
			}

			host, _ := m["subdomain"].(string)
			if host == "" {
				continue
			}

			ports, ok := toPortDataList(m["port_collection"])
			if !ok {
				continue
			}

			for _, p := range ports {
				if !isTLSCandidate(p.Port) {
					continue
				}

				fmt.Fprintf(stdin, "%s:%d\n", host, p.Port)
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {

		select {
		case <-ctx.Done():
			return empty, ctx.Err()
		default:
		}

		var out core.TLSXOutput

		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			continue
		}

		port, err := strconv.Atoi(out.Port)
		if err != nil {
			continue
		}

		var expired bool
		if t, err := time.Parse(time.RFC3339, out.NotAfter); err == nil {
			expired = time.Now().After(t)
		}

		tlsData := &core.TLSData{
			Enabled:     out.ProbeStatus,
			Version:     out.TLSVersion,
			Cipher:      out.Cipher,
			Issuer:      out.IssuerDN,
			Subject:     out.SubjectDN,
			NotBefore:   out.NotBefore,
			NotAfter:    out.NotAfter,
			Expired:     expired,
			SelfSigned:  out.SubjectCN == out.IssuerCN,
			Wildcard:    detectWildcard(out.SubjectAN),
			SAN:         out.SubjectAN,
			JARM:        out.JARMHash,
			Fingerprint: out.FingerprintHash.SHA256,
		}

		items, ok := subdomains.Data.([]any)
		if !ok {
			continue
		}

		for _, item := range items {

			m, ok := item.(map[string]any)
			if !ok {
				continue
			}

			if m["subdomain"] != out.Host {
				continue
			}

			ports, ok := toPortDataList(m["port_collection"])
			if !ok {
				continue
			}

			for i := range ports {
				if ports[i].Port == port {
					ports[i].TLS = tlsData
				}
			}

			m["port_collection"] = ports
		}
	}

	if err := scanner.Err(); err != nil {
		return empty, fmt.Errorf("scanner error: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return empty, fmt.Errorf("tlsx process error: %w", err)
	}

	return core.Result{
		Scanner:   f.Name(),
		Category:  f.Category(),
		Target:    domain,
		Data:      subdomains.Data,
		Timestamp: time.Now(),
	}, nil
}
