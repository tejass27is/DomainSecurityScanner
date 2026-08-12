package core

import (
	"context"
	"fmt"
	"net"
	"time"
)

func IsCancelled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func WithStageTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

type DiscoveryPipeline struct {
	registry *Registry
	runner   *Runner
}

func NewDiscoveryPipeline(registry *Registry) *DiscoveryPipeline {
	return &DiscoveryPipeline{
		registry: registry,
		runner:   NewRunner(),
	}
}

func (p *DiscoveryPipeline) ExecuteDiscoveryScanner(ctx context.Context, target string) (Result, error) {
	var results []string

	if IsCancelled(ctx) {
		return Result{}, context.Canceled
	}

	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return Result{}, err
	}

	fmt.Println("Starting discovery pipeline for target:", target)

	for _, scanner := range p.registry.All() {
		if IsCancelled(ctx) {
			return Result{}, context.Canceled
		}
		fmt.Println("Running scanner:", scanner.Name())
		stageCtx, cancel := WithStageTimeout(ctx, 45*time.Second)
		res, err := p.runner.RunDiscoveryScanner(stageCtx, scanner, target)
		cancel()
		if err != nil {
			fmt.Println("Scanner error:", scanner.Name(), err)
			continue
		}
		data := res.Data.([]string)
		results = append(results, data...)
		fmt.Println("Completed scanner:", scanner.Name())
		fmt.Println("Total results so far:", len(results))
	}

	discovered_subdomains := Result{
		Scanner:   "discovery_pipeline",
		Category:  "discovery",
		Target:    target,
		Data:      results,
		Timestamp: time.Now(),
	}

	return discovered_subdomains, nil
}

type FilterScannerPipeline struct {
	registry *FilterScannerRegistry
	runner   *Runner
}

func NewFilterPipeline(registry *FilterScannerRegistry) *FilterScannerPipeline {
	return &FilterScannerPipeline{
		registry: registry,
		runner:   NewRunner(),
	}
}

func (p *FilterScannerPipeline) ExecuteFilterScanners(ctx context.Context, discovered_subdomains Result, domain string) (Result, error) {
	fmt.Println("Starting filter pipeline for domain:", domain)
	subdomains := discovered_subdomains

	for _, scanner := range p.registry.All() {
		if IsCancelled(ctx) {
			return Result{}, context.Canceled
		}
		fmt.Println("Running filter scanner:", scanner.Name())
		// 120s (was 30s) so httpx always finishes probing the full host list.
		// With a 30s cap the process gets killed mid-scan and only the hosts
		// probed so far survive — the SAME discovered set produced 7 hosts one
		// run and 34 the next, which is exactly what made scores flip 62↔43.
		stageCtx, cancel := WithStageTimeout(ctx, 120*time.Second)
		res, err := p.runner.RunFilterScanners(stageCtx, scanner, subdomains, domain)
		cancel()
		if err != nil {
			fmt.Println("Filter scanner error:", scanner.Name(), err)
			continue
		}
		fmt.Println("Completed filter scanner:", scanner.Name())
		fmt.Println("Total subdomains so far:", len(res.Data.([]string)))

		subdomains = res
	}

	var data []interface{}

	for _, subdomain := range subdomains.Data.([]string) {
		var filter_structured_subdomains = make(map[string]any)
		filter_structured_subdomains["subdomain"] = subdomain
		data = append(data, filter_structured_subdomains)
	}

	filtered_subdomains := Result{
		Scanner:   "filter_pipeline",
		Category:  "filter",
		Target:    domain,
		Data:      data,
		Timestamp: time.Now(),
	}

	return filtered_subdomains, nil
}

type CollectionPipeline struct {
	registry *CollectionScannerRegistry
	runner   *Runner
}

func NewCollectionPipeline(registry *CollectionScannerRegistry) *CollectionPipeline {
	return &CollectionPipeline{
		registry: registry,
		runner:   NewRunner(),
	}
}

func (c *CollectionPipeline) ExecuteCollectionScanenrs(ctx context.Context, subdomains Result, domain string) (Result, error) {
	fmt.Println("Starting collection pipeline for domain:", domain)

	for _, scanner := range c.registry.All() {
		if IsCancelled(ctx) {
			return Result{}, context.Canceled
		}
		fmt.Println("Running collection scanner:", scanner.Name())
		// 300s (was 90s) so every host gets its full evaluation (ports + TLS).
		// When TLS didn't finish before the old 90s cap, missing TLS data made
		// hosts look "clean" and silently inflated the score.
		stageCtx, cancel := WithStageTimeout(ctx, 300*time.Second)
		res, err := c.runner.RunCollectionScanners(stageCtx, scanner, subdomains, domain)
		cancel()
		if err != nil {
			fmt.Println("Collection scanner error:", scanner.Name(), err)
		}

		fmt.Println("Completed collection scanner:", scanner.Name())

		subdomains = res
	}

	return subdomains, nil
}
