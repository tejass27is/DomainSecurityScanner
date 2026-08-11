package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func main() {

	ctx := context.Background()

	// Domain comes from the CLI arg (README documents `go run cmd/scanner/main.go <domain>`);
	// fall back to a default only for convenience.
	domain_name := "www.isecurify.co"
	if len(os.Args) > 1 {
		domain_name = os.Args[1]
	}

	// Optional second arg `<host>:<port>` triggers a single-port rescan at the end.
	var rescanHost string
	var rescanPort int
	if len(os.Args) > 2 {
		parts := strings.SplitN(os.Args[2], ":", 2)
		if len(parts) == 2 {
			if p, err := strconv.Atoi(parts[1]); err == nil && p >= 1 && p <= 65535 {
				rescanHost = parts[0]
				rescanPort = p
			} else {
				fmt.Println("Invalid rescan target (want <host>:<port 1-65535>), ignoring:", os.Args[2])
			}
		}
	}

	fmt.Println("Starting scanning for domain:", domain_name)

	// =====================================
	// DISCOVERY
	// =====================================

	fmt.Println("Scanner 1 : Subdomain Discovery")

	registry := core.NewRegistry()

	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewDiscoveryPipeline(registry)

	results, err := pipeline.ExecuteDiscoveryScanner(ctx, domain_name)
	if err != nil {
		panic(err)
	}

	discoveryData, ok := results.Data.([]string)
	if !ok {
		panic("invalid discovery result format")
	}

	fmt.Println("Total Subdomains Found:", len(discoveryData))

	// =====================================
	// FILTER
	// =====================================

	fmt.Println("Scanner 2 : Subdomain Filter")

	filterRegistry := core.NewFilterScannerRegistry()

	// Same filter set as the production worker.
	filterRegistry.RegisterFilterScanner(filters.NewDedupFilter())
	filterRegistry.RegisterFilterScanner(filters.NewDNSFilter())
	filterRegistry.RegisterFilterScanner(filters.NewHTTPFilter())

	filterPipeline := core.NewFilterPipeline(filterRegistry)

	filteredResults, err := filterPipeline.ExecuteFilterScanners(
		ctx,
		results,
		domain_name,
	)

	if err != nil {
		panic(err)
	}

	filterData, ok := filteredResults.Data.([]interface{})
	if !ok {
		panic("invalid filtered result format")
	}

	fmt.Println("Total Filtered Subdomains Found:", len(filterData))

	// =====================================
	// COLLECTION
	// =====================================

	fmt.Println("Scanner 3 : Data Collection")

	collectionRegistry := core.NewCollectionRegistry()

	// Same collection set as the production worker.
	collectionRegistry.RegisterCollectionScanner(collection.NewDNSDataOutput())
	collectionRegistry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
	collectionRegistry.RegisterCollectionScanner(collection.NewPortFilter())
	collectionRegistry.RegisterCollectionScanner(collection.NewTLSDataCollection())
	collectionRegistry.RegisterCollectionScanner(collection.NewMailSecurityDataCollection())

	collectionPipeline := core.NewCollectionPipeline(collectionRegistry)

	collectionResults, err := collectionPipeline.ExecuteCollectionScanenrs(
		ctx,
		filteredResults,
		domain_name,
	)

	if err != nil {
		panic(err)
	}

	// The Mail Security scanner wraps the data into {host, subdomains}.
	var collectionData []interface{}
	if m, ok := collectionResults.Data.(map[string]interface{}); ok {
		if subs, ok := m["subdomains"].([]interface{}); ok {
			collectionData = subs
		} else {
			collectionData = []interface{}{m}
		}
	} else {
		collectionData, ok = collectionResults.Data.([]interface{})
		if !ok {
			panic("invalid collection result format")
		}
	}

	// =====================================
	// OUTPUT
	// =====================================

	for _, r := range collectionData {

		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			fmt.Println("marshal error:", err)
			continue
		}

		fmt.Println(string(data))
	}
	// =====================================
	// PORT RESCAN (optional, CLI-driven)
	// =====================================
	// Only runs when given as `go run cmd/scanner/main.go <domain> <host>:<port>`,
	// so the standalone tool never pings an external target on its own.
	if rescanHost != "" {
		fmt.Println("\nTesting Single Port Rescan")
		fmt.Println(RescanSinglePort(rescanHost, rescanPort))
	}
}
