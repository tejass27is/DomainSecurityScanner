package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func main() {

	ctx := context.Background()

	// Domain comes from the CLI arg (README documents `go run cmd/scanner/main.go <domain>`);
	// fall back to a default only for convenience.
	domain_name := "officebeacon.com"
	if len(os.Args) > 1 {
		domain_name = os.Args[1]
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
}
