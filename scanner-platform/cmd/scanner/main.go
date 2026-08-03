package main

import (
	"context"
	"encoding/json"
	"fmt"

	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func main() {

	ctx := context.Background()

	domain_name := "www.isecurify.co"

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

	filterRegistry.RegisterFilterScanner(filters.NewDedupFilter())
	filterRegistry.RegisterFilterScanner(filters.NewDNSFilter())

	filterPipeline := core.NewFilterPipeline(filterRegistry)

	filteredResults, err := filterPipeline.ExecuteFilterScanners(
		ctx,
		results,
		domain_name,
	)

	if err != nil {
		panic(err)
	}

	filterData, ok := filteredResults.Data.([]any)
	if !ok {
		panic("invalid filtered result format")
	}

	fmt.Println("Total Filtered Subdomains Found:", len(filterData))

	// =====================================
	// COLLECTION
	// =====================================

	fmt.Println("Scanner 3 : Data Collection")

	collectionRegistry := core.NewCollectionRegistry()

	collectionRegistry.RegisterCollectionScanner(collection.NewDNSDataOutput())
	collectionRegistry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
	collectionRegistry.RegisterCollectionScanner(collection.NewPortFilter())
	collectionRegistry.RegisterCollectionScanner(collection.NewServiceDetectionScanner())
	collectionRegistry.RegisterCollectionScanner(collection.NewTLSDataCollection())

	collectionPipeline := core.NewCollectionPipeline(collectionRegistry)

	collectionResults, err := collectionPipeline.ExecuteCollectionScanenrs(
		ctx,
		filteredResults,
		domain_name,
	)

	if err != nil {
		panic(err)
	}

	collectionData, ok := collectionResults.Data.([]any)
	if !ok {
		panic("invalid collection result format")
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
	// PORT RESCAN TEST
	// =====================================

	fmt.Println("\nTesting Single Port Rescan")

	rescanResult := RescanSinglePort(
		"officebeacon.com",
		80,
	)

	fmt.Println(rescanResult)
}
