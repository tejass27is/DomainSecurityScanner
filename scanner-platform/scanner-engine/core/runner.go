package core

import (
	"context"
)

type Runner struct{}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) RunDiscoveryScanner(ctx context.Context,
	scanner DiscoveryScanner,
	target string,
) (Result, error) {
	return scanner.RunDiscoveryScanner(ctx, target)
}

func (r *Runner) RunFilterScanners(ctx context.Context, 
	scanner FilterScanner, 
	subdomains Result,
	domain string,
) (Result, error){
	return scanner.RunFilterScanner(ctx, subdomains, domain)
}

func (r *Runner) RunCollectionScanners(ctx context.Context, 
	scanner CollectionScanners,
	subdomains Result,
	domain string,
) (Result, error) {
	return scanner.RunCollectionScanner(ctx, subdomains, domain)
}