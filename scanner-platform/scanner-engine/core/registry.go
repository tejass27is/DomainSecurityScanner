package core

type Registry struct {
	scanners []DiscoveryScanner
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(scanner DiscoveryScanner) {
	r.scanners = append(r.scanners, scanner)
}

func (r *Registry) All() []DiscoveryScanner {
	return r.scanners
}

type FilterScannerRegistry struct {
	filterscanners []FilterScanner
}

func NewFilterScannerRegistry() *FilterScannerRegistry {
	return &FilterScannerRegistry{}
}

func (r *FilterScannerRegistry) RegisterFilterScanner(scanner FilterScanner) {
	r.filterscanners = append(r.filterscanners, scanner)
}

func (r *Registry) IsFilterScanner(scanner FilterScanner) bool {
	return true
}

func (r *FilterScannerRegistry) All() []FilterScanner {
	return r.filterscanners
}

type CollectionScannerRegistry struct {
	CollectionScanners []CollectionScanners
}

func NewCollectionRegistry() *CollectionScannerRegistry {
	return &CollectionScannerRegistry{}
}

func (r *CollectionScannerRegistry) RegisterCollectionScanner(scanner CollectionScanners) {
	r.CollectionScanners = append(r.CollectionScanners, scanner)
}

func (r *CollectionScannerRegistry) All() []CollectionScanners {
	return r.CollectionScanners
}
