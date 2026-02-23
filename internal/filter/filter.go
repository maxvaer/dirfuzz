package filter

import "github.com/maxvaer/dirfuzz/internal/scanner"

// Filter decides whether a scan result should be hidden from output.
type Filter interface {
	Name() string
	ShouldFilter(result *scanner.ScanResult) bool
}

// Chain applies multiple filters in order, short-circuiting on the first match.
type Chain struct {
	filters []Filter
}

// NewChain returns an empty filter chain.
func NewChain() *Chain {
	return &Chain{}
}

// Add appends a filter to the chain.
func (c *Chain) Add(f Filter) {
	c.filters = append(c.filters, f)
}

// Apply runs every filter against the result. Returns true and the filter
// name if the result should be filtered out.
func (c *Chain) Apply(result *scanner.ScanResult) (bool, string) {
	for _, f := range c.filters {
		if f.ShouldFilter(result) {
			return true, f.Name()
		}
	}
	return false, ""
}
