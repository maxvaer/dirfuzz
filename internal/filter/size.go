package filter

import "github.com/maxvaer/dirfuzz/internal/scanner"

// SizeFilter excludes results matching specific response body sizes.
type SizeFilter struct {
	sizes map[int64]struct{}
}

// NewSizeFilter creates a filter that drops results with the given body sizes.
func NewSizeFilter(excludeSizes []int) *SizeFilter {
	f := &SizeFilter{sizes: make(map[int64]struct{}, len(excludeSizes))}
	for _, s := range excludeSizes {
		f.sizes[int64(s)] = struct{}{}
	}
	return f
}

func (f *SizeFilter) Name() string { return "size" }

func (f *SizeFilter) ShouldFilter(result *scanner.ScanResult) bool {
	_, ok := f.sizes[result.ContentLength]
	return ok
}
