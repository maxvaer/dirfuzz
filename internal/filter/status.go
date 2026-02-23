package filter

import "github.com/maxvaer/dirfuzz/internal/scanner"

// StatusFilter includes or excludes results based on HTTP status codes.
type StatusFilter struct {
	include map[int]struct{}
	exclude map[int]struct{}
}

// NewStatusFilter creates a status code filter. If include is non-empty, only
// those codes pass through. If exclude is non-empty, those codes are filtered.
func NewStatusFilter(include, exclude []int) *StatusFilter {
	f := &StatusFilter{
		include: make(map[int]struct{}, len(include)),
		exclude: make(map[int]struct{}, len(exclude)),
	}
	for _, code := range include {
		f.include[code] = struct{}{}
	}
	for _, code := range exclude {
		f.exclude[code] = struct{}{}
	}
	return f
}

func (f *StatusFilter) Name() string { return "status" }

func (f *StatusFilter) ShouldFilter(result *scanner.ScanResult) bool {
	if len(f.include) > 0 {
		_, ok := f.include[result.StatusCode]
		return !ok // filter if NOT in include list
	}
	if len(f.exclude) > 0 {
		_, ok := f.exclude[result.StatusCode]
		return ok // filter if in exclude list
	}
	return false
}
