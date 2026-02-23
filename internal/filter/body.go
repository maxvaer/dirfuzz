package filter

import (
	"strings"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

// BodyMatchFilter only passes results whose body contains a given string.
type BodyMatchFilter struct {
	needle string
}

// NewBodyMatchFilter creates a filter that requires the body to contain needle.
func NewBodyMatchFilter(needle string) *BodyMatchFilter {
	return &BodyMatchFilter{needle: needle}
}

func (f *BodyMatchFilter) Name() string { return "body-match" }

func (f *BodyMatchFilter) ShouldFilter(result *scanner.ScanResult) bool {
	return !strings.Contains(string(result.Body), f.needle)
}

// BodyExcludeFilter hides results whose body contains a given string.
type BodyExcludeFilter struct {
	needle string
}

// NewBodyExcludeFilter creates a filter that hides results containing needle.
func NewBodyExcludeFilter(needle string) *BodyExcludeFilter {
	return &BodyExcludeFilter{needle: needle}
}

func (f *BodyExcludeFilter) Name() string { return "body-exclude" }

func (f *BodyExcludeFilter) ShouldFilter(result *scanner.ScanResult) bool {
	return strings.Contains(string(result.Body), f.needle)
}
