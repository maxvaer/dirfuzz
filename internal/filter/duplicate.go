package filter

import (
	"sync"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

// responseKey identifies a unique response shape by status code and body hash.
type responseKey struct {
	statusCode int
	bodyHash   [16]byte
}

// fuzzyKey groups responses by status and structural shape (line count +
// bucketed word count). This catches catch-all pages that embed the requested
// URL in the body — each hash is unique but line count and word count are
// nearly identical.
type fuzzyKey struct {
	statusCode int
	lineCount  int
	wordBucket int // wordCount / 5
}

// DuplicateFilter detects and filters responses that appear repeatedly with
// the same status code and body content. This catches catch-all routes (e.g.
// /app/login/* always serving the same login page) that the smart filter
// can't detect because its calibration probes hit a different route.
//
// Two detection modes:
//   - Exact: same (statusCode, bodyHash) — threshold occurrences allowed.
//   - Fuzzy: same (statusCode, lineCount, ~wordCount) — 3× threshold
//     occurrences allowed. Catches pages that embed the requested URL,
//     making each hash unique while the page structure stays the same.
type DuplicateFilter struct {
	mu             sync.Mutex
	seen           map[responseKey]int
	fuzzySeen      map[fuzzyKey]int
	threshold      int
	fuzzyThreshold int
}

// NewDuplicateFilter returns a filter that allows up to threshold identical
// responses through before filtering the rest. A threshold of 2 means the
// first 2 results with the same (status, body) pass, then duplicates are
// hidden. Fuzzy detection uses 3× the threshold.
func NewDuplicateFilter(threshold int) *DuplicateFilter {
	fuzzyT := threshold * 3
	if fuzzyT < 5 {
		fuzzyT = 5
	}
	return &DuplicateFilter{
		seen:           make(map[responseKey]int),
		fuzzySeen:      make(map[fuzzyKey]int),
		threshold:      threshold,
		fuzzyThreshold: fuzzyT,
	}
}

func (d *DuplicateFilter) Name() string { return "duplicate" }

func (d *DuplicateFilter) ShouldFilter(result *scanner.ScanResult) bool {
	exact := responseKey{
		statusCode: result.StatusCode,
		bodyHash:   result.BodyHash,
	}
	fuzzy := fuzzyKey{
		statusCode: result.StatusCode,
		lineCount:  result.LineCount,
		wordBucket: result.WordCount / 5,
	}

	d.mu.Lock()
	d.seen[exact]++
	exactCount := d.seen[exact]
	d.fuzzySeen[fuzzy]++
	fuzzyCount := d.fuzzySeen[fuzzy]
	d.mu.Unlock()

	if exactCount > d.threshold {
		return true
	}
	if fuzzyCount > d.fuzzyThreshold {
		return true
	}
	return false
}
