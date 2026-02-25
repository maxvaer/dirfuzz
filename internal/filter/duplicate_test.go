package filter

import (
	"crypto/md5"
	"fmt"
	"testing"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

func TestDuplicateFilter_Name(t *testing.T) {
	f := NewDuplicateFilter(2)
	if f.Name() != "duplicate" {
		t.Errorf("Name() = %q, want %q", f.Name(), "duplicate")
	}
}

func TestDuplicateFilter_AllowsUpToThreshold(t *testing.T) {
	f := NewDuplicateFilter(3)
	body := []byte("login page content")
	hash := md5.Sum(body)

	for i := 1; i <= 3; i++ {
		result := &scanner.ScanResult{StatusCode: 200, BodyHash: hash}
		if f.ShouldFilter(result) {
			t.Errorf("call %d: should NOT filter (threshold 3)", i)
		}
	}

	// 4th occurrence should be filtered.
	result := &scanner.ScanResult{StatusCode: 200, BodyHash: hash}
	if !f.ShouldFilter(result) {
		t.Error("call 4: should filter (exceeds threshold 3)")
	}
}

func TestDuplicateFilter_DifferentStatusCodesAreSeparate(t *testing.T) {
	f := NewDuplicateFilter(1)
	hash := md5.Sum([]byte("same body"))

	r200 := &scanner.ScanResult{StatusCode: 200, BodyHash: hash}
	r301 := &scanner.ScanResult{StatusCode: 301, BodyHash: hash}

	// First of each status code should pass.
	if f.ShouldFilter(r200) {
		t.Error("first 200 should pass")
	}
	if f.ShouldFilter(r301) {
		t.Error("first 301 should pass")
	}

	// Second of each should be filtered.
	if !f.ShouldFilter(r200) {
		t.Error("second 200 should be filtered")
	}
	if !f.ShouldFilter(r301) {
		t.Error("second 301 should be filtered")
	}
}

func TestDuplicateFilter_DifferentBodiesAreSeparate(t *testing.T) {
	f := NewDuplicateFilter(1)

	hashA := md5.Sum([]byte("page A"))
	hashB := md5.Sum([]byte("page B"))

	rA := &scanner.ScanResult{StatusCode: 200, BodyHash: hashA}
	rB := &scanner.ScanResult{StatusCode: 200, BodyHash: hashB}

	if f.ShouldFilter(rA) {
		t.Error("first body A should pass")
	}
	if f.ShouldFilter(rB) {
		t.Error("first body B should pass")
	}
	if !f.ShouldFilter(rA) {
		t.Error("second body A should be filtered")
	}
	if !f.ShouldFilter(rB) {
		t.Error("second body B should be filtered")
	}
}

func TestDuplicateFilter_UniqueResponsesNeverFiltered(t *testing.T) {
	f := NewDuplicateFilter(2)

	// 100 unique responses should all pass (each has unique hash,
	// word count, and line count).
	for i := 0; i < 100; i++ {
		hash := md5.Sum([]byte{byte(i), byte(i >> 8)})
		result := &scanner.ScanResult{
			StatusCode: 200,
			BodyHash:   hash,
			WordCount:  i * 10, // spread across different buckets
			LineCount:  i * 5,
		}
		if f.ShouldFilter(result) {
			t.Errorf("unique response %d should not be filtered", i)
		}
	}
}

func TestDuplicateFilter_FuzzyDetectsURLEmbeddedPages(t *testing.T) {
	// Simulate a catch-all page that embeds the requested URL,
	// making each hash unique but keeping structure (lines, words) stable.
	f := NewDuplicateFilter(2)
	// fuzzyThreshold = max(2*3, 5) = 6

	lineCount := 150
	wordCount := 320 // bucket = 320/5 = 64

	for i := 0; i < 20; i++ {
		// Each body is unique (contains path), so hash differs.
		body := fmt.Sprintf("<html>login page /app/login/path%d</html>", i)
		hash := md5.Sum([]byte(body))
		result := &scanner.ScanResult{
			StatusCode:    200,
			ContentLength: int64(len(body)),
			BodyHash:      hash,
			WordCount:     wordCount,
			LineCount:     lineCount,
		}
		filtered := f.ShouldFilter(result)

		// First 6 should pass (fuzzyThreshold=6), rest should be filtered.
		if i < 6 && filtered {
			t.Errorf("fuzzy call %d: should NOT filter (within fuzzy threshold)", i)
		}
		if i >= 6 && !filtered {
			t.Errorf("fuzzy call %d: should filter (exceeds fuzzy threshold)", i)
		}
	}
}

func TestDuplicateFilter_FuzzyMinThreshold(t *testing.T) {
	// With threshold=1, fuzzy threshold should be min 5 (not 1*3=3).
	f := NewDuplicateFilter(1)
	if f.fuzzyThreshold != 5 {
		t.Errorf("fuzzyThreshold = %d, want 5 (minimum)", f.fuzzyThreshold)
	}
}

func TestDuplicateFilter_FuzzyDifferentStructureNotGrouped(t *testing.T) {
	// Pages with different line counts should NOT be grouped.
	f := NewDuplicateFilter(1)

	for i := 0; i < 20; i++ {
		hash := md5.Sum([]byte(fmt.Sprintf("page %d", i)))
		result := &scanner.ScanResult{
			StatusCode: 200,
			BodyHash:   hash,
			WordCount:  100,
			LineCount:  i * 10, // each has different line count
		}
		if f.ShouldFilter(result) {
			t.Errorf("structurally different response %d should not be fuzzy-filtered", i)
		}
	}
}
