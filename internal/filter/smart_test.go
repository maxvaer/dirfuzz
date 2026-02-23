package filter

import (
	"testing"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

func TestSmartFilter_HashExactMatch(t *testing.T) {
	// Simulate a baseline where all probes returned identical content.
	sf := &SmartFilter{
		baselines: []baseline{
			{
				statusCode:    200,
				contentLength: 1234,
				bodyHash:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				wordCount:     100,
				lineCount:     20,
				mode:          matchHashExact,
			},
		},
		threshold: 50,
	}

	// Exact hash match should be filtered.
	result := &scanner.ScanResult{
		StatusCode:    200,
		ContentLength: 1234,
		BodyHash:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		WordCount:     100,
		LineCount:     20,
	}
	if !sf.ShouldFilter(result) {
		t.Error("expected exact hash match to be filtered")
	}

	// Different hash should pass through.
	result.BodyHash = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	result.ContentLength = 5000
	result.WordCount = 500
	if sf.ShouldFilter(result) {
		t.Error("expected different hash to pass through")
	}
}

func TestSmartFilter_FuzzyLengthMatch(t *testing.T) {
	sf := &SmartFilter{
		baselines: []baseline{
			{
				statusCode:    200,
				contentLength: 4500,
				wordCount:     200,
				lineCount:     50,
				mode:          matchFuzzyLength,
			},
		},
		threshold: 50,
	}

	// Within threshold: length 4520, word count 198 → should be filtered.
	result := &scanner.ScanResult{
		StatusCode:    200,
		ContentLength: 4520,
		WordCount:     198,
	}
	if !sf.ShouldFilter(result) {
		t.Error("expected fuzzy match within threshold to be filtered")
	}

	// Outside length threshold: length 4600 → should pass.
	result.ContentLength = 4600
	if sf.ShouldFilter(result) {
		t.Error("expected length outside threshold to pass through")
	}

	// Within length but very different word count → should pass.
	result.ContentLength = 4510
	result.WordCount = 50
	if sf.ShouldFilter(result) {
		t.Error("expected divergent word count to pass through")
	}
}

func TestSmartFilter_DifferentStatusCode(t *testing.T) {
	sf := &SmartFilter{
		baselines: []baseline{
			{
				statusCode:    200,
				contentLength: 1234,
				bodyHash:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				mode:          matchHashExact,
			},
		},
		threshold: 50,
	}

	// Status 301 has no baseline → should pass.
	result := &scanner.ScanResult{
		StatusCode:    301,
		ContentLength: 1234,
		BodyHash:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	if sf.ShouldFilter(result) {
		t.Error("expected different status code to pass through")
	}
}

func TestSmartFilter_EmptyBody(t *testing.T) {
	sf := &SmartFilter{
		baselines: []baseline{
			{
				statusCode:    200,
				contentLength: 0,
				bodyHash:      [16]byte{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e},
				wordCount:     0,
				lineCount:     0,
				mode:          matchHashExact,
			},
		},
		threshold: 50,
	}

	// Empty body matching the baseline hash → should be filtered.
	result := &scanner.ScanResult{
		StatusCode:    200,
		ContentLength: 0,
		BodyHash:      [16]byte{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e},
	}
	if !sf.ShouldFilter(result) {
		t.Error("expected empty body hash match to be filtered")
	}
}

func TestSmartFilter_MultipleBaselines(t *testing.T) {
	sf := &SmartFilter{
		baselines: []baseline{
			{
				statusCode:    200,
				contentLength: 1000,
				bodyHash:      [16]byte{1},
				mode:          matchHashExact,
			},
			{
				statusCode:    302,
				contentLength: 200,
				wordCount:     10,
				mode:          matchFuzzyLength,
			},
		},
		threshold: 50,
	}

	// 200 with matching hash → filtered.
	r200 := &scanner.ScanResult{StatusCode: 200, BodyHash: [16]byte{1}, ContentLength: 1000}
	if !sf.ShouldFilter(r200) {
		t.Error("expected 200 hash match to be filtered")
	}

	// 302 with close length and word count → filtered.
	r302 := &scanner.ScanResult{StatusCode: 302, ContentLength: 210, WordCount: 10}
	if !sf.ShouldFilter(r302) {
		t.Error("expected 302 fuzzy match to be filtered")
	}

	// 200 with different hash → pass.
	r200pass := &scanner.ScanResult{StatusCode: 200, BodyHash: [16]byte{99}, ContentLength: 5000}
	if sf.ShouldFilter(r200pass) {
		t.Error("expected 200 with different hash to pass")
	}
}
