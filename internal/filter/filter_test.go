package filter

import (
	"testing"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

func TestStatusFilter_Include(t *testing.T) {
	f := NewStatusFilter([]int{200, 301}, nil)

	r200 := &scanner.ScanResult{StatusCode: 200}
	if f.ShouldFilter(r200) {
		t.Error("200 should pass include filter")
	}

	r404 := &scanner.ScanResult{StatusCode: 404}
	if !f.ShouldFilter(r404) {
		t.Error("404 should be filtered by include filter")
	}
}

func TestStatusFilter_Exclude(t *testing.T) {
	f := NewStatusFilter(nil, []int{404, 500})

	r200 := &scanner.ScanResult{StatusCode: 200}
	if f.ShouldFilter(r200) {
		t.Error("200 should pass exclude filter")
	}

	r404 := &scanner.ScanResult{StatusCode: 404}
	if !f.ShouldFilter(r404) {
		t.Error("404 should be filtered by exclude filter")
	}
}

func TestSizeFilter(t *testing.T) {
	f := NewSizeFilter([]int{0, 1234})

	r := &scanner.ScanResult{ContentLength: 1234}
	if !f.ShouldFilter(r) {
		t.Error("size 1234 should be filtered")
	}

	r.ContentLength = 5678
	if f.ShouldFilter(r) {
		t.Error("size 5678 should pass")
	}
}

func TestChain_ShortCircuits(t *testing.T) {
	chain := NewChain()
	chain.Add(NewStatusFilter(nil, []int{404}))
	chain.Add(NewSizeFilter([]int{0}))

	// Status filter should catch this first.
	r := &scanner.ScanResult{StatusCode: 404, ContentLength: 0}
	filtered, reason := chain.Apply(r)
	if !filtered {
		t.Error("expected chain to filter")
	}
	if reason != "status" {
		t.Errorf("expected reason 'status', got %q", reason)
	}
}
