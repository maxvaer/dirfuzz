package filter

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxvaer/dirfuzz/internal/config"
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

func TestNewSmartFilter_BasePathProbesCorrectDirectory(t *testing.T) {
	// Track which paths were requested.
	var mu sync.Mutex
	var requestedPaths []string

	rootBody := "root not found page"
	subdirBody := "subdir custom error page with different content"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedPaths = append(requestedPaths, r.URL.Path)
		mu.Unlock()

		if strings.HasPrefix(r.URL.Path, "/subdir/") {
			fmt.Fprint(w, subdirBody)
		} else {
			fmt.Fprint(w, rootBody)
		}
	}))
	defer server.Close()

	req, err := scanner.NewRequester(&config.Options{
		URL:     server.URL,
		Timeout: 5 * time.Second,
		Threads: 1,
	})
	if err != nil {
		t.Fatalf("creating requester: %v", err)
	}

	ctx := context.Background()

	// Test 1: empty basePath probes root paths.
	requestedPaths = nil
	_, err = NewSmartFilter(ctx, req, "", 50)
	if err != nil {
		t.Fatalf("root smart filter: %v", err)
	}

	mu.Lock()
	rootPaths := make([]string, len(requestedPaths))
	copy(rootPaths, requestedPaths)
	mu.Unlock()

	for _, p := range rootPaths {
		if strings.HasPrefix(p, "/subdir/") {
			t.Errorf("root filter probed subdir path: %s", p)
		}
		if !strings.Contains(p, "dirfuzz_probe_") {
			t.Errorf("root filter probe missing prefix: %s", p)
		}
	}

	// Test 2: basePath "subdir" probes under /subdir/.
	mu.Lock()
	requestedPaths = nil
	mu.Unlock()

	_, err = NewSmartFilter(ctx, req, "subdir", 50)
	if err != nil {
		t.Fatalf("subdir smart filter: %v", err)
	}

	mu.Lock()
	subdirPaths := make([]string, len(requestedPaths))
	copy(subdirPaths, requestedPaths)
	mu.Unlock()

	for _, p := range subdirPaths {
		if !strings.HasPrefix(p, "/subdir/") {
			t.Errorf("subdir filter probed outside subdir: %s", p)
		}
		if !strings.Contains(p, "dirfuzz_probe_") {
			t.Errorf("subdir filter probe missing prefix: %s", p)
		}
	}
}

func TestNewSmartFilter_BasePathDifferentBaselines(t *testing.T) {
	rootBody := "root not found page"
	subdirBody := "subdir custom error page with different content"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/subdir/") {
			fmt.Fprint(w, subdirBody)
		} else {
			fmt.Fprint(w, rootBody)
		}
	}))
	defer server.Close()

	req, err := scanner.NewRequester(&config.Options{
		URL:     server.URL,
		Timeout: 5 * time.Second,
		Threads: 1,
	})
	if err != nil {
		t.Fatalf("creating requester: %v", err)
	}

	ctx := context.Background()

	rootSF, err := NewSmartFilter(ctx, req, "", 50)
	if err != nil {
		t.Fatalf("root smart filter: %v", err)
	}

	subdirSF, err := NewSmartFilter(ctx, req, "subdir", 50)
	if err != nil {
		t.Fatalf("subdir smart filter: %v", err)
	}

	// Result matching root 404 pattern.
	rootResult := &scanner.ScanResult{
		StatusCode:    200,
		ContentLength: int64(len(rootBody)),
		BodyHash:      md5.Sum([]byte(rootBody)),
		WordCount:     len(strings.Fields(rootBody)),
		LineCount:     1,
	}

	// Result matching subdir 404 pattern.
	subdirResult := &scanner.ScanResult{
		StatusCode:    200,
		ContentLength: int64(len(subdirBody)),
		BodyHash:      md5.Sum([]byte(subdirBody)),
		WordCount:     len(strings.Fields(subdirBody)),
		LineCount:     1,
	}

	// Root filter should catch root 404 but not subdir 404.
	if !rootSF.ShouldFilter(rootResult) {
		t.Error("root filter should filter root 404 page")
	}
	if rootSF.ShouldFilter(subdirResult) {
		t.Error("root filter should NOT filter subdir 404 page")
	}

	// Subdir filter should catch subdir 404 but not root 404.
	if !subdirSF.ShouldFilter(subdirResult) {
		t.Error("subdir filter should filter subdir 404 page")
	}
	if subdirSF.ShouldFilter(rootResult) {
		t.Error("subdir filter should NOT filter root 404 page")
	}
}

func TestNewSmartFilter_NestedBasePath(t *testing.T) {
	deepBody := "deeply nested error page"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/a/b/c/") {
			fmt.Fprint(w, deepBody)
		} else {
			fmt.Fprint(w, "other page")
		}
	}))
	defer server.Close()

	req, err := scanner.NewRequester(&config.Options{
		URL:     server.URL,
		Timeout: 5 * time.Second,
		Threads: 1,
	})
	if err != nil {
		t.Fatalf("creating requester: %v", err)
	}

	sf, err := NewSmartFilter(context.Background(), req, "a/b/c", 50)
	if err != nil {
		t.Fatalf("nested smart filter: %v", err)
	}

	result := &scanner.ScanResult{
		StatusCode:    200,
		ContentLength: int64(len(deepBody)),
		BodyHash:      md5.Sum([]byte(deepBody)),
		WordCount:     len(strings.Fields(deepBody)),
		LineCount:     1,
	}
	if !sf.ShouldFilter(result) {
		t.Error("nested filter should filter its own 404 page")
	}
}
