package filter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

type matchMode int

const (
	matchHashExact   matchMode = iota // all calibration bodies were byte-identical
	matchFuzzyLength                  // bodies varied but lengths converged
)

type baseline struct {
	statusCode    int
	contentLength int64
	bodyHash      [16]byte
	wordCount     int
	lineCount     int
	mode          matchMode
}

// SmartFilter detects custom 404 pages (soft-404s) by calibrating against
// random non-existent paths before the scan starts.
type SmartFilter struct {
	baselines []baseline
	threshold int // byte tolerance for fuzzy length matching
}

// NewSmartFilter performs calibration against the target and returns a filter
// that can detect soft-404 responses during scanning. basePath is the
// directory prefix for probes (e.g. "" for root, "Home" for /Home/).
// Returns an error if calibration fails entirely.
func NewSmartFilter(ctx context.Context, req *scanner.Requester, basePath string, threshold int) (*SmartFilter, error) {
	probes := generateProbes(5)

	var results []probeResult
	for _, probe := range probes {
		if basePath != "" {
			probe = strings.TrimRight(basePath, "/") + "/" + probe
		}
		resp, err := req.Do(ctx, "GET", probe, "")
		if err != nil {
			continue
		}
		results = append(results, probeResult{
			statusCode:    resp.StatusCode,
			contentLength: resp.ContentLength,
			bodyHash:      resp.BodyHash,
			wordCount:     resp.WordCount,
			lineCount:     resp.LineCount,
		})
	}

	return buildSmartFilter(results, len(probes), threshold)
}

// NewSmartFilterVHost performs calibration for virtual host fuzzing by
// sending requests with random subdomain Host headers.
func NewSmartFilterVHost(ctx context.Context, req *scanner.Requester, targetURL string, threshold int) (*SmartFilter, error) {
	probeHosts := generateVHostProbes(5)

	var results []probeResult
	for _, host := range probeHosts {
		resp, err := req.Do(ctx, "GET", "/", host)
		if err != nil {
			continue
		}
		results = append(results, probeResult{
			statusCode:    resp.StatusCode,
			contentLength: resp.ContentLength,
			bodyHash:      resp.BodyHash,
			wordCount:     resp.WordCount,
			lineCount:     resp.LineCount,
		})
	}

	return buildSmartFilter(results, len(probeHosts), threshold)
}

type probeResult struct {
	statusCode    int
	contentLength int64
	bodyHash      [16]byte
	wordCount     int
	lineCount     int
}

func buildSmartFilter(results []probeResult, probeCount, threshold int) (*SmartFilter, error) {
	if len(results) < 2 {
		return nil, fmt.Errorf("only %d/%d calibration probes succeeded, need at least 2", len(results), probeCount)
	}

	groups := make(map[int][]probeResult)
	for _, r := range results {
		groups[r.statusCode] = append(groups[r.statusCode], r)
	}

	sf := &SmartFilter{threshold: threshold}

	for code, group := range groups {
		if len(group) < 2 {
			continue
		}

		allSameHash := true
		for i := 1; i < len(group); i++ {
			if group[i].bodyHash != group[0].bodyHash {
				allSameHash = false
				break
			}
		}

		if allSameHash {
			sf.baselines = append(sf.baselines, baseline{
				statusCode:    code,
				contentLength: group[0].contentLength,
				bodyHash:      group[0].bodyHash,
				wordCount:     group[0].wordCount,
				lineCount:     group[0].lineCount,
				mode:          matchHashExact,
			})
			continue
		}

		lengths := make([]int64, len(group))
		words := make([]int, len(group))
		lines := make([]int, len(group))
		for i, g := range group {
			lengths[i] = g.contentLength
			words[i] = g.wordCount
			lines[i] = g.lineCount
		}

		medianLen := medianInt64(lengths)
		medianWords := medianInt(words)
		medianLines := medianInt(lines)

		converges := true
		for _, l := range lengths {
			if abs64(l-medianLen) > int64(threshold) {
				converges = false
				break
			}
		}

		if converges {
			sf.baselines = append(sf.baselines, baseline{
				statusCode:    code,
				contentLength: medianLen,
				wordCount:     medianWords,
				lineCount:     medianLines,
				mode:          matchFuzzyLength,
			})
		}
	}

	if len(sf.baselines) == 0 {
		return nil, fmt.Errorf("calibration could not establish any baselines")
	}

	return sf, nil
}

func (sf *SmartFilter) Name() string { return "smart-404" }

func (sf *SmartFilter) ShouldFilter(result *scanner.ScanResult) bool {
	// Empty body with 200 status is almost certainly a catch-all, not real content.
	if result.StatusCode == 200 && result.ContentLength == 0 {
		return true
	}

	for _, b := range sf.baselines {
		if result.StatusCode != b.statusCode {
			continue
		}

		switch b.mode {
		case matchHashExact:
			return result.BodyHash == b.bodyHash

		case matchFuzzyLength:
			// Composite scoring: require at least 2 of 3 metrics to match.
			// This catches pages that embed the requested URL (changing size
			// slightly) while keeping word/line counts stable.
			lengthOK := abs64(result.ContentLength-b.contentLength) <= int64(sf.threshold)
			wordThreshold := max(5, b.wordCount/20) // 5%, min 5
			wordOK := absInt(result.WordCount-b.wordCount) <= wordThreshold
			lineThreshold := max(2, b.lineCount/10) // 10%, min 2
			lineOK := absInt(result.LineCount-b.lineCount) <= lineThreshold

			matches := 0
			if lengthOK {
				matches++
			}
			if wordOK {
				matches++
			}
			if lineOK {
				matches++
			}
			return matches >= 2
		}

		return false
	}
	return false
}

// generateProbes creates random path strings that are extremely unlikely to
// exist on any real server.
func generateProbes(n int) []string {
	probes := make([]string, n)
	for i := range probes {
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		probes[i] = "dirfuzz_probe_" + hex.EncodeToString(buf)
	}
	return probes
}

// generateVHostProbes creates random subdomain strings for vhost calibration.
func generateVHostProbes(n int) []string {
	probes := make([]string, n)
	for i := range probes {
		buf := make([]byte, 6)
		_, _ = rand.Read(buf)
		probes[i] = "dirfuzz-" + hex.EncodeToString(buf) + ".probe.invalid"
	}
	return probes
}

func medianInt64(vals []int64) int64 {
	sorted := make([]int64, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func medianInt(vals []int) int {
	sorted := make([]int, len(vals))
	copy(sorted, vals)
	sort.Ints(sorted)
	return sorted[len(sorted)/2]
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func absInt(x int) int {
	return int(math.Abs(float64(x)))
}
