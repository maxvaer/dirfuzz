package output

import (
	"sort"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

// SortedWriter buffers results and replays them sorted by a field when
// WriteFooter is called. It wraps any other Writer.
type SortedWriter struct {
	inner   Writer
	sortBy  string
	results []*scanner.ScanResult
}

// NewSortedWriter wraps inner and buffers results for sorted replay.
func NewSortedWriter(inner Writer, sortBy string) *SortedWriter {
	return &SortedWriter{inner: inner, sortBy: sortBy}
}

func (w *SortedWriter) WriteHeader() error {
	return w.inner.WriteHeader()
}

func (w *SortedWriter) WriteResult(result *scanner.ScanResult) error {
	cpy := *result
	w.results = append(w.results, &cpy)
	return nil
}

func (w *SortedWriter) WriteFooter(stats Stats) error {
	sort.Slice(w.results, func(i, j int) bool {
		switch w.sortBy {
		case "status":
			return w.results[i].StatusCode < w.results[j].StatusCode
		case "size":
			return w.results[i].ContentLength < w.results[j].ContentLength
		case "path":
			return w.results[i].Path < w.results[j].Path
		default:
			return false
		}
	})
	for _, r := range w.results {
		if err := w.inner.WriteResult(r); err != nil {
			return err
		}
	}
	return w.inner.WriteFooter(stats)
}

func (w *SortedWriter) Close() error {
	return w.inner.Close()
}
