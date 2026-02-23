package output

import (
	"time"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

// Stats holds aggregate scan statistics.
type Stats struct {
	TotalRequests  int
	FilteredCount  int
	ErrorCount     int
	Duration       time.Duration
	RequestsPerSec float64
}

// Writer is implemented by each output format.
type Writer interface {
	WriteHeader() error
	WriteResult(result *scanner.ScanResult) error
	WriteFooter(stats Stats) error
	Close() error
}
