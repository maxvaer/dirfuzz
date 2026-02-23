package scanner

import "time"

// ScanResult holds the outcome of a single path probe.
type ScanResult struct {
	Path          string
	URL           string
	StatusCode    int
	ContentLength int64
	BodyHash      [16]byte // MD5
	WordCount     int
	LineCount     int
	RedirectURL   string
	Duration      time.Duration
	Error         error
	Filtered      bool
	FilterReason  string
}
