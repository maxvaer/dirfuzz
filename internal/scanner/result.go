package scanner

import "time"

// ScanResult holds the outcome of a single path probe.
type ScanResult struct {
	Method        string // HTTP method used
	Host          string // Host header override (vhost fuzzing)
	Path          string
	URL           string
	StatusCode    int
	ContentLength int64
	Body          []byte   // raw body (only retained when body filters are active)
	BodyHash      [16]byte // MD5
	WordCount     int
	LineCount     int
	RedirectURL   string
	Duration      time.Duration
	Error         error
	Filtered      bool
	FilterReason  string
}
