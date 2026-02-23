package config

import "time"

// Options holds all configuration for a dirfuzz scan.
type Options struct {
	// Target
	URL             string
	WordlistPath    string // empty = use embedded
	Extensions      []string
	ForceExtensions bool

	// Performance
	Threads int
	Timeout time.Duration
	Delay   time.Duration

	// Smart filter
	SmartFilter          bool
	SmartFilterThreshold int // bytes tolerance

	// Status filtering
	IncludeStatus []int
	ExcludeStatus []int
	ExcludeSize   []int

	// Output
	OutputFile   string
	OutputFormat string // "text", "json", "csv"
	Quiet        bool
	NoColor      bool

	// Recursion
	Recursive bool
	MaxDepth  int

	// HTTP
	RequestFile     string // path to raw HTTP request file (e.g. Burp export)
	Headers         map[string]string
	UserAgent       string
	Proxy           string
	FollowRedirects bool
}
