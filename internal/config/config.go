package config

import "time"

// Options holds all configuration for a dirfuzz scan.
type Options struct {
	// Target
	URL             string
	URLsFile        string   // -l: file with one URL per line
	WordlistPath    string   // empty = use embedded
	Extensions      []string
	ForceExtensions bool

	// Performance
	Threads          int
	Timeout          time.Duration
	Delay            time.Duration
	AdaptiveThrottle bool // auto back-off on 429/rate limits

	// Smart filter
	SmartFilter          bool
	SmartFilterThreshold int  // bytes tolerance
	SmartFilterPerDir    bool // re-calibrate per subdirectory

	// Status filtering
	IncludeStatus []int
	ExcludeStatus []int
	ExcludeSize   []int

	// Body filtering
	MatchBody   string // only show responses containing this string
	ExcludeBody string // hide responses containing this string

	// Output
	OutputFile   string
	OutputFormat string // "text", "json", "csv"
	Quiet        bool
	NoColor      bool

	// Recursion
	Recursive bool
	MaxDepth  int

	// Resume
	ResumeFile string // path to save/load scan state

	// HTTP
	RequestFile     string // path to raw HTTP request file (e.g. Burp export)
	Headers         map[string]string
	UserAgent       string
	Proxy           string
	FollowRedirects bool

	// Network
	CIDRTargets string // CIDR range (e.g. 192.168.1.0/24)
	Ports       string // comma-separated ports to scan

	// Method fuzzing
	Methods []string // HTTP methods to try per path (default: GET only)

	// Virtual host fuzzing
	VHost         bool   // enable vhost fuzzing mode
	VHostWordlist string // path to hostname wordlist

	// Crawl
	Crawl      bool // crawl discovered pages for additional paths
	CrawlDepth int  // maximum link-following hops

	// Hooks
	OnResultCmd string // command to run for each result (receives JSON on stdin)
}
