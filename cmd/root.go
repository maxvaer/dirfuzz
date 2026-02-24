package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maxvaer/dirfuzz/internal/config"
	"github.com/maxvaer/dirfuzz/internal/reqparse"
	"github.com/maxvaer/dirfuzz/internal/runner"
	"github.com/maxvaer/dirfuzz/internal/updater"
	"github.com/maxvaer/dirfuzz/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	opts       config.Options
	updateFlag bool
)

type flagGroup struct {
	title string
	flags []string
}

var helpGroups = []flagGroup{
	{"TARGET", []string{"url", "urls-file", "request-file", "wordlist", "extensions", "force-extensions", "cidr", "ports"}},
	{"DISCOVERY", []string{"recursive", "max-depth", "crawl", "crawl-depth", "vhost", "vhost-wordlist"}},
	{"MATCHERS", []string{"include-status", "match-body"}},
	{"FILTERS", []string{"exclude-status", "exclude-size", "exclude-body", "smart-filter", "smart-filter-threshold", "smart-filter-per-dir"}},
	{"RATE-LIMIT", []string{"threads", "timeout", "delay", "adaptive-throttle", "max-eta"}},
	{"HTTP", []string{"header", "user-agent", "proxy", "follow-redirects", "methods"}},
	{"OUTPUT", []string{"output", "format", "quiet", "no-color", "sort", "tree", "on-result"}},
	{"CONFIGURATION", []string{"resume-file"}},
	{"UPDATE", []string{"update"}},
}

var rootCmd = &cobra.Command{
	Use:     "dirfuzz -u <url> [flags]",
	Short:   "Fast web path brute-forcer with smart 404 detection",
	Version: version.Version,
	Long: `dirfuzz is a web path/file brute-forcing tool designed for penetration
testing and bug bounty hunting. It features automatic detection and
filtering of custom 404 pages (soft-404s) that return HTTP 200.`,
	Example: `  dirfuzz -u https://example.com
  dirfuzz -u https://example.com -e php,html -t 50
  dirfuzz -u https://example.com -w custom.txt --smart-filter=false
  dirfuzz -u https://example.com -x 403,500 -o results.json --format json
  dirfuzz -r burp.req -e php,html
  dirfuzz -l urls.txt -w wordlist.txt
  dirfuzz --cidr 192.168.1.0/24 --ports 80,443,8080
  dirfuzz -u https://example.com --match-body "Welcome"
  dirfuzz -u https://example.com --resume-file scan.state
  dirfuzz -u https://example.com --on-result "notify-send {url}"`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Self-update mode: skip all validation.
		if updateFlag {
			return nil
		}
		// Parse raw HTTP request file (e.g. Burp export) if provided.
		if opts.RequestFile != "" {
			parsed, err := reqparse.ParseFile(opts.RequestFile)
			if err != nil {
				return fmt.Errorf("parsing request file: %w", err)
			}
			// Use parsed URL if -u was not explicitly set.
			if !cmd.Flags().Changed("url") {
				opts.URL = parsed.URL
			}
			// Merge parsed headers (explicit -H flags take precedence).
			if opts.Headers == nil {
				opts.Headers = make(map[string]string)
			}
			for key, val := range parsed.Headers {
				k := strings.ToLower(key)
				// Skip hop-by-hop and encoding headers that don't make sense for fuzzing.
				if k == "host" || k == "content-length" || k == "accept-encoding" {
					continue
				}
				// Only set if not already overridden by -H flag.
				if _, exists := opts.Headers[key]; !exists {
					opts.Headers[key] = val
				}
			}
			// Use parsed User-Agent if --user-agent was not explicitly set.
			if !cmd.Flags().Changed("user-agent") {
				if ua, ok := parsed.Headers["User-Agent"]; ok {
					opts.UserAgent = ua
				}
			}
			if !opts.Quiet {
				fmt.Fprintf(os.Stderr, "[+] Loaded request from %s -> %s\n", opts.RequestFile, opts.URL)
			}
		}
		if opts.URL == "" && opts.URLsFile == "" && opts.CIDRTargets == "" {
			_ = cmd.Help()
			fmt.Fprintln(os.Stderr)
			return fmt.Errorf("target required: use -u, -l, --cidr, or --request-file")
		}
		if opts.URL != "" && !strings.HasPrefix(opts.URL, "http://") && !strings.HasPrefix(opts.URL, "https://") {
			opts.URL = "http://" + opts.URL
		}
		if len(opts.IncludeStatus) > 0 && len(opts.ExcludeStatus) > 0 {
			return fmt.Errorf("--include-status and --exclude-status are mutually exclusive")
		}
		if opts.VHost {
			if opts.Recursive {
				return fmt.Errorf("--vhost and --recursive are mutually exclusive")
			}
		}
		if opts.SortBy != "" && opts.SortBy != "status" && opts.SortBy != "path" && opts.SortBy != "size" {
			return fmt.Errorf("--sort must be one of: status, path, size")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateFlag {
			return updater.Update()
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return runner.Run(ctx, &opts)
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	f := rootCmd.Flags()

	// Target
	f.StringVarP(&opts.URL, "url", "u", "", "Target URL")
	f.StringVarP(&opts.URLsFile, "urls-file", "l", "", "File with one URL per line")
	f.StringVarP(&opts.WordlistPath, "wordlist", "w", "", "Custom wordlist path (default: built-in)")
	f.StringSliceVarP(&opts.Extensions, "extensions", "e", nil, "File extensions to test (e.g. php,html,js)")
	f.BoolVarP(&opts.ForceExtensions, "force-extensions", "f", false, "Append extensions to every wordlist entry")

	// Performance
	f.IntVarP(&opts.Threads, "threads", "t", 25, "Number of concurrent threads")
	f.DurationVar(&opts.Timeout, "timeout", 10*time.Second, "HTTP request timeout")
	f.DurationVar(&opts.Delay, "delay", 0, "Delay between requests per thread")
	f.BoolVar(&opts.AdaptiveThrottle, "adaptive-throttle", false, "Auto back-off on 429/rate limits")

	// Smart filter
	f.BoolVar(&opts.SmartFilter, "smart-filter", true, "Enable smart 404 detection")
	f.IntVar(&opts.SmartFilterThreshold, "smart-filter-threshold", 50, "Size tolerance in bytes for smart filter")
	f.BoolVar(&opts.SmartFilterPerDir, "smart-filter-per-dir", false, "Re-calibrate smart filter per subdirectory")

	// Filtering
	f.VarP(&intSliceValue{target: &opts.IncludeStatus}, "include-status", "i", "Only show these status codes (comma-separated)")
	f.VarP(&intSliceValue{target: &opts.ExcludeStatus}, "exclude-status", "x", "Hide these status codes (comma-separated)")
	f.Var(&intSliceValue{target: &opts.ExcludeSize}, "exclude-size", "Hide responses of these sizes (comma-separated)")

	// Body filtering
	f.StringVar(&opts.MatchBody, "match-body", "", "Only show responses containing this string")
	f.StringVar(&opts.ExcludeBody, "exclude-body", "", "Hide responses containing this string")

	// Output
	f.StringVarP(&opts.OutputFile, "output", "o", "", "Output file path")
	f.StringVar(&opts.OutputFormat, "format", "text", "Output format: text, json, csv")
	f.BoolVarP(&opts.Quiet, "quiet", "q", false, "Minimal output")
	f.BoolVar(&opts.NoColor, "no-color", false, "Disable colored output")

	// Recursion
	f.BoolVar(&opts.Recursive, "recursive", false, "Enable recursive scanning")
	f.IntVarP(&opts.MaxDepth, "max-depth", "R", 3, "Maximum recursion depth")

	// Resume
	f.StringVar(&opts.ResumeFile, "resume-file", "", "File to save/load scan progress for resume")

	// Network
	f.StringVar(&opts.CIDRTargets, "cidr", "", "CIDR range to scan (e.g. 192.168.1.0/24)")
	f.StringVar(&opts.Ports, "ports", "", "Ports for CIDR targets (comma-separated, e.g. 80,443,8080)")

	// HTTP
	f.StringVarP(&opts.RequestFile, "request-file", "r", "", "Raw HTTP request file (e.g. Burp Suite export)")
	f.StringSliceVarP(new([]string), "header", "H", nil, "Custom headers (Key: Value)")
	f.StringVar(&opts.UserAgent, "user-agent", "", "Custom User-Agent string")
	f.StringVar(&opts.Proxy, "proxy", "", "HTTP/SOCKS proxy URL")
	f.BoolVar(&opts.FollowRedirects, "follow-redirects", false, "Follow HTTP redirects")

	// Method fuzzing
	f.StringSliceVar(&opts.Methods, "methods", nil, "HTTP methods to try per path (e.g. GET,POST,PUT)")

	// Virtual host fuzzing
	f.BoolVar(&opts.VHost, "vhost", false, "Enable virtual host fuzzing mode")
	f.StringVar(&opts.VHostWordlist, "vhost-wordlist", "", "Wordlist of hostnames for vhost fuzzing (default: built-in top-5000)")

	// Crawl
	f.BoolVar(&opts.Crawl, "crawl", true, "Crawl discovered pages for additional paths")
	f.IntVar(&opts.CrawlDepth, "crawl-depth", 2, "Maximum crawl depth (link-following hops)")

	// Hooks
	f.StringVar(&opts.OnResultCmd, "on-result", "", "Shell command to run for each result (receives JSON on stdin)")

	// Sort
	f.StringVar(&opts.SortBy, "sort", "", "Sort results: status, path, size (buffers until scan completes)")

	// Tree
	f.BoolVar(&opts.Tree, "tree", false, "Print directory tree summary after scan")

	// Skip
	f.DurationVar(&opts.MaxETA, "max-eta", time.Hour, "Skip target if ETA exceeds this duration (0 to disable)")

	// Update
	f.BoolVar(&updateFlag, "update", false, "Update dirfuzz to the latest version")

	// Custom help: categorized flags like httpx.
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		w := os.Stderr
		fmt.Fprint(w, helpBanner(cmd.Version))
		fmt.Fprintf(w, "%s\n\nUsage:\n  %s\n", cmd.Long, cmd.UseLine())
		fmt.Fprintf(w, "\nExamples:\n%s\n", cmd.Example)
		fmt.Fprintf(w, "\nFlags:\n")
		for _, g := range helpGroups {
			fmt.Fprintf(w, "\n%s:\n", g.title)
			for _, name := range g.flags {
				if f := cmd.Flags().Lookup(name); f != nil {
					fmt.Fprintln(w, formatFlag(f))
				}
			}
		}
		fmt.Fprintln(w)
	})

	// Parse headers from string slice into map in PreRun.
	rootCmd.PreRunE = chainPreRun(rootCmd.PreRunE, func(cmd *cobra.Command, args []string) error {
		headers, _ := f.GetStringSlice("header")
		if len(headers) > 0 {
			opts.Headers = make(map[string]string, len(headers))
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid header format %q, expected 'Key: Value'", h)
				}
				opts.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		return nil
	})
}

// Execute runs the root command.
func Execute() {
	// Rewrite -up to --update before cobra parses args,
	// since pflag would interpret -up as -u "p".
	for i, arg := range os.Args {
		if arg == "-up" {
			os.Args[i] = "--update"
		}
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// chainPreRun combines two PreRunE functions.
func chainPreRun(first, second func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if first != nil {
			if err := first(cmd, args); err != nil {
				return err
			}
		}
		return second(cmd, args)
	}
}

// intSliceValue implements pflag.Value for comma-separated int slices.
type intSliceValue struct {
	target *[]int
}

func (v *intSliceValue) String() string {
	if v.target == nil || len(*v.target) == 0 {
		return ""
	}
	parts := make([]string, len(*v.target))
	for i, val := range *v.target {
		parts[i] = strconv.Itoa(val)
	}
	return strings.Join(parts, ",")
}

func (v *intSliceValue) Set(s string) error {
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("invalid status code %q: %w", p, err)
		}
		*v.target = append(*v.target, n)
	}
	return nil
}

func (v *intSliceValue) Type() string { return "ints" }

func formatFlag(f *pflag.Flag) string {
	var left string
	if f.Shorthand != "" {
		left = fmt.Sprintf("-%s, --%s", f.Shorthand, f.Name)
	} else {
		left = fmt.Sprintf("    --%s", f.Name)
	}

	typ := f.Value.Type()
	if typ != "bool" {
		left += " " + typ
	}

	// Pad to fixed column width for aligned descriptions.
	const col = 36
	for len(left) < col {
		left += " "
	}

	right := f.Usage
	// Show default for non-zero values.
	def := f.DefValue
	if def != "" && def != "false" && def != "0" && def != "0s" && def != "[]" {
		right += fmt.Sprintf(" (default %s)", def)
	}

	return "   " + left + right
}

func helpBanner(ver string) string {
	if ver != "dev" && ver != "" && !strings.HasPrefix(ver, "v") {
		ver = "v" + ver
	}
	return fmt.Sprintf(`
     ___  _      ______
    / _ \(_)____/ ____/_  __________
   / // / / __/ /_/ / / / /_  /_  /
  / ___/ / / / __/ / /_/ / / /_/ /_
 /_/  /_/_/ /_/   \__,_/ /___/___/   %s

`, ver)
}
