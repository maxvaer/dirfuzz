package runner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/maxvaer/dirfuzz/internal/config"
	"github.com/maxvaer/dirfuzz/internal/filter"
	"github.com/maxvaer/dirfuzz/internal/output"
	"github.com/maxvaer/dirfuzz/internal/scanner"
	"github.com/maxvaer/dirfuzz/internal/wordlist"
	"github.com/maxvaer/dirfuzz/pkg/version"
)

// Run executes the full scan pipeline: load wordlist, calibrate smart filter,
// scan with the worker pool, filter results, and write output.
func Run(ctx context.Context, opts *config.Options) error {
	// 1. Load wordlist.
	paths, err := wordlist.Load(opts.WordlistPath, opts.Extensions, opts.ForceExtensions)
	if err != nil {
		return fmt.Errorf("loading wordlist: %w", err)
	}

	// 2. Create HTTP requester.
	req, err := scanner.NewRequester(opts)
	if err != nil {
		return fmt.Errorf("creating requester: %w", err)
	}

	// 3. Build filter chain.
	chain := filter.NewChain()
	if len(opts.IncludeStatus) > 0 || len(opts.ExcludeStatus) > 0 {
		chain.Add(filter.NewStatusFilter(opts.IncludeStatus, opts.ExcludeStatus))
	}
	if len(opts.ExcludeSize) > 0 {
		chain.Add(filter.NewSizeFilter(opts.ExcludeSize))
	}

	// 4. Smart filter calibration.
	if opts.SmartFilter {
		if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "[*] Calibrating smart filter against %s ...\n", opts.URL)
		}
		sf, err := filter.NewSmartFilter(ctx, req, opts.URL, opts.SmartFilterThreshold)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Smart filter disabled: %v\n", err)
		} else {
			chain.Add(sf)
			if !opts.Quiet {
				fmt.Fprintf(os.Stderr, "[+] Smart filter ready\n")
			}
		}
	}

	// 5. Create output writer.
	out, err := createWriter(opts)
	if err != nil {
		return fmt.Errorf("creating output writer: %w", err)
	}
	defer out.Close()

	if err := out.WriteHeader(); err != nil {
		return err
	}

	// 6. Print banner.
	if !opts.Quiet {
		printBanner(opts, len(paths))
	}

	// 7. Run worker pool.
	progress := output.NewProgress(len(paths), opts.Quiet)
	progress.Start()
	startTime := time.Now()

	results := scanner.RunWorkerPool(ctx, req, paths, opts.Threads, opts.Delay)

	var stats output.Stats
	stats.TotalRequests = len(paths)

	// 8. Recursive scanning state.
	var discoveredDirs []string

	for result := range results {
		progress.Increment()

		if result.Error != nil {
			stats.ErrorCount++
			progress.IncrementErrors()
			continue
		}

		// Apply filter chain.
		filtered, reason := chain.Apply(&result)
		if filtered {
			result.Filtered = true
			result.FilterReason = reason
			stats.FilteredCount++
			progress.IncrementFiltered()
			continue
		}

		if err := out.WriteResult(&result); err != nil {
			return err
		}

		// Collect directories for recursive scanning.
		if opts.Recursive && looksLikeDirectory(result) {
			discoveredDirs = append(discoveredDirs, result.Path)
		}
	}

	progress.Stop()

	// 9. Recursive scanning (breadth-first).
	if opts.Recursive && len(discoveredDirs) > 0 {
		err := runRecursive(ctx, opts, req, chain, out, progress, discoveredDirs, paths, &stats, 1)
		if err != nil {
			return err
		}
	}

	// 10. Write footer.
	stats.Duration = time.Since(startTime)
	if stats.Duration.Seconds() > 0 {
		stats.RequestsPerSec = float64(stats.TotalRequests) / stats.Duration.Seconds()
	}
	return out.WriteFooter(stats)
}

func runRecursive(
	ctx context.Context,
	opts *config.Options,
	req *scanner.Requester,
	chain *filter.Chain,
	out output.Writer,
	progress *output.Progress,
	dirs []string,
	basePaths []string,
	stats *output.Stats,
	depth int,
) error {
	if depth > opts.MaxDepth {
		return nil
	}

	var nextDirs []string

	for _, dir := range dirs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Build new paths by prepending the discovered directory.
		newPaths := make([]string, len(basePaths))
		for i, p := range basePaths {
			newPaths[i] = strings.TrimRight(dir, "/") + "/" + strings.TrimLeft(p, "/")
		}

		if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "\n[*] Recursing into /%s (depth %d/%d, %d paths)\n",
				dir, depth, opts.MaxDepth, len(newPaths))
		}

		results := scanner.RunWorkerPool(ctx, req, newPaths, opts.Threads, opts.Delay)
		stats.TotalRequests += len(newPaths)

		for result := range results {
			progress.Increment()

			if result.Error != nil {
				stats.ErrorCount++
				progress.IncrementErrors()
				continue
			}

			filtered, reason := chain.Apply(&result)
			if filtered {
				result.Filtered = true
				result.FilterReason = reason
				stats.FilteredCount++
				progress.IncrementFiltered()
				continue
			}

			if err := out.WriteResult(&result); err != nil {
				return err
			}

			if looksLikeDirectory(result) {
				nextDirs = append(nextDirs, result.Path)
			}
		}
	}

	if len(nextDirs) > 0 {
		return runRecursive(ctx, opts, req, chain, out, progress, nextDirs, basePaths, stats, depth+1)
	}

	return nil
}

func looksLikeDirectory(result scanner.ScanResult) bool {
	// Directories typically end with / or return 301/302 redirects to a / path.
	if strings.HasSuffix(result.Path, "/") {
		return true
	}
	if result.StatusCode >= 300 && result.StatusCode < 400 {
		if strings.HasSuffix(result.RedirectURL, result.Path+"/") ||
			strings.HasSuffix(result.RedirectURL, "/") {
			return true
		}
	}
	// A 200 without an extension is likely a directory.
	if result.StatusCode >= 200 && result.StatusCode < 300 {
		lastSegment := result.Path
		if idx := strings.LastIndex(result.Path, "/"); idx >= 0 {
			lastSegment = result.Path[idx+1:]
		}
		return !strings.Contains(lastSegment, ".")
	}
	return false
}

func createWriter(opts *config.Options) (output.Writer, error) {
	switch opts.OutputFormat {
	case "json":
		return output.NewJSONWriter(opts.OutputFile)
	case "csv":
		return output.NewCSVWriter(opts.OutputFile)
	default:
		return output.NewTextWriter(opts.OutputFile, opts.NoColor, opts.Quiet)
	}
}

func printBanner(opts *config.Options, pathCount int) {
	const (
		cyan   = "\033[36m"
		white  = "\033[97m"
		dim    = "\033[2m"
		red    = "\033[31m"
		green  = "\033[32m"
		yellow = "\033[33m"
		reset  = "\033[0m"
	)

	c, w, d, r, g, y, rs := cyan, white, dim, red, green, yellow, reset
	if opts.NoColor {
		c, w, d, r, g, y, rs = "", "", "", "", "", "", ""
	}

	fmt.Fprintf(os.Stderr, `
%s     ___  _      ______                %s
%s    / _ \(_)____/ ____/_  __________   %s
%s   / // / / __/ /_/ / / / /_  /_  /   %s
%s  / ___/ / / / __/ / /_/ / / /_/ /_   %s
%s /_/  /_/_/ /_/   \__,_/ /___/___/   %s %sv%s%s
%s                                       %s
%s    Web Path Brute-Forcer              %s
%s    with Smart 404 Detection           %s
`,
		c, rs,
		c, rs,
		c, rs,
		c, rs,
		c, rs, d, version.Version, rs,
		c, rs,
		w, rs,
		d, rs,
	)

	smartLabel := fmt.Sprintf("%sON%s", g, rs)
	if !opts.SmartFilter {
		smartLabel = fmt.Sprintf("%sOFF%s", r, rs)
	}
	if opts.NoColor {
		smartLabel = "ON"
		if !opts.SmartFilter {
			smartLabel = "OFF"
		}
	}

	fmt.Fprintf(os.Stderr, "%s  ──────────────────────────────────────%s\n", d, rs)
	fmt.Fprintf(os.Stderr, "  %sTarget:%s       %s%s%s\n", d, rs, w, opts.URL, rs)
	fmt.Fprintf(os.Stderr, "  %sThreads:%s      %s%d%s\n", d, rs, y, opts.Threads, rs)
	fmt.Fprintf(os.Stderr, "  %sWordlist:%s     %s%d paths%s\n", d, rs, w, pathCount, rs)
	if len(opts.Extensions) > 0 {
		fmt.Fprintf(os.Stderr, "  %sExtensions:%s   %s%s%s\n", d, rs, w, strings.Join(opts.Extensions, ", "), rs)
	}
	fmt.Fprintf(os.Stderr, "  %sSmart filter:%s %s\n", d, rs, smartLabel)
	fmt.Fprintf(os.Stderr, "%s  ──────────────────────────────────────%s\n\n", d, rs)
}
