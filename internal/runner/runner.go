package runner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/maxvaer/dirfuzz/internal/config"
	"github.com/maxvaer/dirfuzz/internal/crawl"
	"github.com/maxvaer/dirfuzz/internal/filter"
	"github.com/maxvaer/dirfuzz/internal/hook"
	"github.com/maxvaer/dirfuzz/internal/netutil"
	"github.com/maxvaer/dirfuzz/internal/output"
	"github.com/maxvaer/dirfuzz/internal/resume"
	"github.com/maxvaer/dirfuzz/internal/scanner"
	"github.com/maxvaer/dirfuzz/internal/wordlist"
	"github.com/maxvaer/dirfuzz/pkg/version"
)

// Run executes the full scan pipeline. It supports multiple targets via
// -l (URL list file) and --cidr flags.
func Run(ctx context.Context, opts *config.Options) error {
	targets, err := resolveTargets(opts)
	if err != nil {
		return err
	}

	for idx, target := range targets {
		if len(targets) > 1 && !opts.Quiet {
			fmt.Fprintf(os.Stderr, "\n[*] Target %d/%d: %s\n", idx+1, len(targets), target)
		}
		opts.URL = target
		if err := runSingleTarget(ctx, opts); err != nil {
			if ctx.Err() != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "[!] Error scanning %s: %v\n", target, err)
		}
	}
	return nil
}

// resolveTargets builds the list of URLs to scan from -u, -l, and --cidr.
func resolveTargets(opts *config.Options) ([]string, error) {
	var targets []string

	if opts.URL != "" {
		targets = append(targets, opts.URL)
	}

	if opts.URLsFile != "" {
		f, err := os.Open(opts.URLsFile)
		if err != nil {
			return nil, fmt.Errorf("opening URLs file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
					line = "http://" + line
				}
				targets = append(targets, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("reading URLs file: %w", err)
		}
	}

	if opts.CIDRTargets != "" {
		scheme := "https"
		if opts.URL != "" && strings.HasPrefix(opts.URL, "http://") {
			scheme = "http"
		}
		cidrURLs, err := netutil.ExpandTargets(opts.CIDRTargets, opts.Ports, scheme)
		if err != nil {
			return nil, fmt.Errorf("expanding CIDR: %w", err)
		}
		targets = append(targets, cidrURLs...)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets specified (-u, -l, or --cidr)")
	}
	return targets, nil
}

func runSingleTarget(ctx context.Context, opts *config.Options) error {
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
	needBody := opts.MatchBody != "" || opts.ExcludeBody != "" || opts.Crawl
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
		var sf *filter.SmartFilter
		var sfErr error
		if opts.VHost {
			sf, sfErr = filter.NewSmartFilterVHost(ctx, req, opts.URL, opts.SmartFilterThreshold)
		} else {
			sf, sfErr = filter.NewSmartFilter(ctx, req, opts.URL, opts.SmartFilterThreshold)
		}
		if sfErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Smart filter disabled: %v\n", sfErr)
		} else {
			chain.Add(sf)
			if !opts.Quiet {
				fmt.Fprintf(os.Stderr, "[+] Smart filter ready\n")
			}
		}
	}

	// Body filters (added after smart filter so they run on remaining results).
	if opts.MatchBody != "" {
		chain.Add(filter.NewBodyMatchFilter(opts.MatchBody))
	}
	if opts.ExcludeBody != "" {
		chain.Add(filter.NewBodyExcludeFilter(opts.ExcludeBody))
	}

	// 5. Resume support.
	var resumeState *resume.State
	if opts.ResumeFile != "" {
		existing, err := resume.Load(opts.ResumeFile)
		if err != nil {
			return fmt.Errorf("loading resume file: %w", err)
		}
		if existing != nil && existing.URL == opts.URL {
			resumeState = existing
			before := len(paths)
			paths = resumeState.FilterRemaining(paths)
			if !opts.Quiet {
				fmt.Fprintf(os.Stderr, "[+] Resuming: skipping %d already completed paths\n", before-len(paths))
			}
		} else {
			resumeState = resume.New(opts.ResumeFile, opts.URL, len(paths))
		}

		// Save state on interrupt for resume.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			if resumeState != nil {
				_ = resumeState.Save()
				fmt.Fprintf(os.Stderr, "\n[*] Progress saved to %s — resume with --resume-file\n", opts.ResumeFile)
			}
		}()
	}

	if len(paths) == 0 {
		if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "[+] All paths already completed\n")
		}
		return nil
	}

	// 6. Create output writer.
	out, err := createWriter(opts)
	if err != nil {
		return fmt.Errorf("creating output writer: %w", err)
	}
	defer out.Close()

	if err := out.WriteHeader(); err != nil {
		return err
	}

	// 7. Print banner.
	if !opts.Quiet {
		printBanner(opts, len(paths))
	}

	// 8. Create throttler and hook runner.
	throttler := scanner.NewThrottler(opts.Delay, opts.AdaptiveThrottle, opts.Quiet)

	var hookRunner *hook.Runner
	if opts.OnResultCmd != "" {
		hookRunner = hook.NewRunner(opts.OnResultCmd, opts.Quiet)
	}

	workerCfg := scanner.WorkerConfig{
		Threads:   opts.Threads,
		Throttler: throttler,
		KeepBody:  needBody,
	}

	// 9. Build work items and run worker pool.
	methods := resolveMethods(opts)
	var items []scanner.WorkItem

	if opts.VHost {
		// VHost mode: fuzz Host header instead of paths.
		hostnames, err := wordlist.LoadSimple(opts.VHostWordlist)
		if err != nil {
			return fmt.Errorf("loading vhost wordlist: %w", err)
		}
		items = make([]scanner.WorkItem, 0, len(hostnames)*len(methods))
		for _, host := range hostnames {
			for _, m := range methods {
				items = append(items, scanner.WorkItem{Method: m, Path: "/", Host: host})
			}
		}
	} else {
		items = expandItems(paths, methods)
	}

	progress := output.NewProgress(len(items), opts.Quiet)
	progress.Start()
	startTime := time.Now()

	results := scanner.RunWorkerPool(ctx, req, items, workerCfg)

	var stats output.Stats
	stats.TotalRequests = len(items)

	var discoveredDirs []string
	var crawledPaths []string
	scannedSet := make(map[string]struct{}, len(items))
	for _, item := range items {
		scannedSet[item.Path] = struct{}{}
	}

	for result := range results {
		progress.Increment()

		if resumeState != nil {
			resumeState.MarkCompleted(result.Path)
		}

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

		// Extract links before clearing body.
		if opts.Crawl && result.Body != nil {
			newPaths := crawl.ExtractPaths(result.Body, opts.URL)
			for _, p := range newPaths {
				if _, already := scannedSet[p]; !already {
					crawledPaths = append(crawledPaths, p)
					scannedSet[p] = struct{}{}
				}
			}
		}

		// Clear body to free memory after filtering and crawling.
		result.Body = nil

		progress.ClearLine()
		if err := out.WriteResult(&result); err != nil {
			progress.Redraw()
			return err
		}
		progress.Redraw()

		// Run hook for non-filtered results.
		if hookRunner != nil {
			hookRunner.Run(&result)
		}

		// Collect directories for recursive scanning.
		if opts.Recursive && !opts.VHost && looksLikeDirectory(result) {
			discoveredDirs = append(discoveredDirs, result.Path)
		}
	}

	// 10. Periodic resume save.
	if resumeState != nil {
		_ = resumeState.Save()
	}

	// 11. Recursive scanning (breadth-first).
	if opts.Recursive && !opts.VHost && len(discoveredDirs) > 0 {
		err := runRecursive(ctx, opts, req, chain, out, progress, throttler, hookRunner, needBody, discoveredDirs, paths, methods, &stats, resumeState, 1)
		if err != nil {
			progress.Stop()
			return err
		}
	}

	// 12. Crawl passes.
	if opts.Crawl && len(crawledPaths) > 0 {
		err := runCrawlPasses(ctx, opts, req, chain, out, progress, throttler, hookRunner, needBody, crawledPaths, scannedSet, methods, &stats, resumeState, 1)
		if err != nil {
			progress.Stop()
			return err
		}
	}

	progress.Stop()

	// 13. Write footer.
	stats.Duration = time.Since(startTime)
	if stats.Duration.Seconds() > 0 {
		stats.RequestsPerSec = float64(stats.TotalRequests) / stats.Duration.Seconds()
	}

	// Clean up resume file on successful completion.
	if resumeState != nil {
		_ = resumeState.Remove()
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
	throttler *scanner.Throttler,
	hookRunner *hook.Runner,
	needBody bool,
	dirs []string,
	basePaths []string,
	methods []string,
	stats *output.Stats,
	resumeState *resume.State,
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

		// Per-directory smart filter recalibration.
		if opts.SmartFilter && opts.SmartFilterPerDir {
			dirURL := opts.URL + "/" + strings.TrimLeft(dir, "/")
			sf, err := filter.NewSmartFilter(ctx, req, dirURL, opts.SmartFilterThreshold)
			if err == nil {
				chain.Add(sf)
				if !opts.Quiet {
					fmt.Fprintf(os.Stderr, "[+] Smart filter recalibrated for /%s\n", dir)
				}
			}
		}

		workerCfg := scanner.WorkerConfig{
			Threads:   opts.Threads,
			Throttler: throttler,
			KeepBody:  needBody,
		}

		newItems := expandItems(newPaths, methods)
		results := scanner.RunWorkerPool(ctx, req, newItems, workerCfg)
		stats.TotalRequests += len(newItems)

		for result := range results {
			progress.Increment()

			if resumeState != nil {
				resumeState.MarkCompleted(result.Path)
			}

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

			result.Body = nil

			progress.ClearLine()
			if err := out.WriteResult(&result); err != nil {
				progress.Redraw()
				return err
			}
			progress.Redraw()

			if hookRunner != nil {
				hookRunner.Run(&result)
			}

			if looksLikeDirectory(result) {
				nextDirs = append(nextDirs, result.Path)
			}
		}
	}

	if resumeState != nil {
		_ = resumeState.Save()
	}

	if len(nextDirs) > 0 {
		return runRecursive(ctx, opts, req, chain, out, progress, throttler, hookRunner, needBody, nextDirs, basePaths, methods, stats, resumeState, depth+1)
	}

	return nil
}

func looksLikeDirectory(result scanner.ScanResult) bool {
	if strings.HasSuffix(result.Path, "/") {
		return true
	}
	if result.StatusCode >= 300 && result.StatusCode < 400 {
		if strings.HasSuffix(result.RedirectURL, result.Path+"/") ||
			strings.HasSuffix(result.RedirectURL, "/") {
			return true
		}
	}
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

func resolveMethods(opts *config.Options) []string {
	if len(opts.Methods) > 0 {
		methods := make([]string, len(opts.Methods))
		for i, m := range opts.Methods {
			methods[i] = strings.ToUpper(m)
		}
		return methods
	}
	return []string{"GET"}
}

func expandItems(paths, methods []string) []scanner.WorkItem {
	items := make([]scanner.WorkItem, 0, len(paths)*len(methods))
	for _, p := range paths {
		for _, m := range methods {
			items = append(items, scanner.WorkItem{Method: m, Path: p})
		}
	}
	return items
}

func runCrawlPasses(
	ctx context.Context,
	opts *config.Options,
	req *scanner.Requester,
	chain *filter.Chain,
	out output.Writer,
	progress *output.Progress,
	throttler *scanner.Throttler,
	hookRunner *hook.Runner,
	needBody bool,
	newPaths []string,
	scannedSet map[string]struct{},
	methods []string,
	stats *output.Stats,
	resumeState *resume.State,
	depth int,
) error {
	if depth > opts.CrawlDepth || len(newPaths) == 0 {
		return nil
	}

	items := expandItems(newPaths, methods)
	progress.AddTotal(len(items))
	stats.TotalRequests += len(items)

	if !opts.Quiet {
		progress.ClearLine()
		fmt.Fprintf(os.Stderr, "[*] Crawl pass %d/%d: %d new paths discovered\n",
			depth, opts.CrawlDepth, len(newPaths))
		progress.Redraw()
	}

	workerCfg := scanner.WorkerConfig{
		Threads:   opts.Threads,
		Throttler: throttler,
		KeepBody:  needBody,
	}

	results := scanner.RunWorkerPool(ctx, req, items, workerCfg)

	var nextPaths []string

	for result := range results {
		progress.Increment()

		if resumeState != nil {
			resumeState.MarkCompleted(result.Path)
		}
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

		// Extract links before clearing body.
		if result.Body != nil {
			discovered := crawl.ExtractPaths(result.Body, opts.URL)
			for _, p := range discovered {
				if _, already := scannedSet[p]; !already {
					nextPaths = append(nextPaths, p)
					scannedSet[p] = struct{}{}
				}
			}
		}
		result.Body = nil

		progress.ClearLine()
		if err := out.WriteResult(&result); err != nil {
			progress.Redraw()
			return err
		}
		progress.Redraw()

		if hookRunner != nil {
			hookRunner.Run(&result)
		}
	}

	if len(nextPaths) > 0 {
		return runCrawlPasses(ctx, opts, req, chain, out, progress, throttler, hookRunner, needBody, nextPaths, scannedSet, methods, stats, resumeState, depth+1)
	}

	return nil
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
	if len(opts.Methods) > 0 {
		fmt.Fprintf(os.Stderr, "  %sMethods:%s     %s%s%s\n", d, rs, w, strings.Join(opts.Methods, ", "), rs)
	}
	if opts.VHost {
		fmt.Fprintf(os.Stderr, "  %sMode:%s        %sVirtual Host Fuzzing%s\n", d, rs, y, rs)
	}
	fmt.Fprintf(os.Stderr, "  %sSmart filter:%s %s\n", d, rs, smartLabel)
	fmt.Fprintf(os.Stderr, "%s  ──────────────────────────────────────%s\n\n", d, rs)
}
