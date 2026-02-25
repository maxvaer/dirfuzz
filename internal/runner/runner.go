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
		if len(targets) > 1 && !opts.Silent {
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

	// 3. Resume support (before banner so path count is accurate).
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
			if !opts.Silent {
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
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[+] All paths already completed\n")
		}
		return nil
	}

	// 4. Print banner (before any other output).
	if !opts.Silent {
		printBanner(opts, len(paths))
	}

	// 5. Build filter chain.
	needBody := opts.MatchBody != "" || opts.ExcludeBody != "" || opts.Crawl
	chain := filter.NewChain()
	if len(opts.IncludeStatus) > 0 || len(opts.ExcludeStatus) > 0 {
		chain.Add(filter.NewStatusFilter(opts.IncludeStatus, opts.ExcludeStatus))
	}
	if len(opts.ExcludeSize) > 0 {
		chain.Add(filter.NewSizeFilter(opts.ExcludeSize))
	}

	// 6. Smart filter calibration.
	if opts.SmartFilter {
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[*] Calibrating smart filter against %s ...\n", opts.URL)
		}
		var sf *filter.SmartFilter
		var sfErr error
		if opts.VHost {
			sf, sfErr = filter.NewSmartFilterVHost(ctx, req, opts.URL, opts.SmartFilterThreshold)
		} else {
			sf, sfErr = filter.NewSmartFilter(ctx, req, "", opts.SmartFilterThreshold)
		}
		if sfErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Smart filter disabled: %v\n", sfErr)
		} else {
			chain.Add(sf)
			if !opts.Silent {
				fmt.Fprintf(os.Stderr, "[+] Smart filter ready\n")
			}
		}
	}
	// Duplicate filter catches catch-all routes that serve the same
	// page for every subpath (e.g. /app/login/*) — these evade smart
	// filter calibration because the probes hit a different route.
	if opts.DuplicateThreshold > 0 {
		chain.Add(filter.NewDuplicateFilter(opts.DuplicateThreshold))
	}

	// Body filters (added after smart filter so they run on remaining results).
	if opts.MatchBody != "" {
		chain.Add(filter.NewBodyMatchFilter(opts.MatchBody))
	}
	if opts.ExcludeBody != "" {
		chain.Add(filter.NewBodyExcludeFilter(opts.ExcludeBody))
	}

	// 7. Create output writer.
	out, err := createWriter(opts)
	if err != nil {
		return fmt.Errorf("creating output writer: %w", err)
	}
	defer out.Close()

	if err := out.WriteHeader(); err != nil {
		return err
	}

	// 8. Create throttler and hook runner.
	throttler := scanner.NewThrottler(opts.Delay, opts.AdaptiveThrottle, opts.Silent)

	var hookRunner *hook.Runner
	if opts.OnResultCmd != "" {
		hookRunner = hook.NewRunner(opts.OnResultCmd, opts.Silent)
	}

	workerCfg := scanner.WorkerConfig{
		Threads:   opts.Threads,
		Throttler: throttler,
		KeepBody:  needBody,
	}

	// 8b. Set up interactive pause/resume.
	pauser, cleanupTerminal := startStdinToggle(opts.Silent)
	defer cleanupTerminal()
	if pauser != nil {
		workerCfg.Pauser = pauser
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

	progress := output.NewProgress(len(items), opts.Silent)
	if pauser != nil {
		progress.SetPauser(pauser)
	}
	progress.Start()
	startTime := time.Now()

	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	results := scanner.RunWorkerPool(workerCtx, req, items, workerCfg)

	var stats output.Stats
	stats.TotalRequests = len(items)

	var discoveredDirs []string
	var crawledPaths []string
	scannedSet := make(map[string]struct{}, len(items))
	for _, item := range items {
		scannedSet[item.Path] = struct{}{}
	}
	seenDirs := make(map[string]struct{})

	// ETA-based skip: check after a minimum number of requests for stable estimate.
	etaCheckAfter := int64(100)
	if n := int64(len(items)) / 20; n > etaCheckAfter {
		etaCheckAfter = n // 5% of total, whichever is larger
	}
	etaSkipped := false

	for result := range results {
		progress.Increment()

		// Check ETA threshold to skip slow targets.
		if opts.MaxETA > 0 && !etaSkipped {
			if completed := progress.Completed(); completed >= etaCheckAfter {
				if eta := progress.ETA(); eta > opts.MaxETA {
					if !opts.Silent {
						progress.ClearLine()
						fmt.Fprintf(os.Stderr, "[!] Skipping %s: ETA %s exceeds --max-eta %s\n",
							opts.URL, eta.Round(time.Second), opts.MaxETA)
						progress.Redraw()
					}
					workerCancel()
					etaSkipped = true
					break
				}
			}
		}

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

		progress.IncrementFound()

		// Extract links before clearing body.
		if opts.Crawl && result.Body != nil {
			newPaths := crawl.ExtractPaths(result.Body, opts.URL)
			for _, p := range newPaths {
				if _, already := scannedSet[p]; !already {
					crawledPaths = append(crawledPaths, p)
					scannedSet[p] = struct{}{}
				}
			}
			// Infer directories from crawled paths for recursive scanning and tree output.
			if (opts.Recursive || opts.Tree) && !opts.VHost {
				for _, p := range newPaths {
					for _, dir := range extractParentDirs(p, opts.MaxDepth) {
						key := normalizeDirKey(dir)
						if _, already := seenDirs[key]; !already {
							discoveredDirs = append(discoveredDirs, dir)
							seenDirs[key] = struct{}{}
						}
					}
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

		// Collect directories for recursive scanning and tree output.
		if (opts.Recursive || opts.Tree) && !opts.VHost && looksLikeDirectory(result) {
			dir := strings.TrimRight(result.Path, "/")
			key := normalizeDirKey(dir)
			if _, already := seenDirs[key]; !already {
				if isStaticAssetDir(dir) {
					if !opts.Silent {
						progress.ClearLine()
						fmt.Fprintf(os.Stderr, "[*] Skipping /%s/ (static asset directory)\n", dir)
						progress.Redraw()
					}
				} else {
					discoveredDirs = append(discoveredDirs, dir)
				}
				seenDirs[key] = struct{}{}
			}
		}
	}

	// If target was skipped due to ETA, drain remaining results and return.
	if etaSkipped {
		for range results {
			// drain channel
		}
		progress.Stop()
		stats.Duration = time.Since(startTime)
		return out.WriteFooter(stats)
	}

	// Stop main progress bar before recursive/crawl phases (they create their own).
	progress.Stop()

	// 10. Periodic resume save.
	if resumeState != nil {
		_ = resumeState.Save()
	}

	// 11. Recursive scanning (breadth-first).
	if opts.Recursive && !opts.VHost && len(discoveredDirs) > 0 {
		err := runRecursive(ctx, opts, req, chain, out, throttler, hookRunner, needBody, discoveredDirs, paths, methods, &stats, resumeState, pauser, 1)
		if err != nil {
			return err
		}
	}

	// 12. Crawl passes.
	var crawlDirs []string
	if opts.Crawl && len(crawledPaths) > 0 {
		var err error
		crawlDirs, err = runCrawlPasses(ctx, opts, req, chain, out, throttler, hookRunner, needBody, crawledPaths, scannedSet, methods, &stats, resumeState, pauser, 1)
		if err != nil {
			return err
		}
		// Recursively scan directories discovered during crawling.
		if opts.Recursive && !opts.VHost && len(crawlDirs) > 0 {
			err := runRecursive(ctx, opts, req, chain, out, throttler, hookRunner, needBody, crawlDirs, paths, methods, &stats, resumeState, pauser, 1)
			if err != nil {
				return err
			}
		}
	}

	// 13. Print directory tree if requested.
	if opts.Tree && !opts.Silent {
		allDirs := append(discoveredDirs, crawlDirs...)
		output.PrintTree(os.Stderr, allDirs)
	}

	// 14. Write footer.
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
	throttler *scanner.Throttler,
	hookRunner *hook.Runner,
	needBody bool,
	dirs []string,
	basePaths []string,
	methods []string,
	stats *output.Stats,
	resumeState *resume.State,
	pauser *scanner.Pauser,
	depth int,
) error {
	if depth > opts.MaxDepth {
		return nil
	}

	// Deduplicate incoming dirs (case-insensitive, ignore trailing slash).
	dirs = deduplicateDirs(dirs)

	// Find parent smart filter for directory probe check.
	var parentSF *filter.SmartFilter
	for _, f := range chain.Filters() {
		if sf, ok := f.(*filter.SmartFilter); ok {
			parentSF = sf
			break
		}
	}

	var nextDirs []string
	seenDirs := make(map[string]struct{})

	for _, dir := range dirs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Quick probe: if the directory page itself matches the parent
		// smart filter baseline (soft-404), skip recursing into it.
		if parentSF != nil {
			probeResp, err := req.Do(ctx, "GET", strings.TrimRight(dir, "/")+"/", "")
			if err == nil {
				probeResult := &scanner.ScanResult{
					StatusCode:    probeResp.StatusCode,
					ContentLength: probeResp.ContentLength,
					BodyHash:      probeResp.BodyHash,
					WordCount:     probeResp.WordCount,
					LineCount:     probeResp.LineCount,
				}
				if parentSF.ShouldFilter(probeResult) {
					if !opts.Silent {
						fmt.Fprintf(os.Stderr, "\n[*] Skipping /%s/ (directory page matches soft-404 baseline)\n",
							strings.TrimRight(dir, "/"))
					}
					continue
				}
			}
		}

		// Build new paths by prepending the discovered directory.
		newPaths := make([]string, len(basePaths))
		for i, p := range basePaths {
			newPaths[i] = strings.TrimRight(dir, "/") + "/" + strings.TrimLeft(p, "/")
		}

		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "\n[*] Recursing into /%s/ (depth %d/%d, %d paths)\n",
				strings.TrimRight(dir, "/"), depth, opts.MaxDepth, len(newPaths))
		}

		// Build per-directory filter chain: copy static filters, recalibrate smart + duplicate.
		dirChain := filter.NewChain()
		for _, f := range chain.Filters() {
			switch f.(type) {
			case *filter.SmartFilter, *filter.DuplicateFilter:
				// Skip — these are recreated per directory below.
			default:
				dirChain.Add(f)
			}
		}
		if opts.SmartFilter {
			sf, err := filter.NewSmartFilter(ctx, req, dir, opts.SmartFilterThreshold)
			if err == nil {
				dirChain.Add(sf)
				if !opts.Silent {
					fmt.Fprintf(os.Stderr, "[+] Smart filter recalibrated for /%s\n", dir)
				}
			}
		}
		if opts.DuplicateThreshold > 0 {
			dirChain.Add(filter.NewDuplicateFilter(opts.DuplicateThreshold))
		}

		workerCfg := scanner.WorkerConfig{
			Threads:   opts.Threads,
			Throttler: throttler,
			KeepBody:  needBody,
			Pauser:    pauser,
		}

		newItems := expandItems(newPaths, methods)

		// Create a fresh progress bar for this directory.
		progress := output.NewProgress(len(newItems), opts.Silent)
		if pauser != nil {
			progress.SetPauser(pauser)
		}
		progress.Start()

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

			filtered, reason := dirChain.Apply(&result)
			if filtered {
				result.Filtered = true
				result.FilterReason = reason
				stats.FilteredCount++
				progress.IncrementFiltered()
				continue
			}

			progress.IncrementFound()
			result.Body = nil

			progress.ClearLine()
			if err := out.WriteResult(&result); err != nil {
				progress.Redraw()
				progress.Stop()
				return err
			}
			progress.Redraw()

			if hookRunner != nil {
				hookRunner.Run(&result)
			}

			if looksLikeDirectory(result) {
				dir := strings.TrimRight(result.Path, "/")
				key := normalizeDirKey(dir)
				if _, already := seenDirs[key]; !already {
					if !isStaticAssetDir(dir) {
						nextDirs = append(nextDirs, dir)
					}
					seenDirs[key] = struct{}{}
				}
			}
		}

		progress.Stop()
	}

	if resumeState != nil {
		_ = resumeState.Save()
	}

	if len(nextDirs) > 0 {
		return runRecursive(ctx, opts, req, chain, out, throttler, hookRunner, needBody, nextDirs, basePaths, methods, stats, resumeState, pauser, depth+1)
	}

	return nil
}

// extractParentDirs returns intermediate directory segments of a path,
// limited to maxDepth levels. For example, "/js/asset/login.js" with
// maxDepth=3 returns ["js", "js/asset"].
func extractParentDirs(path string, maxDepth int) []string {
	path = strings.TrimLeft(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) <= 1 {
		return nil
	}
	// Exclude the last segment (the file itself).
	n := len(parts) - 1
	if n > maxDepth {
		n = maxDepth
	}
	dirs := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		dirs = append(dirs, strings.Join(parts[:i], "/"))
	}
	return dirs
}

// normalizeDirKey returns a canonical key for directory deduplication:
// trimmed of trailing slashes and lowercased so /Home, /home/, /Home/ all
// map to the same key.
func normalizeDirKey(dir string) string {
	return strings.ToLower(strings.TrimRight(dir, "/"))
}

// staticAssetDirs contains directory names that are typically static assets
// and not worth recursing into during directory fuzzing.
var staticAssetDirs = map[string]struct{}{
	"css": {}, "images": {}, "img": {}, "fonts": {},
	"assets": {}, "media": {}, ".hg": {},
}

// isStaticAssetDir returns true if the last segment of the directory path
// is a common static asset directory name that is not worth recursing into.
func isStaticAssetDir(dir string) bool {
	dir = strings.TrimRight(dir, "/")
	lastSeg := dir
	if idx := strings.LastIndex(dir, "/"); idx >= 0 {
		lastSeg = dir[idx+1:]
	}
	_, ok := staticAssetDirs[strings.ToLower(lastSeg)]
	return ok
}

// deduplicateDirs returns dirs with case-insensitive, slash-normalized
// duplicates removed, keeping the first occurrence.
func deduplicateDirs(dirs []string) []string {
	seen := make(map[string]struct{}, len(dirs))
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		key := normalizeDirKey(d)
		if _, already := seen[key]; !already {
			out = append(out, strings.TrimRight(d, "/"))
			seen[key] = struct{}{}
		}
	}
	return out
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
	var w output.Writer
	var err error
	switch opts.OutputFormat {
	case "json":
		w, err = output.NewJSONWriter(opts.OutputFile)
	case "csv":
		w, err = output.NewCSVWriter(opts.OutputFile)
	default:
		w, err = output.NewTextWriter(opts.OutputFile, opts.NoColor, opts.Silent)
	}
	if err != nil {
		return nil, err
	}
	if opts.SortBy != "" {
		w = output.NewSortedWriter(w, opts.SortBy)
	}
	return w, nil
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
	throttler *scanner.Throttler,
	hookRunner *hook.Runner,
	needBody bool,
	newPaths []string,
	scannedSet map[string]struct{},
	methods []string,
	stats *output.Stats,
	resumeState *resume.State,
	pauser *scanner.Pauser,
	depth int,
) ([]string, error) {
	if depth > opts.CrawlDepth || len(newPaths) == 0 {
		return nil, nil
	}

	items := expandItems(newPaths, methods)
	stats.TotalRequests += len(items)

	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "\n[*] Crawl pass %d/%d: %d new paths discovered\n",
			depth, opts.CrawlDepth, len(newPaths))
	}

	// Create a fresh progress bar for this crawl pass.
	progress := output.NewProgress(len(items), opts.Silent)
	if pauser != nil {
		progress.SetPauser(pauser)
	}
	progress.Start()

	workerCfg := scanner.WorkerConfig{
		Threads:   opts.Threads,
		Throttler: throttler,
		KeepBody:  needBody,
		Pauser:    pauser,
	}

	results := scanner.RunWorkerPool(ctx, req, items, workerCfg)

	var nextPaths []string
	var crawlDirs []string

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

		progress.IncrementFound()

		// Extract links before clearing body.
		if result.Body != nil {
			discovered := crawl.ExtractPaths(result.Body, opts.URL)
			for _, p := range discovered {
				if _, already := scannedSet[p]; !already {
					nextPaths = append(nextPaths, p)
					scannedSet[p] = struct{}{}
				}
			}
			// Infer directories from crawled paths for recursive scanning and tree output.
			if (opts.Recursive || opts.Tree) && !opts.VHost {
				for _, p := range discovered {
					for _, dir := range extractParentDirs(p, opts.MaxDepth) {
						if _, already := scannedSet[dir+"/"]; !already {
							crawlDirs = append(crawlDirs, dir)
							scannedSet[dir+"/"] = struct{}{}
						}
					}
				}
			}
		}
		result.Body = nil

		progress.ClearLine()
		if err := out.WriteResult(&result); err != nil {
			progress.Redraw()
			progress.Stop()
			return nil, err
		}
		progress.Redraw()

		if hookRunner != nil {
			hookRunner.Run(&result)
		}
	}

	progress.Stop()

	if len(nextPaths) > 0 {
		moreDirs, err := runCrawlPasses(ctx, opts, req, chain, out, throttler, hookRunner, needBody, nextPaths, scannedSet, methods, stats, resumeState, pauser, depth+1)
		if err != nil {
			return nil, err
		}
		crawlDirs = append(crawlDirs, moreDirs...)
	}

	return crawlDirs, nil
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

	ver := version.Version
	if ver != "dev" && !strings.HasPrefix(ver, "v") {
		ver = "v" + ver
	}

	fmt.Fprintf(os.Stderr, `
%s     _ _       __                      %s
%s  __| (_)_ __ / _|_   _ ________       %s
%s / _` + "`" + ` | | '__| |_| | | |_  /_  /       %s
%s| (_| | | |  |  _| |_| |/ / / /        %s
%s \__,_|_|_|  |_|  \__,_/___/___| %s %s%s%s
%s                                        %s
%s    Web Path Brute-Forcer               %s
%s    with Smart 404 Detection            %s
`,
		c, rs,
		c, rs,
		c, rs,
		c, rs,
		c, rs, d, ver, rs,
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
