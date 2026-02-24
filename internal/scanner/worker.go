package scanner

import (
	"context"
	"sync"
	"time"
)

// WorkerConfig holds options for the worker pool.
type WorkerConfig struct {
	Threads   int
	Throttler *Throttler
	KeepBody  bool    // retain response body in ScanResult for body filters
	Pauser    *Pauser // nil = no pause support
}

// RunWorkerPool fans out work items across workers and returns a channel
// of results. The channel is closed when all items have been processed.
func RunWorkerPool(
	ctx context.Context,
	req *Requester,
	items []WorkItem,
	cfg WorkerConfig,
) <-chan ScanResult {
	threads := cfg.Threads
	itemsCh := make(chan WorkItem, threads*2)
	resultsCh := make(chan ScanResult, threads*2)

	var wg sync.WaitGroup

	// Producer: feed items into channel.
	go func() {
		defer close(itemsCh)
		for _, item := range items {
			select {
			case itemsCh <- item:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Workers: consume items, produce results.
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range itemsCh {
				if cfg.Pauser != nil {
					cfg.Pauser.Wait()
				}

				delay := cfg.Throttler.Delay()
				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return
					}
				}

				resp, err := req.Do(ctx, item.Method, item.Path, item.Host)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					cfg.Throttler.RecordError()
					resultsCh <- ScanResult{
						Method: item.Method,
						Host:   item.Host,
						Path:   item.Path,
						Error:  err,
					}
					continue
				}

				cfg.Throttler.RecordStatus(resp.StatusCode)

				result := ScanResult{
					Method:        item.Method,
					Host:          item.Host,
					Path:          item.Path,
					URL:           resp.URL,
					StatusCode:    resp.StatusCode,
					ContentLength: resp.ContentLength,
					BodyHash:      resp.BodyHash,
					WordCount:     resp.WordCount,
					LineCount:     resp.LineCount,
					RedirectURL:   resp.RedirectURL,
					Duration:      resp.Duration,
				}
				if cfg.KeepBody {
					result.Body = resp.Body
				}

				resultsCh <- result
			}
		}()
	}

	// Closer: when all workers finish, close the results channel.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	return resultsCh
}
