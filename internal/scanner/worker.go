package scanner

import (
	"context"
	"sync"
	"time"
)

// RunWorkerPool fans out path requests across workers and returns a channel
// of results. The channel is closed when all paths have been processed.
func RunWorkerPool(
	ctx context.Context,
	req *Requester,
	paths []string,
	threads int,
	delay time.Duration,
) <-chan ScanResult {
	pathsCh := make(chan string, threads*2)
	resultsCh := make(chan ScanResult, threads*2)

	var wg sync.WaitGroup

	// Producer: feed paths into channel.
	go func() {
		defer close(pathsCh)
		for _, p := range paths {
			select {
			case pathsCh <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Workers: consume paths, produce results.
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathsCh {
				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return
					}
				}

				resp, err := req.Do(ctx, path)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					resultsCh <- ScanResult{
						Path:  path,
						Error: err,
					}
					continue
				}

				resultsCh <- ScanResult{
					Path:          path,
					URL:           resp.URL,
					StatusCode:    resp.StatusCode,
					ContentLength: resp.ContentLength,
					BodyHash:      resp.BodyHash,
					WordCount:     resp.WordCount,
					LineCount:     resp.LineCount,
					RedirectURL:   resp.RedirectURL,
					Duration:      resp.Duration,
				}
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
