package output

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// Progress tracks and displays scan progress on stderr.
type Progress struct {
	total     int
	completed atomic.Int64
	filtered  atomic.Int64
	errors    atomic.Int64
	start     time.Time
	done      chan struct{}
	quiet     bool
}

// NewProgress creates a progress tracker. Call Start() to begin display updates.
func NewProgress(total int, quiet bool) *Progress {
	return &Progress{
		total: total,
		start: time.Now(),
		done:  make(chan struct{}),
		quiet: quiet,
	}
}

// Start begins periodically printing progress to stderr.
func (p *Progress) Start() {
	if p.quiet {
		return
	}
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.print()
			case <-p.done:
				p.print()
				fmt.Fprint(os.Stderr, "\n")
				return
			}
		}
	}()
}

// Increment records a completed request.
func (p *Progress) Increment() {
	p.completed.Add(1)
}

// IncrementFiltered records a filtered result.
func (p *Progress) IncrementFiltered() {
	p.filtered.Add(1)
}

// IncrementErrors records an error.
func (p *Progress) IncrementErrors() {
	p.errors.Add(1)
}

// Stop ends the progress display.
func (p *Progress) Stop() {
	close(p.done)
}

func (p *Progress) print() {
	completed := p.completed.Load()
	elapsed := time.Since(p.start).Seconds()
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(completed) / elapsed
	}

	pct := float64(0)
	if p.total > 0 {
		pct = float64(completed) / float64(p.total) * 100
	}

	eta := ""
	if rate > 0 && completed < int64(p.total) {
		remaining := float64(int64(p.total)-completed) / rate
		eta = fmt.Sprintf("ETA: %s", time.Duration(remaining*float64(time.Second)).Round(time.Second))
	}

	fmt.Fprintf(os.Stderr, "\r\033[K[%3.0f%%] %d/%d | %.0f req/s | Filtered: %d | Errors: %d | %s",
		pct, completed, p.total, rate,
		p.filtered.Load(), p.errors.Load(), eta)
}
