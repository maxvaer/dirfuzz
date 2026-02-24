package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PauseState provides pause-related information for display and ETA.
type PauseState interface {
	IsPaused() bool
	PausedDuration() time.Duration
	CurrentPauseDuration() time.Duration
}

// Progress tracks and displays scan progress on stderr.
type Progress struct {
	total     int
	completed atomic.Int64
	filtered  atomic.Int64
	errors    atomic.Int64
	found     atomic.Int64
	start     time.Time
	done      chan struct{}
	quiet     bool
	mu        sync.Mutex
	visible   bool       // whether the progress line is currently drawn
	pauser    PauseState // may be nil
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
				p.mu.Lock()
				p.draw()
				p.mu.Unlock()
			case <-p.done:
				p.mu.Lock()
				p.draw()
				fmt.Fprint(os.Stderr, "\n")
				p.visible = false
				p.mu.Unlock()
				return
			}
		}
	}()
}

// ClearLine temporarily removes the progress bar from the terminal so that
// a result line can be printed cleanly. Call Redraw() after printing.
func (p *Progress) ClearLine() {
	if p.quiet {
		return
	}
	p.mu.Lock()
	if p.visible {
		fmt.Fprint(os.Stderr, "\r\033[K")
		p.visible = false
	}
}

// Redraw redraws the progress bar after a ClearLine+print cycle.
func (p *Progress) Redraw() {
	if p.quiet {
		return
	}
	p.draw()
	p.mu.Unlock()
}

// Increment records a completed request.
func (p *Progress) Increment() {
	p.completed.Add(1)
}

// Completed returns the number of completed requests.
func (p *Progress) Completed() int64 {
	return p.completed.Load()
}

// IncrementFiltered records a filtered result.
func (p *Progress) IncrementFiltered() {
	p.filtered.Add(1)
}

// IncrementErrors records an error.
func (p *Progress) IncrementErrors() {
	p.errors.Add(1)
}

// IncrementFound records a result that passed all filters.
func (p *Progress) IncrementFound() {
	p.found.Add(1)
}

// SetPauser attaches a PauseState for pause-aware ETA and display.
func (p *Progress) SetPauser(ps PauseState) {
	p.mu.Lock()
	p.pauser = ps
	p.mu.Unlock()
}

// AddTotal increases the total request count (e.g. when crawl discovers new paths).
func (p *Progress) AddTotal(n int) {
	p.mu.Lock()
	p.total += n
	p.mu.Unlock()
}

// ETA returns the estimated remaining time based on current progress rate.
// Returns 0 if not enough data to estimate.
func (p *Progress) ETA() time.Duration {
	completed := p.completed.Load()
	elapsed := time.Since(p.start).Seconds()
	if p.pauser != nil {
		elapsed -= p.pauser.PausedDuration().Seconds()
	}
	if elapsed <= 0 || completed <= 0 {
		return 0
	}
	rate := float64(completed) / elapsed
	p.mu.Lock()
	total := p.total
	p.mu.Unlock()
	remaining := float64(int64(total)-completed) / rate
	return time.Duration(remaining * float64(time.Second))
}

// Stop ends the progress display.
func (p *Progress) Stop() {
	close(p.done)
}

// buildBar creates a visual progress bar of the given width.
func buildBar(pct float64, width int) string {
	filled := int(pct / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}

	var buf strings.Builder
	buf.WriteByte('[')
	for i := 0; i < width; i++ {
		if i < filled {
			buf.WriteByte('=')
		} else if i == filled && pct < 100 {
			buf.WriteByte('>')
		} else {
			buf.WriteByte(' ')
		}
	}
	buf.WriteByte(']')
	return buf.String()
}

func (p *Progress) draw() {
	completed := p.completed.Load()
	elapsed := time.Since(p.start).Seconds()
	if p.pauser != nil {
		elapsed -= p.pauser.PausedDuration().Seconds()
		if elapsed < 0 {
			elapsed = 0
		}
	}
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

	pauseTag := ""
	if p.pauser != nil && p.pauser.IsPaused() {
		pd := p.pauser.CurrentPauseDuration().Round(time.Second)
		pauseTag = fmt.Sprintf(" [PAUSED %s]", pd)
	}

	bar := buildBar(pct, 20)

	fmt.Fprintf(os.Stderr, "\r\033[K%s %3.0f%% | %d/%d | %.0f req/s | Found: %d | Filtered: %d | Errors: %d | %s%s",
		bar, pct, completed, p.total, rate,
		p.found.Load(), p.filtered.Load(), p.errors.Load(), eta, pauseTag)
	p.visible = true
}
