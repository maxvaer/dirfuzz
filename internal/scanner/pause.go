package scanner

import (
	"sync"
	"time"
)

// Pauser provides a cooperative pause/resume gate for worker goroutines.
// When paused, calls to Wait() block until resumed. When not paused,
// Wait() is near-zero overhead (mutex lock + bool check + unlock).
type Pauser struct {
	mu          sync.Mutex
	cond        *sync.Cond
	paused      bool
	pausedSince time.Time
	totalPaused time.Duration
}

// NewPauser creates a Pauser in the running (unpaused) state.
func NewPauser() *Pauser {
	p := &Pauser{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Wait blocks the calling goroutine while the scan is paused.
// Returns immediately if not paused.
func (p *Pauser) Wait() {
	p.mu.Lock()
	for p.paused {
		p.cond.Wait()
	}
	p.mu.Unlock()
}

// Toggle flips between paused and running states.
// Returns the new paused state (true = now paused).
func (p *Pauser) Toggle() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.paused {
		p.totalPaused += time.Since(p.pausedSince)
		p.paused = false
		p.cond.Broadcast()
	} else {
		p.paused = true
		p.pausedSince = time.Now()
	}
	return p.paused
}

// IsPaused returns whether the scan is currently paused.
func (p *Pauser) IsPaused() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paused
}

// PausedDuration returns the total accumulated time spent paused,
// including any ongoing pause.
func (p *Pauser) PausedDuration() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.totalPaused
	if p.paused {
		d += time.Since(p.pausedSince)
	}
	return d
}

// CurrentPauseDuration returns how long the current pause has lasted.
// Returns 0 if not currently paused.
func (p *Pauser) CurrentPauseDuration() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.paused {
		return 0
	}
	return time.Since(p.pausedSince)
}
