package scanner

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Throttler provides adaptive rate limiting. When it detects 429 or
// connection-reset responses, it exponentially backs off. When responses
// are healthy, it gradually recovers to the original delay.
type Throttler struct {
	mu           sync.Mutex
	baseDelay    time.Duration
	currentDelay time.Duration
	maxDelay     time.Duration
	consecutive  int // consecutive throttle signals
	enabled      bool
	quiet        bool
}

// NewThrottler creates an adaptive throttler.
func NewThrottler(baseDelay time.Duration, enabled, quiet bool) *Throttler {
	return &Throttler{
		baseDelay:    baseDelay,
		currentDelay: baseDelay,
		maxDelay:     30 * time.Second,
		enabled:      enabled,
		quiet:        quiet,
	}
}

// Delay returns the current per-request delay. Workers should call this
// before each request.
func (t *Throttler) Delay() time.Duration {
	if !t.enabled {
		return t.baseDelay
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.currentDelay
}

// RecordStatus updates the throttler based on a response status code.
func (t *Throttler) RecordStatus(statusCode int) {
	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if statusCode == 429 || statusCode == 503 {
		t.consecutive++
		// Exponential back-off: double the delay, up to maxDelay.
		newDelay := t.currentDelay * 2
		if newDelay < 500*time.Millisecond {
			newDelay = 500 * time.Millisecond
		}
		if newDelay > t.maxDelay {
			newDelay = t.maxDelay
		}
		if newDelay != t.currentDelay {
			t.currentDelay = newDelay
			if !t.quiet {
				fmt.Fprintf(os.Stderr, "\n[!] Rate limited (HTTP %d) — backing off to %s/req\n", statusCode, t.currentDelay)
			}
		}
	} else {
		if t.consecutive > 0 {
			t.consecutive = 0
			// Gradually recover: halve delay toward base, but not below base.
			newDelay := t.currentDelay / 2
			if newDelay < t.baseDelay {
				newDelay = t.baseDelay
			}
			if newDelay != t.currentDelay {
				t.currentDelay = newDelay
				if !t.quiet && t.currentDelay > t.baseDelay {
					fmt.Fprintf(os.Stderr, "\n[+] Recovering — delay now %s/req\n", t.currentDelay)
				}
			}
		}
	}
}

// RecordError flags a connection error (timeout, reset) as a possible
// rate limit signal.
func (t *Throttler) RecordError() {
	if !t.enabled {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.consecutive++
	if t.consecutive >= 3 {
		newDelay := t.currentDelay * 2
		if newDelay < 500*time.Millisecond {
			newDelay = 500 * time.Millisecond
		}
		if newDelay > t.maxDelay {
			newDelay = t.maxDelay
		}
		if newDelay != t.currentDelay {
			t.currentDelay = newDelay
			if !t.quiet {
				fmt.Fprintf(os.Stderr, "\n[!] Multiple errors — backing off to %s/req\n", t.currentDelay)
			}
		}
	}
}
