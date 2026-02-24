package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPauserWaitNotPaused(t *testing.T) {
	p := NewPauser()
	// Wait should return immediately when not paused.
	done := make(chan struct{})
	go func() {
		p.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait() blocked when not paused")
	}
}

func TestPauserToggle(t *testing.T) {
	p := NewPauser()

	if p.IsPaused() {
		t.Fatal("expected not paused initially")
	}

	nowPaused := p.Toggle()
	if !nowPaused {
		t.Fatal("Toggle should return true (paused)")
	}
	if !p.IsPaused() {
		t.Fatal("expected paused after Toggle")
	}

	nowPaused = p.Toggle()
	if nowPaused {
		t.Fatal("Toggle should return false (resumed)")
	}
	if p.IsPaused() {
		t.Fatal("expected not paused after second Toggle")
	}
}

func TestPauserBlocksAndResumes(t *testing.T) {
	p := NewPauser()
	p.Toggle() // pause

	var blocked atomic.Int32
	var wg sync.WaitGroup

	n := 5
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blocked.Add(1)
			p.Wait() // should block
		}()
	}

	// Give goroutines time to hit Wait().
	time.Sleep(50 * time.Millisecond)
	if blocked.Load() != int32(n) {
		t.Fatalf("expected %d goroutines to reach Wait, got %d", n, blocked.Load())
	}

	// Resume.
	p.Toggle()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutines did not unblock after resume")
	}
}

func TestPauserDurationAccuracy(t *testing.T) {
	p := NewPauser()

	p.Toggle() // pause
	time.Sleep(100 * time.Millisecond)

	d := p.PausedDuration()
	if d < 80*time.Millisecond || d > 200*time.Millisecond {
		t.Fatalf("expected ~100ms paused duration, got %s", d)
	}

	cd := p.CurrentPauseDuration()
	if cd < 80*time.Millisecond {
		t.Fatalf("expected non-zero current pause duration, got %s", cd)
	}

	p.Toggle() // resume
	time.Sleep(50 * time.Millisecond)

	// Current pause should be 0 after resume.
	if p.CurrentPauseDuration() != 0 {
		t.Fatal("expected 0 current pause duration after resume")
	}

	// Total should still reflect the first pause.
	total := p.PausedDuration()
	if total < 80*time.Millisecond || total > 200*time.Millisecond {
		t.Fatalf("expected ~100ms total paused duration, got %s", total)
	}
}

func TestPauserMultipleToggles(t *testing.T) {
	p := NewPauser()

	// Pause 1: ~50ms
	p.Toggle()
	time.Sleep(50 * time.Millisecond)
	p.Toggle()

	// Pause 2: ~50ms
	p.Toggle()
	time.Sleep(50 * time.Millisecond)
	p.Toggle()

	total := p.PausedDuration()
	if total < 80*time.Millisecond || total > 300*time.Millisecond {
		t.Fatalf("expected ~100ms accumulated pause, got %s", total)
	}
}

func TestPauserConcurrent(t *testing.T) {
	p := NewPauser()
	var wg sync.WaitGroup

	// Many goroutines calling Wait() while toggling.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				p.Wait()
			}
		}()
	}

	// Toggle rapidly in the background.
	go func() {
		for i := 0; i < 10; i++ {
			p.Toggle()
			time.Sleep(5 * time.Millisecond)
		}
		// Ensure we end unpaused.
		if p.IsPaused() {
			p.Toggle()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent test timed out")
	}
}
