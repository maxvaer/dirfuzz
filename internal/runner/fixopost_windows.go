//go:build windows

package runner

// fixOutputProcessing is a no-op on Windows where output processing is
// handled differently and not affected by terminal raw mode.
func fixOutputProcessing(fd int) {}
