package runner

import (
	"fmt"
	"io"
	"os"

	"github.com/maxvaer/dirfuzz/internal/scanner"
	"golang.org/x/term"
)

// startStdinToggle starts a goroutine that reads single keypresses from
// stdin and toggles the pauser on Enter or Space. It returns a cleanup
// function that restores the terminal state. If stdin is not a terminal,
// it returns a nil pauser and a no-op cleanup.
func startStdinToggle(quiet bool) (pauser *scanner.Pauser, cleanup func()) {
	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		return nil, func() {}
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "[!] Could not enable raw terminal: %v\n", err)
		}
		return nil, func() {}
	}

	// MakeRaw disables OPOST which stops \n → \r\n translation, causing
	// cursor alignment issues. Re-enable it since we only need raw input.
	fixOutputProcessing(fd)

	pauser = scanner.NewPauser()

	cleanup = func() {
		_ = term.Restore(fd, oldState)
	}

	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				return
			}
			if n == 0 {
				continue
			}

			key := buf[0]

			// Ctrl+C (0x03): restore terminal and re-send SIGINT so the
			// existing signal handler chain fires normally.
			if key == 0x03 {
				_ = term.Restore(fd, oldState)
				sendInterrupt()
				return
			}

			// Enter (CR or LF) or Space: toggle pause.
			if key == '\r' || key == '\n' || key == ' ' {
				nowPaused := pauser.Toggle()
				if !quiet {
					if nowPaused {
						fmt.Fprintf(os.Stderr, "\r\033[K[*] Scan PAUSED — press Enter or Space to resume\n")
					} else {
						fmt.Fprintf(os.Stderr, "\r\033[K[*] Scan RESUMED\n")
					}
				}
			}
		}
	}()

	return pauser, cleanup
}
