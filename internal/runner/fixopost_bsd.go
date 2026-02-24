//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package runner

import "golang.org/x/sys/unix"

// fixOutputProcessing re-enables OPOST after term.MakeRaw so that \n is
// translated to \r\n on output. MakeRaw disables all output processing
// which causes cursor alignment issues with progress bar output.
func fixOutputProcessing(fd int) {
	t, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return
	}
	t.Oflag |= unix.OPOST
	_ = unix.IoctlSetTermios(fd, unix.TIOCSETA, t)
}
