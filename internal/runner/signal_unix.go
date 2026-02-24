//go:build !windows

package runner

import (
	"os"
	"syscall"
)

func sendInterrupt() {
	syscall.Kill(os.Getpid(), syscall.SIGINT)
}
