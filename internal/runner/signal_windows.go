//go:build windows

package runner

import "syscall"

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGenerateConsoleCtrlEvent = kernel32.NewProc("GenerateConsoleCtrlEvent")
)

func sendInterrupt() {
	// CTRL_C_EVENT (0) to the current process group (0).
	procGenerateConsoleCtrlEvent.Call(0, 0)
}
