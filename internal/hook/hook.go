package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

// resultJSON is the JSON payload sent to the hook command via stdin.
type resultJSON struct {
	Method        string `json:"method"`
	Host          string `json:"host,omitempty"`
	URL           string `json:"url"`
	Path          string `json:"path"`
	StatusCode    int    `json:"status"`
	ContentLength int64  `json:"size"`
	RedirectURL   string `json:"redirect,omitempty"`
	WordCount     int    `json:"words"`
	LineCount     int    `json:"lines"`
}

// Runner executes a shell command for each non-filtered scan result.
type Runner struct {
	cmd   string
	quiet bool
}

// NewRunner creates a hook runner. cmd is the shell command to execute.
func NewRunner(cmd string, quiet bool) *Runner {
	return &Runner{cmd: cmd, quiet: quiet}
}

// Run executes the hook command with the result as JSON on stdin.
// The command runs with a 30-second timeout. Errors are logged but
// do not halt the scan.
func (r *Runner) Run(result *scanner.ScanResult) {
	payload := resultJSON{
		Method:        result.Method,
		Host:          result.Host,
		URL:           result.URL,
		Path:          result.Path,
		StatusCode:    result.StatusCode,
		ContentLength: result.ContentLength,
		RedirectURL:   result.RedirectURL,
		WordCount:     result.WordCount,
		LineCount:     result.LineCount,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[hook] marshal error: %v\n", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	shell, args := shellCommand()
	// Replace {url}, {status}, {path} placeholders in the command.
	expanded := r.cmd
	expanded = strings.ReplaceAll(expanded, "{url}", result.URL)
	expanded = strings.ReplaceAll(expanded, "{path}", result.Path)
	expanded = strings.ReplaceAll(expanded, "{status}", fmt.Sprintf("%d", result.StatusCode))
	expanded = strings.ReplaceAll(expanded, "{size}", fmt.Sprintf("%d", result.ContentLength))
	expanded = strings.ReplaceAll(expanded, "{method}", result.Method)
	expanded = strings.ReplaceAll(expanded, "{host}", result.Host)

	cmd = exec.CommandContext(ctx, shell, append(args, expanded)...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if !r.quiet {
			fmt.Fprintf(os.Stderr, "[hook] error: %v\n", err)
		}
		return
	}

	if len(output) > 0 && !r.quiet {
		fmt.Fprintf(os.Stderr, "[hook] %s", output)
	}
}

func shellCommand() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C"}
	}
	return "sh", []string{"-c"}
}
