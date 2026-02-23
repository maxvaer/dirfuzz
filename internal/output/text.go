package output

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

// ANSI color codes.
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
)

// TextWriter writes colored text output to a writer.
type TextWriter struct {
	w       io.Writer
	noColor bool
	quiet   bool
}

// NewTextWriter creates a text output writer. If outputFile is empty, stdout
// is used. noColor disables ANSI escape codes.
func NewTextWriter(outputFile string, noColor, quiet bool) (*TextWriter, error) {
	var w io.Writer = os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, err
		}
		w = f
	}
	return &TextWriter{w: w, noColor: noColor, quiet: quiet}, nil
}

func (t *TextWriter) WriteHeader() error {
	if t.quiet {
		return nil
	}
	dim := "\033[2m"
	reset := colorReset
	if t.noColor {
		dim = ""
		reset = ""
	}
	_, err := fmt.Fprintf(t.w, "%sCode      Size  URL%s\n", dim, reset)
	return err
}

func (t *TextWriter) WriteResult(result *scanner.ScanResult) error {
	color := t.colorForStatus(result.StatusCode)
	reset := colorReset
	if t.noColor {
		color = ""
		reset = ""
	}

	redirectInfo := ""
	if result.RedirectURL != "" {
		redirectInfo = fmt.Sprintf(" -> %s", result.RedirectURL)
	}

	prefix := ""
	if result.Method != "" && result.Method != "GET" {
		prefix += fmt.Sprintf("[%s] ", result.Method)
	}
	if result.Host != "" {
		prefix += fmt.Sprintf("[%s] ", result.Host)
	}

	_, err := fmt.Fprintf(t.w, "%s%3d%s  %8d  %s%s%s\n",
		color, result.StatusCode, reset,
		result.ContentLength,
		prefix,
		result.URL,
		redirectInfo,
	)
	return err
}

func (t *TextWriter) WriteFooter(stats Stats) error {
	if t.quiet {
		return nil
	}
	_, err := fmt.Fprintf(os.Stderr,
		"\nCompleted: %d requests | Filtered: %d | Errors: %d | Duration: %s | %.1f req/s\n",
		stats.TotalRequests,
		stats.FilteredCount,
		stats.ErrorCount,
		stats.Duration.Round(time.Millisecond),
		stats.RequestsPerSec,
	)
	return err
}

func (t *TextWriter) Close() error {
	if closer, ok := t.w.(io.Closer); ok && t.w != os.Stdout {
		return closer.Close()
	}
	return nil
}

func (t *TextWriter) colorForStatus(code int) string {
	if t.noColor {
		return ""
	}
	switch {
	case code >= 200 && code < 300:
		return colorGreen
	case code >= 300 && code < 400:
		return colorCyan
	case code >= 400 && code < 500:
		return colorYellow
	case code >= 500:
		return colorRed
	default:
		return ""
	}
}
