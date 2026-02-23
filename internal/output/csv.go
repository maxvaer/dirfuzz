package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

// CSVWriter writes results in CSV format.
type CSVWriter struct {
	w      *csv.Writer
	closer io.Closer
}

// NewCSVWriter creates a CSV output writer.
func NewCSVWriter(outputFile string) (*CSVWriter, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, err
		}
		w = f
		closer = f
	}
	return &CSVWriter{w: csv.NewWriter(w), closer: closer}, nil
}

func (c *CSVWriter) WriteHeader() error {
	return c.w.Write([]string{"url", "path", "status", "size", "redirect"})
}

func (c *CSVWriter) WriteResult(result *scanner.ScanResult) error {
	return c.w.Write([]string{
		result.URL,
		result.Path,
		fmt.Sprintf("%d", result.StatusCode),
		fmt.Sprintf("%d", result.ContentLength),
		result.RedirectURL,
	})
}

func (c *CSVWriter) WriteFooter(_ Stats) error {
	c.w.Flush()
	return c.w.Error()
}

func (c *CSVWriter) Close() error {
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}
