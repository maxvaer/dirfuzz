package output

import (
	"encoding/json"
	"io"
	"os"

	"github.com/maxvaer/dirfuzz/internal/scanner"
)

type jsonEntry struct {
	Method        string `json:"method"`
	Host          string `json:"host,omitempty"`
	URL           string `json:"url"`
	Path          string `json:"path"`
	StatusCode    int    `json:"status"`
	ContentLength int64  `json:"size"`
	RedirectURL   string `json:"redirect,omitempty"`
}

// JSONWriter writes results as a JSON array.
type JSONWriter struct {
	w       io.Writer
	closer  io.Closer
	entries []jsonEntry
}

// NewJSONWriter creates a JSON output writer.
func NewJSONWriter(outputFile string) (*JSONWriter, error) {
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
	return &JSONWriter{w: w, closer: closer}, nil
}

func (j *JSONWriter) WriteHeader() error { return nil }

func (j *JSONWriter) WriteResult(result *scanner.ScanResult) error {
	j.entries = append(j.entries, jsonEntry{
		Method:        result.Method,
		Host:          result.Host,
		URL:           result.URL,
		Path:          result.Path,
		StatusCode:    result.StatusCode,
		ContentLength: result.ContentLength,
		RedirectURL:   result.RedirectURL,
	})
	return nil
}

func (j *JSONWriter) WriteFooter(stats Stats) error {
	enc := json.NewEncoder(j.w)
	enc.SetIndent("", "  ")
	return enc.Encode(j.entries)
}

func (j *JSONWriter) Close() error {
	if j.closer != nil {
		return j.closer.Close()
	}
	return nil
}
