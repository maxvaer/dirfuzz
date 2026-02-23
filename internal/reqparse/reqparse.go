package reqparse

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ParsedRequest holds the extracted data from a raw HTTP request file.
type ParsedRequest struct {
	Method  string
	URL     string // full URL reconstructed from Host + request line
	Headers map[string]string
}

// ParseFile reads a raw HTTP request (e.g. Burp Suite export) and extracts
// the target URL and all headers including cookies.
func ParseFile(path string) (*ParsedRequest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening request file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB lines for large cookies

	// Parse request line: GET /path HTTP/1.1
	if !scanner.Scan() {
		return nil, fmt.Errorf("request file is empty")
	}
	requestLine := strings.TrimSpace(scanner.Text())
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %q", requestLine)
	}
	method := parts[0]
	requestPath := parts[1]

	// Parse headers until blank line.
	headers := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			break // end of headers
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])
		headers[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading request file: %w", err)
	}

	// Reconstruct the full URL from Host header + request path.
	host, ok := headers["Host"]
	if !ok {
		return nil, fmt.Errorf("request file missing Host header")
	}

	// Determine scheme. HTTP/2 in Burp exports usually means HTTPS.
	// Also check if the protocol version hints at TLS.
	scheme := "https"
	if len(parts) >= 3 {
		proto := strings.ToUpper(parts[2])
		if strings.HasPrefix(proto, "HTTP/1") {
			// Could be either, but default to https for safety.
			// If port 80 is explicit, use http.
			if strings.HasSuffix(host, ":80") {
				scheme = "http"
			}
		}
	}

	// If the request path is already a full URL (some proxies do this), use it directly.
	if strings.HasPrefix(requestPath, "http://") || strings.HasPrefix(requestPath, "https://") {
		parsedURL, err := url.Parse(requestPath)
		if err != nil {
			return nil, fmt.Errorf("invalid URL in request line: %w", err)
		}
		// Use only the scheme + host, strip the path (dirfuzz will append its own paths).
		return &ParsedRequest{
			Method:  method,
			URL:     parsedURL.Scheme + "://" + parsedURL.Host,
			Headers: headers,
		}, nil
	}

	// Build the base URL (scheme + host only, no path — dirfuzz appends wordlist paths).
	baseURL := scheme + "://" + host

	return &ParsedRequest{
		Method:  method,
		URL:     baseURL,
		Headers: headers,
	}, nil
}
