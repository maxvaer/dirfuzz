package scanner

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maxvaer/dirfuzz/internal/config"
)

// Response holds the parsed HTTP response data.
type Response struct {
	StatusCode    int
	ContentLength int64
	Body          []byte
	BodyHash      [16]byte
	WordCount     int
	LineCount     int
	URL           string
	RedirectURL   string
	Duration      time.Duration
}

// Requester wraps an HTTP client for directory fuzzing.
type Requester struct {
	client    *http.Client
	baseURL   *url.URL
	headers   map[string]string
	userAgent string
	timeout   time.Duration
}

// NewRequester creates a Requester from the provided options.
func NewRequester(opts *config.Options) (*Requester, error) {
	base, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", opts.URL, err)
	}
	if base.Scheme == "" {
		base.Scheme = "http"
	}
	base.Path = strings.TrimRight(base.Path, "/")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: opts.Timeout,
		}).DialContext,
		MaxIdleConnsPerHost: opts.Threads,
		MaxIdleConns:        opts.Threads,
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", opts.Proxy, err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = "dirfuzz/1.0"
	}

	return &Requester{
		client:    client,
		baseURL:   base,
		headers:   opts.Headers,
		userAgent: ua,
		timeout:   opts.Timeout,
	}, nil
}

// Do sends an HTTP request for the given path and returns the parsed response.
// method defaults to GET if empty. host overrides the Host header if non-empty.
func (r *Requester) Do(ctx context.Context, method, path, host string) (*Response, error) {
	if method == "" {
		method = http.MethodGet
	}
	targetURL := r.baseURL.String() + "/" + strings.TrimLeft(path, "/")

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", r.userAgent)
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	if host != "" {
		req.Host = host
	}

	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body for %s: %w", path, err)
	}
	elapsed := time.Since(start)

	bodyStr := string(body)
	wordCount := len(strings.Fields(bodyStr))
	lineCount := strings.Count(bodyStr, "\n") + 1
	if len(body) == 0 {
		lineCount = 0
	}

	result := &Response{
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(body)),
		Body:          body,
		BodyHash:      md5.Sum(body),
		WordCount:     wordCount,
		LineCount:     lineCount,
		URL:           targetURL,
		Duration:      elapsed,
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.RedirectURL = resp.Header.Get("Location")
	}

	return result, nil
}
