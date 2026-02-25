package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxvaer/dirfuzz/internal/config"
)

func writeWordlist(t *testing.T, words []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wordlist.txt")
	if err := os.WriteFile(path, []byte(strings.Join(words, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testOpts(t *testing.T, serverURL, wordlistPath string) *config.Options {
	t.Helper()
	return &config.Options{
		URL:          serverURL,
		WordlistPath: wordlistPath,
		Threads:      2,
		Timeout:      5 * time.Second,
		Quiet:        true,
		NoColor:      true,
		OutputFile:   filepath.Join(t.TempDir(), "output.txt"),
		OutputFormat: "text",
		SmartFilter:  false,
	}
}

func readOutput(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBasicScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(200)
			fmt.Fprint(w, "admin page")
		case "/login":
			w.WriteHeader(200)
			fmt.Fprint(w, "login page")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer srv.Close()

	wordlist := writeWordlist(t, []string{"admin", "login", "notexist"})
	opts := testOpts(t, srv.URL, wordlist)
	opts.ExcludeStatus = []int{404}

	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	out := readOutput(t, opts.OutputFile)
	if !strings.Contains(out, "/admin") {
		t.Error("expected /admin in output")
	}
	if !strings.Contains(out, "/login") {
		t.Error("expected /login in output")
	}
	if strings.Contains(out, "/notexist") {
		t.Error("unexpected /notexist in output")
	}
}

func TestSmartFilterRemovesSoft404s(t *testing.T) {
	const soft404Body = "Page not found. This is a custom 404 page with some content that looks real."

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			fmt.Fprint(w, "Welcome to the real admin panel. This is unique content that differs from the 404 page.")
			return
		}
		// Everything else returns 200 with identical body (soft-404).
		w.WriteHeader(200)
		fmt.Fprint(w, soft404Body)
	}))
	defer srv.Close()

	wordlist := writeWordlist(t, []string{"admin", "fakeone", "faketwo", "fakethree"})
	opts := testOpts(t, srv.URL, wordlist)
	opts.SmartFilter = true
	opts.SmartFilterThreshold = 50

	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	out := readOutput(t, opts.OutputFile)
	if !strings.Contains(out, "/admin") {
		t.Errorf("expected /admin in output, got:\n%s", out)
	}
	if strings.Contains(out, "/fakeone") {
		t.Error("unexpected /fakeone — smart filter should have removed it")
	}
	if strings.Contains(out, "/faketwo") {
		t.Error("unexpected /faketwo — smart filter should have removed it")
	}
}

func TestMethodFuzzing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" && r.Method == "POST" {
			w.WriteHeader(200)
			fmt.Fprint(w, "upload ok")
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	wordlist := writeWordlist(t, []string{"upload"})
	opts := testOpts(t, srv.URL, wordlist)
	opts.Methods = []string{"GET", "POST"}
	opts.ExcludeStatus = []int{404}

	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	out := readOutput(t, opts.OutputFile)
	if !strings.Contains(out, "/upload") {
		t.Error("expected /upload in output")
	}
	if !strings.Contains(out, "[POST]") {
		t.Errorf("expected [POST] prefix in output, got:\n%s", out)
	}
}

func TestCrawlDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index":
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><body><a href="/hidden">link</a></body></html>`)
		case "/hidden":
			w.WriteHeader(200)
			fmt.Fprint(w, "secret page")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer srv.Close()

	wordlist := writeWordlist(t, []string{"index"})
	opts := testOpts(t, srv.URL, wordlist)
	opts.Crawl = true
	opts.CrawlDepth = 2
	opts.ExcludeStatus = []int{404}

	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	out := readOutput(t, opts.OutputFile)
	if !strings.Contains(out, "/index") {
		t.Errorf("expected /index in output, got:\n%s", out)
	}
	if !strings.Contains(out, "/hidden") {
		t.Errorf("expected /hidden (discovered by crawl) in output, got:\n%s", out)
	}
}

func TestRecursiveSkipsSoft404Directories(t *testing.T) {
	// Server: /admin is a real directory with content,
	// /ghost returns the same soft-404 page as all unknown paths.
	const soft404 = "This is a custom error page that looks legit but is really a soft 404."

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin" || r.URL.Path == "/admin/":
			w.WriteHeader(301)
			http.Redirect(w, r, "/admin/", 301)
		case strings.HasPrefix(r.URL.Path, "/admin/"):
			w.WriteHeader(200)
			fmt.Fprint(w, "real admin content for "+r.URL.Path)
		case r.URL.Path == "/ghost" || r.URL.Path == "/ghost/":
			// Redirect like a directory, but content is soft-404.
			w.WriteHeader(200)
			fmt.Fprint(w, soft404)
		default:
			w.WriteHeader(200)
			fmt.Fprint(w, soft404)
		}
	}))
	defer srv.Close()

	wordlist := writeWordlist(t, []string{"admin", "ghost", "panel"})
	opts := testOpts(t, srv.URL, wordlist)
	opts.SmartFilter = true
	opts.SmartFilterThreshold = 50
	opts.Recursive = true
	opts.MaxDepth = 1
	opts.Crawl = false
	opts.DuplicateThreshold = 0 // disable to isolate smart filter behavior

	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	out := readOutput(t, opts.OutputFile)
	// /admin should appear (real content, different from soft-404).
	if !strings.Contains(out, "/admin") {
		t.Errorf("expected /admin in output, got:\n%s", out)
	}
	// /ghost should NOT appear (matches soft-404 baseline).
	if strings.Contains(out, "/ghost") {
		t.Errorf("unexpected /ghost in output — smart filter should have caught it:\n%s", out)
	}
}

func TestETASkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
		fmt.Fprint(w, "slow response")
	}))
	defer srv.Close()

	// Large wordlist to ensure ETA exceeds threshold.
	words := make([]string, 1000)
	for i := range words {
		words[i] = fmt.Sprintf("path%d", i)
	}
	wordlist := writeWordlist(t, words)
	opts := testOpts(t, srv.URL, wordlist)
	opts.MaxETA = 1 * time.Second

	start := time.Now()
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	// Without skip: 1000 paths / 2 threads * 100ms = 50s.
	// With skip: should abort after ~5s (100 requests for stable ETA estimate).
	if elapsed > 30*time.Second {
		t.Errorf("expected ETA skip to abort quickly, but took %s", elapsed)
	}
}
