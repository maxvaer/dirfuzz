package crawl

import (
	"sort"
	"testing"
)

func TestExtractPaths_RelativeLinks(t *testing.T) {
	body := []byte(`<a href="/admin">Admin</a> <a href="login">Login</a> <img src="/images/logo.png">`)
	paths := ExtractPaths(body, "http://example.com")
	sort.Strings(paths)
	expected := []string{"admin", "images/logo.png", "login"}
	if len(paths) != len(expected) {
		t.Fatalf("expected %d paths, got %d: %v", len(expected), len(paths), paths)
	}
	for i, p := range paths {
		if p != expected[i] {
			t.Errorf("path[%d] = %q, want %q", i, p, expected[i])
		}
	}
}

func TestExtractPaths_CrossOriginRejected(t *testing.T) {
	body := []byte(`<a href="https://other.com/page">External</a>`)
	paths := ExtractPaths(body, "http://example.com")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for cross-origin, got %v", paths)
	}
}

func TestExtractPaths_JavascriptRejected(t *testing.T) {
	body := []byte(`<a href="javascript:alert(1)">XSS</a> <a href="mailto:a@b.com">Mail</a> <a href="data:text/html,hi">Data</a>`)
	paths := ExtractPaths(body, "http://example.com")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for non-http URIs, got %v", paths)
	}
}

func TestExtractPaths_FragmentRejected(t *testing.T) {
	body := []byte(`<a href="#section">Jump</a>`)
	paths := ExtractPaths(body, "http://example.com")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for fragment-only, got %v", paths)
	}
}

func TestExtractPaths_Deduplication(t *testing.T) {
	body := []byte(`<a href="/page">1</a> <a href="/page">2</a> <img src="/page">`)
	paths := ExtractPaths(body, "http://example.com")
	if len(paths) != 1 {
		t.Errorf("expected 1 deduplicated path, got %v", paths)
	}
}

func TestExtractPaths_FormAction(t *testing.T) {
	body := []byte(`<form action="/submit"></form>`)
	paths := ExtractPaths(body, "http://example.com")
	if len(paths) != 1 || paths[0] != "submit" {
		t.Errorf("expected [submit], got %v", paths)
	}
}
