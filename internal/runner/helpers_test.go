package runner

import (
	"testing"

	"github.com/maxvaer/dirfuzz/internal/config"
	"github.com/maxvaer/dirfuzz/internal/scanner"
)

func TestExtractParentDirs(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		maxDepth int
		want     []string
	}{
		{
			name:     "deep path",
			path:     "/js/asset/login.js",
			maxDepth: 3,
			want:     []string{"js", "js/asset"},
		},
		{
			name:     "single segment",
			path:     "robots.txt",
			maxDepth: 3,
			want:     nil,
		},
		{
			name:     "root slash",
			path:     "/",
			maxDepth: 3,
			want:     nil,
		},
		{
			name:     "empty string",
			path:     "",
			maxDepth: 3,
			want:     nil,
		},
		{
			name:     "max depth limits result",
			path:     "/a/b/c/d/e/file.txt",
			maxDepth: 2,
			want:     []string{"a", "a/b"},
		},
		{
			name:     "two segments",
			path:     "/api/users",
			maxDepth: 5,
			want:     []string{"api"},
		},
		{
			name:     "leading slash stripped",
			path:     "/admin/config/db.ini",
			maxDepth: 10,
			want:     []string{"admin", "admin/config"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractParentDirs(tt.path, tt.maxDepth)
			if len(got) != len(tt.want) {
				t.Fatalf("extractParentDirs(%q, %d) = %v, want %v", tt.path, tt.maxDepth, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLooksLikeDirectory(t *testing.T) {
	tests := []struct {
		name   string
		result scanner.ScanResult
		want   bool
	}{
		{
			name:   "trailing slash",
			result: scanner.ScanResult{Path: "admin/", StatusCode: 200},
			want:   true,
		},
		{
			name:   "redirect to path with slash",
			result: scanner.ScanResult{Path: "admin", StatusCode: 301, RedirectURL: "http://example.com/admin/"},
			want:   true,
		},
		{
			name:   "200 without dot in last segment",
			result: scanner.ScanResult{Path: "api/users", StatusCode: 200},
			want:   true,
		},
		{
			name:   "200 with dot in last segment",
			result: scanner.ScanResult{Path: "css/style.css", StatusCode: 200},
			want:   false,
		},
		{
			name:   "404 status",
			result: scanner.ScanResult{Path: "admin", StatusCode: 404},
			want:   false,
		},
		{
			name:   "redirect not to slash",
			result: scanner.ScanResult{Path: "old", StatusCode: 302, RedirectURL: "http://example.com/new"},
			want:   false,
		},
		{
			name:   "root path with 200",
			result: scanner.ScanResult{Path: "config", StatusCode: 200},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeDirectory(tt.result)
			if got != tt.want {
				t.Errorf("looksLikeDirectory(%+v) = %v, want %v", tt.result, got, tt.want)
			}
		})
	}
}

func TestExpandItems(t *testing.T) {
	tests := []struct {
		name    string
		paths   []string
		methods []string
		want    int
	}{
		{
			name:    "single method",
			paths:   []string{"admin", "login"},
			methods: []string{"GET"},
			want:    2,
		},
		{
			name:    "multiple methods",
			paths:   []string{"admin", "login"},
			methods: []string{"GET", "POST", "PUT"},
			want:    6,
		},
		{
			name:    "empty paths",
			paths:   []string{},
			methods: []string{"GET"},
			want:    0,
		},
		{
			name:    "empty methods",
			paths:   []string{"admin"},
			methods: []string{},
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandItems(tt.paths, tt.methods)
			if len(got) != tt.want {
				t.Errorf("expandItems: got %d items, want %d", len(got), tt.want)
			}
			// Check no duplicates.
			seen := make(map[string]bool)
			for _, item := range got {
				key := item.Method + ":" + item.Path
				if seen[key] {
					t.Errorf("duplicate item: %s", key)
				}
				seen[key] = true
			}
		})
	}
}

func TestResolveMethods(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		want    []string
	}{
		{
			name:    "empty defaults to GET",
			methods: nil,
			want:    []string{"GET"},
		},
		{
			name:    "explicit methods uppercased",
			methods: []string{"get", "post"},
			want:    []string{"GET", "POST"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &config.Options{Methods: tt.methods}
			got := resolveMethods(opts)
			if len(got) != len(tt.want) {
				t.Fatalf("resolveMethods: got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
