package wordlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmbedded(t *testing.T) {
	paths, err := Load("", nil, false)
	if err != nil {
		t.Fatalf("Load embedded: %v", err)
	}
	if len(paths) < 1000 {
		t.Errorf("expected at least 1000 entries in embedded wordlist, got %d", len(paths))
	}
	// Should not contain comments or empty lines.
	for _, p := range paths {
		if strings.HasPrefix(p, "#") {
			t.Errorf("found comment line in loaded wordlist: %q", p)
		}
		if strings.TrimSpace(p) == "" {
			t.Error("found empty line in loaded wordlist")
		}
	}
}

func TestLoadWithExtensions(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "test.txt")
	content := "admin\nindex.%EXT%\nlogin\n"
	if err := os.WriteFile(wl, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	paths, err := Load(wl, []string{"php", "html"}, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := map[string]bool{
		"admin":      true,
		"index.php":  true,
		"index.html": true,
		"index":      true, // bare version from %EXT% removal
		"login":      true,
	}

	got := make(map[string]bool, len(paths))
	for _, p := range paths {
		got[p] = true
	}

	for w := range want {
		if !got[w] {
			t.Errorf("missing expected entry %q", w)
		}
	}
}

func TestLoadForceExtensions(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "test.txt")
	content := "admin\nlogin\n"
	if err := os.WriteFile(wl, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	paths, err := Load(wl, []string{"php"}, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := map[string]bool{
		"admin":     true,
		"admin.php": true,
		"login":     true,
		"login.php": true,
	}

	got := make(map[string]bool, len(paths))
	for _, p := range paths {
		got[p] = true
	}

	for w := range want {
		if !got[w] {
			t.Errorf("missing expected entry %q", w)
		}
	}
	if len(paths) != len(want) {
		t.Errorf("expected %d entries, got %d: %v", len(want), len(paths), paths)
	}
}

func TestLoadDeduplication(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "test.txt")
	content := "admin\nadmin\nlogin\nadmin\n"
	if err := os.WriteFile(wl, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	paths, err := Load(wl, nil, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(paths) != 2 {
		t.Errorf("expected 2 deduplicated entries, got %d: %v", len(paths), paths)
	}
}

func TestLoadSkipsComments(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "test.txt")
	content := "# comment\nadmin\n\n# another\nlogin\n"
	if err := os.WriteFile(wl, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	paths, err := Load(wl, nil, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(paths) != 2 {
		t.Errorf("expected 2 entries (comments/blanks skipped), got %d: %v", len(paths), paths)
	}
}
