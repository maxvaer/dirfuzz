package reqparse

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile_BurpHTTP2(t *testing.T) {
	content := "GET /feedback?_rsc=gyais HTTP/2\r\n" +
		"Host: www.example.com\r\n" +
		"Cookie: session=abc123; token=xyz\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: */*\r\n" +
		"\r\n"

	path := writeTempFile(t, content)
	req, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if req.Method != "GET" {
		t.Errorf("method = %q, want GET", req.Method)
	}
	if req.URL != "https://www.example.com" {
		t.Errorf("url = %q, want https://www.example.com", req.URL)
	}
	if req.Headers["Cookie"] != "session=abc123; token=xyz" {
		t.Errorf("cookie = %q, want 'session=abc123; token=xyz'", req.Headers["Cookie"])
	}
	if req.Headers["User-Agent"] != "Mozilla/5.0" {
		t.Errorf("user-agent = %q, want 'Mozilla/5.0'", req.Headers["User-Agent"])
	}
}

func TestParseFile_HTTP11(t *testing.T) {
	content := "GET /admin HTTP/1.1\r\n" +
		"Host: target.com\r\n" +
		"Authorization: Bearer mytoken\r\n" +
		"\r\n"

	path := writeTempFile(t, content)
	req, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if req.URL != "https://target.com" {
		t.Errorf("url = %q, want https://target.com", req.URL)
	}
	if req.Headers["Authorization"] != "Bearer mytoken" {
		t.Errorf("auth = %q, want 'Bearer mytoken'", req.Headers["Authorization"])
	}
}

func TestParseFile_HTTP11_Port80(t *testing.T) {
	content := "GET / HTTP/1.1\r\n" +
		"Host: target.com:80\r\n" +
		"\r\n"

	path := writeTempFile(t, content)
	req, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	if req.URL != "http://target.com:80" {
		t.Errorf("url = %q, want http://target.com:80", req.URL)
	}
}

func TestParseFile_MissingHost(t *testing.T) {
	content := "GET / HTTP/1.1\r\n" +
		"Accept: */*\r\n" +
		"\r\n"

	path := writeTempFile(t, content)
	_, err := ParseFile(path)
	if err == nil {
		t.Error("expected error for missing Host header")
	}
}

func TestParseFile_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")
	_, err := ParseFile(path)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
