package crawl

import (
	"net/url"
	"regexp"
	"strings"
)

var linkPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)src\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`),
}

// ExtractPaths parses HTML body and returns de-duplicated same-origin paths
// found in href, src, and action attributes.
func ExtractPaths(body []byte, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var paths []string

	content := string(body)
	for _, re := range linkPatterns {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			raw := strings.TrimSpace(m[1])

			// Skip non-HTTP URIs and anchors.
			lower := strings.ToLower(raw)
			if strings.HasPrefix(lower, "javascript:") ||
				strings.HasPrefix(lower, "mailto:") ||
				strings.HasPrefix(lower, "data:") ||
				strings.HasPrefix(raw, "#") {
				continue
			}

			ref, err := url.Parse(raw)
			if err != nil {
				continue
			}
			resolved := base.ResolveReference(ref)

			// Same-origin check.
			if resolved.Host != "" && resolved.Host != base.Host {
				continue
			}

			path := strings.TrimRight(resolved.Path, "/")
			if path == "" {
				continue
			}
			path = strings.TrimPrefix(path, "/")
			if path == "" {
				continue
			}

			if _, ok := seen[path]; !ok {
				seen[path] = struct{}{}
				paths = append(paths, path)
			}
		}
	}

	return paths
}
