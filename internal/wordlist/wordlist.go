package wordlist

import (
	"fmt"
	"os"
	"strings"
)

// Load returns the list of paths to fuzz. If path is empty, the embedded
// default wordlist is used. Extensions are expanded via %EXT% placeholders
// and optionally force-appended to every entry.
func Load(path string, extensions []string, forceExtensions bool) ([]string, error) {
	var raw string
	if path == "" {
		raw = embeddedWordlist
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading wordlist %s: %w", path, err)
		}
		raw = string(data)
	}

	lines := strings.Split(raw, "\n")
	seen := make(map[string]struct{}, len(lines))
	var result []string

	add := func(entry string) {
		if entry == "" {
			return
		}
		if _, ok := seen[entry]; !ok {
			seen[entry] = struct{}{}
			result = append(result, entry)
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "%EXT%") {
			for _, ext := range extensions {
				ext = strings.TrimPrefix(ext, ".")
				add(strings.ReplaceAll(line, "%EXT%", ext))
			}
			// Also add the bare version without extension placeholder.
			bare := strings.ReplaceAll(line, ".%EXT%", "")
			bare = strings.ReplaceAll(bare, "%EXT%", "")
			add(bare)
		} else if forceExtensions && len(extensions) > 0 {
			add(line)
			for _, ext := range extensions {
				ext = strings.TrimPrefix(ext, ".")
				add(line + "." + ext)
			}
		} else {
			add(line)
		}
	}

	return result, nil
}

// LoadSimple reads a wordlist file and returns de-duplicated entries.
// No extension expansion or placeholder processing is performed.
// If path is empty, the embedded default for that context is used.
func LoadSimple(path string) ([]string, error) {
	var raw string
	if path == "" {
		raw = embeddedVHostWordlist
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading wordlist %s: %w", path, err)
		}
		raw = string(data)
	}
	lines := strings.Split(raw, "\n")
	seen := make(map[string]struct{}, len(lines))
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			result = append(result, line)
		}
	}
	return result, nil
}
