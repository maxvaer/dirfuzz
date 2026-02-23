package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/maxvaer/dirfuzz/pkg/version"
)

const (
	repoOwner = "maxvaer"
	repoName  = "dirfuzz"
	apiURL    = "https://api.github.com/repos/" + repoOwner + "/" + repoName + "/releases/latest"
)

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Update checks GitHub for the latest release and replaces the current binary.
func Update() error {
	fmt.Fprintf(os.Stderr, "[*] Current version: %s\n", version.Version)
	fmt.Fprintf(os.Stderr, "[*] Checking for updates...\n")

	release, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(version.Version, "v")

	if currentVersion != "dev" && latestVersion == currentVersion {
		fmt.Fprintf(os.Stderr, "[+] Already up to date (%s)\n", version.Version)
		return nil
	}

	fmt.Fprintf(os.Stderr, "[*] New version available: %s -> %s\n", version.Version, release.TagName)

	// Find the right asset for this OS/arch.
	asset, err := findAsset(release.Assets)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[*] Downloading %s...\n", asset.Name)

	bin, err := downloadAndExtract(asset)
	if err != nil {
		return fmt.Errorf("downloading update: %w", err)
	}

	if err := replaceBinary(bin); err != nil {
		return fmt.Errorf("replacing binary: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[+] Updated to %s\n", release.TagName)
	return nil
}

func fetchLatestRelease() (*githubRelease, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found at %s/%s", repoOwner, repoName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &release, nil
}

func findAsset(assets []githubAsset) (*githubAsset, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Build search patterns for common naming conventions.
	// e.g. dirfuzz_linux_amd64.tar.gz, dirfuzz_windows_amd64.zip
	patterns := []string{
		fmt.Sprintf("%s_%s_%s", repoName, goos, goarch),
		fmt.Sprintf("%s-%s-%s", repoName, goos, goarch),
	}

	for _, asset := range assets {
		name := strings.ToLower(asset.Name)
		for _, pattern := range patterns {
			if strings.Contains(name, pattern) {
				return &asset, nil
			}
		}
	}

	return nil, fmt.Errorf("no release asset found for %s/%s — available assets: %s",
		goos, goarch, assetNames(assets))
}

func assetNames(assets []githubAsset) string {
	names := make([]string, len(assets))
	for i, a := range assets {
		names[i] = a.Name
	}
	return strings.Join(names, ", ")
}

func downloadAndExtract(asset *githubAsset) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(asset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	name := strings.ToLower(asset.Name)

	switch {
	case strings.HasSuffix(name, ".zip"):
		return extractZip(data)
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz"):
		return extractTarGz(data)
	default:
		// Assume the asset is a raw binary.
		return data, nil
	}
}

func extractZip(data []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	binaryName := repoName
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if strings.EqualFold(base, binaryName) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("binary %q not found in zip archive", binaryName)
}

func extractTarGz(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	binaryName := repoName

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		base := filepath.Base(hdr.Name)
		if base == binaryName && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary %q not found in tar.gz archive", binaryName)
}

func replaceBinary(newBin []byte) error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return err
	}

	oldPath := execPath + ".old"

	// Remove any leftover .old file from a previous update.
	_ = os.Remove(oldPath)

	// Rename current binary so we can write the new one.
	if err := os.Rename(execPath, oldPath); err != nil {
		return fmt.Errorf("renaming current binary: %w", err)
	}

	if err := os.WriteFile(execPath, newBin, 0o755); err != nil {
		// Try to restore the old binary.
		_ = os.Rename(oldPath, execPath)
		return fmt.Errorf("writing new binary: %w", err)
	}

	// Clean up old binary (may fail on Windows since it's still running — that's OK).
	_ = os.Remove(oldPath)

	return nil
}
