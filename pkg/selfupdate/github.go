package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultRepo is the GitHub slug releases are fetched from.
	DefaultRepo = "lenny-ts/caddy-analyzer"

	// userAgent is mandatory for the GitHub API and polite for downloads.
	userAgent = "caddy-analyzer-selfupdate"
)

// Asset describes one release artifact we care about.
type Asset struct {
	Name string
	URL  string // browser_download_url
}

// Release is the subset of a GitHub release the updater needs.
type Release struct {
	Tag    string // e.g. "v0.5.0"
	Assets []Asset
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// FetchRelease resolves the target release: the latest published one when
// version is empty, otherwise the pinned tag's release. version may carry
// a "v" prefix ("v0.4.0").
func FetchRelease(ctx context.Context, client *http.Client, repo, version string) (*Release, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	if version != "" {
		endpoint = fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, strings.TrimPrefix(version, "v"))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decoding below
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("github api rate limit hit (%s): wait an hour or download manually from https://github.com/%s/releases", resp.Status, repo)
	case http.StatusNotFound:
		return nil, fmt.Errorf("release %q not found in %s (check the spelling of --version)", version, repo)
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github api returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var gr ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, fmt.Errorf("decode github response: %w", err)
	}
	if gr.TagName == "" {
		return nil, fmt.Errorf("github api returned no tag_name")
	}
	rel := &Release{Tag: gr.TagName}
	for _, a := range gr.Assets {
		rel.Assets = append(rel.Assets, Asset{Name: a.Name, URL: a.BrowserDownloadURL})
	}
	return rel, nil
}

// SelectAsset picks the archive matching the platform from the release
// assets. Naming follows .goreleaser.yaml:
//
//	caddy-analyzer_<version>_<os>_<arch>.tar.gz   (.zip on windows)
//
// The legacy "caddy-analyze_" project-name prefix is accepted as a
// fallback so updates from very old installs keep working.
func SelectAsset(assets []Asset, goos, goarch string) (*Asset, error) {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	suffixes := []string{"_" + goos + "_" + goarch + ext}
	prefixes := []string{"caddy-analyzer_", "caddy-analyze_"}

	for _, prefix := range prefixes {
		for i := range assets {
			name := assets[i].Name
			if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffixes[0]) && !strings.Contains(name, ".spdx") {
				return &assets[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no %s/%s archive in this release (looked for *%s); unsupported platform?", goos, goarch, suffixes[0])
}

// FindAsset returns the named artifact from the release (checksums.txt,
// its .pem/.sig sidecars, ...).
func FindAsset(rel *Release, name string) (*Asset, error) {
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			return &rel.Assets[i], nil
		}
	}
	return nil, fmt.Errorf("asset %q not attached to release %s", name, rel.Tag)
}

// DownloadTo fetches url into destDir under a temp name and returns the
// file path. The caller owns cleanup via CleanTemp.
func DownloadTo(ctx context.Context, client *http.Client, url, destDir string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", filepath.Base(url), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: unexpected status %s", filepath.Base(url), resp.Status)
	}

	f, err := os.CreateTemp(destDir, "caddy-analyze-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("download %s: %w", filepath.Base(url), err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

// BinaryName is the executable file name inside release archives.
func BinaryName(goos string) string {
	if goos == "windows" {
		return "caddy-analyze.exe"
	}
	return "caddy-analyze"
}
