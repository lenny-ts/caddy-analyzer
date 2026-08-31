package selfupdate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	cosignRepo      = "sigstore/cosign"
	cosignBinary    = "cosign"
	cosignChecksums = "cosign_checksums.txt"
)

// EnsureCosign finds or downloads cosign. If cosign is already in PATH,
// it returns the existing path. Otherwise it downloads the appropriate
// binary for the current platform, verifies its checksum, and returns
// the path to the temporary binary. The caller must remove the temp dir
// when done.
func EnsureCosign(ctx context.Context, client *http.Client) (string, string, error) {
	// Check if cosign is already available.
	if path, err := exec.LookPath(cosignBinary); err == nil {
		return path, "", nil
	}

	fmt.Fprintf(os.Stderr, "cosign not found in PATH, downloading...\n")

	if client == nil {
		client = &http.Client{}
	}

	// Get latest cosign release info.
	tag, err := getLatestCosignTag(ctx, client)
	if err != nil {
		return "", "", fmt.Errorf("get cosign release: %w", err)
	}

	// Download cosign binary and checksums.
	tmpDir, err := os.MkdirTemp("", "cosign-*")
	if err != nil {
		return "", "", fmt.Errorf("create temp dir: %w", err)
	}

	binPath, checksumPath, err := downloadCosign(ctx, client, tag, tmpDir)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", err
	}

	// Verify checksum.
	if err := verifyCosignChecksum(binPath, checksumPath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("cosign verification failed: %w", err)
	}

	// Make executable.
	if err := os.Chmod(binPath, 0o755); err != nil { //nosec G302 -- binary must be executable
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("chmod cosign: %w", err)
	}

	fmt.Fprintf(os.Stderr, "cosign %s downloaded and verified\n", tag)
	return binPath, tmpDir, nil
}

// getLatestCosignTag returns the latest cosign release tag from GitHub.
func getLatestCosignTag(ctx context.Context, client *http.Client) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", cosignRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api: %s", resp.Status)
	}

	var result struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.TagName == "" {
		return "", fmt.Errorf("no tag_name in response")
	}
	return result.TagName, nil
}

// downloadCosign downloads the cosign binary and checksums file for the
// current platform.
func downloadCosign(ctx context.Context, client *http.Client, tag, dir string) (string, string, error) {
	// Determine binary name based on platform.
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}

	binName := fmt.Sprintf("cosign-%s-%s%s", goos, goarch, ext)
	checksumName := cosignChecksums

	// Build download URLs.
	baseURL := cosignReleaseURL(tag)
	binURL := baseURL + "/" + binName
	checksumURL := baseURL + "/" + checksumName

	// Download checksums.
	checksumPath := filepath.Join(dir, checksumName)
	if err := downloadFile(ctx, client, checksumURL, checksumPath); err != nil {
		return "", "", fmt.Errorf("download checksums: %w", err)
	}

	// Download binary.
	binPath := filepath.Join(dir, cosignBinary+ext)
	if err := downloadFile(ctx, client, binURL, binPath); err != nil {
		return "", "", fmt.Errorf("download cosign: %w", err)
	}

	return binPath, checksumPath, nil
}

func cosignReleaseURL(tag string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s", cosignRepo, tag)
}

// downloadFile downloads a URL to a local file.
func downloadFile(ctx context.Context, client *http.Client, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: status %s", filepath.Base(url), resp.Status)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	_, err = io.Copy(f, resp.Body)
	return err
}

// verifyCosignChecksum verifies the downloaded cosign binary against the
// checksum file.
func verifyCosignChecksum(binPath, checksumPath string) error {
	// Read checksums file.
	f, err := os.Open(checksumPath)
	if err != nil {
		return fmt.Errorf("open checksums: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Compute hash of binary.
	bf, err := os.Open(binPath)
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer func() { _ = bf.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, bf); err != nil {
		return fmt.Errorf("hash binary: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))

	// Find expected hash in checksums file.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) < 2 {
			continue
		}
		expected := line[0]
		name := filepath.Base(line[1])
		if name == filepath.Base(binPath) || strings.HasPrefix(name, "cosign") {
			if got == expected {
				return nil
			}
			return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, got)
		}
	}

	return fmt.Errorf("binary %s not found in checksums file", filepath.Base(binPath))
}
