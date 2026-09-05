package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestFetchReleasePreservesVersionTagPrefix(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		wantPath := "/repos/lenny-ts/caddy-analyzer/releases/tags/v0.6.3"
		if req.URL.Path != wantPath {
			t.Fatalf("request path = %q, want %q", req.URL.Path, wantPath)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v0.6.3","assets":[]}`)),
			Header:     make(http.Header),
		}, nil
	})}

	rel, err := FetchRelease(context.Background(), client, "lenny-ts/caddy-analyzer", "v0.6.3")
	if err != nil {
		t.Fatalf("FetchRelease returned error: %v", err)
	}
	if rel.Tag != "v0.6.3" {
		t.Fatalf("release tag = %q, want v0.6.3", rel.Tag)
	}
}

func TestSelectAsset(t *testing.T) {
	rel := &Release{Tag: "v0.5.0", Assets: []Asset{
		{Name: "caddy-analyzer_0.5.0_linux_amd64.tar.gz", URL: "u1"},
		{Name: "caddy-analyzer_0.5.0_linux_arm64.tar.gz", URL: "u2"},
		{Name: "caddy-analyzer_0.5.0_darwin_amd64.tar.gz", URL: "u3"},
		{Name: "caddy-analyzer_0.5.0_windows_amd64.zip", URL: "u4"},
		{Name: "caddy-analyzer_0.5.0_linux_amd64.tar.gz.spdx.json", URL: "sbom"},
		{Name: "checksums.txt", URL: "sums"},
		{Name: "checksums.txt.pem", URL: "pem"},
		{Name: "checksums.txt.sig", URL: "sig"},
		{Name: "checksums.txt.bundle", URL: "bundle"},
		{Name: "trusted_root.json", URL: "root"},
	}}

	got, err := SelectAsset(rel.Assets, "linux", "amd64")
	if err != nil || got.URL != "u1" {
		t.Fatalf("linux/amd64: got %+v, err %v (want u1)", got, err)
	}
	got, err = SelectAsset(rel.Assets, "windows", "amd64")
	if err != nil || got.URL != "u4" {
		t.Fatalf("windows/amd64: got %+v, err %v (want u4 zip)", got, err)
	}
	if _, err := SelectAsset(rel.Assets, "plan9", "amd64"); err == nil {
		t.Fatal("unsupported platform must error")
	}

	// Legacy project-name fallback (very old releases).
	legacy := []Asset{{Name: "caddy-analyze_0.2.0_linux_amd64.tar.gz", URL: "old"}}
	if got, err := SelectAsset(legacy, "linux", "amd64"); err != nil || got.URL != "old" {
		t.Fatalf("legacy prefix: got %+v, err %v", got, err)
	}
}

func TestFindAsset(t *testing.T) {
	rel := &Release{Tag: "v0.5.0", Assets: []Asset{{Name: "checksums.txt", URL: "u"}}}
	if a, err := FindAsset(rel, "checksums.txt"); err != nil || a.URL != "u" {
		t.Fatalf("FindAsset existing: %+v err=%v", a, err)
	}
	if _, err := FindAsset(rel, "nope"); err == nil {
		t.Fatal("missing asset must error")
	}
}

func TestParseChecksums(t *testing.T) {
	content := strings.Join([]string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  caddy-analyzer_0.5.0_linux_amd64.tar.gz",
		"deadbeef  short-and-malformed",
		"",
		"zz-not-hex-00000000000000000000000000000000000000000000000000  bad.txt",
	}, "\n")
	sums := ParseChecksums(content)
	if len(sums) != 1 {
		t.Fatalf("ParseChecksums kept %d entries, want 1 (only well-formed sha256 lines)", len(sums))
	}
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if sums["caddy-analyzer_0.5.0_linux_amd64.tar.gz"] != want {
		t.Errorf("entry mismatch: %q", sums["caddy-analyzer_0.5.0_linux_amd64.tar.gz"])
	}
}

func TestVerifyArchiveChecksum(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "caddy-analyzer_0.5.0_linux_amd64.tar.gz")
	payload := []byte("release archive bytes")
	if err := os.WriteFile(archive, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := FileSHA256(archive)
	if err != nil {
		t.Fatal(err)
	}

	// Match passes.
	if err := VerifyArchiveChecksum(archive, map[string]string{filepath.Base(archive): sum}); err != nil {
		t.Fatalf("matching checksum rejected: %v", err)
	}
	// Mismatch fails closed.
	if err := VerifyArchiveChecksum(archive, map[string]string{filepath.Base(archive): strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("tampered archive accepted")
	}
	// Unlisted archive fails closed.
	if err := VerifyArchiveChecksum(filepath.Join(dir, "other.tar.gz"), map[string]string{"x": sum}); err == nil {
		t.Fatal("unlisted archive accepted")
	}
}

// recordingRunner captures cosign invocations so tests can assert the
// exact verification command without shipping the cosign binary.
type recordingRunner struct {
	calls [][]string
	err   error // returned from every Run
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.err
}

func TestVerifyChecksumsSignatureBuildsCosignCommand(t *testing.T) {
	dir := t.TempDir()
	repo := DefaultRepo
	runner := &recordingRunner{}
	for _, name := range []string{"checksums.txt.pem", "checksums.txt.sig"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := VerifyChecksumsSignature(context.Background(), runner, "cosign", dir, repo); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("expected exactly one cosign invocation, got %d", len(runner.calls))
	}
	call := runner.calls[0]
	joined := strings.Join(call, "\x00")

	for _, want := range []string{
		"verify-blob",
		filepath.Join(dir, "checksums.txt.pem"),
		filepath.Join(dir, "checksums.txt.sig"),
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		filepath.Join(dir, "checksums.txt"),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cosign args missing %q; got %v", want, call)
		}
	}
	// Identity regexp must be anchored to this repo's release workflow and
	// must actually match the certificate identity GitHub Actions mints.
	idIdx := -1
	for i, a := range call {
		if a == "--certificate-identity-regexp" {
			idIdx = i + 1
		}
	}
	if idIdx <= 0 {
		t.Fatal("--certificate-identity-regexp not passed to cosign")
	}
	re, err := regexp.Compile(call[idIdx])
	if err != nil {
		t.Fatalf("identity regexp does not compile: %v", err)
	}
	good := "https://github.com/lenny-ts/caddy-analyzer/.github/workflows/release.yml@refs/tags/v0.5.0"
	if !re.MatchString(good) {
		t.Errorf("identity regexp %q does not match legitimate workflow URI %q", call[idIdx], good)
	}
	bad := "https://github.com/attacker/forked-analyzer/.github/workflows/release.yml@refs/tags/v0.5.0"
	if re.MatchString(bad) {
		t.Errorf("identity regexp %q must reject foreign repos (%q)", call[idIdx], bad)
	}
}

func TestVerifyChecksumsSignatureUsesBundleAndTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt.bundle"), []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trusted_root.json"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	if err := VerifyChecksumsSignature(context.Background(), runner, "cosign", dir, DefaultRepo); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	call := strings.Join(runner.calls[0], "\x00")
	for _, want := range []string{"--bundle", filepath.Join(dir, "checksums.txt.bundle"), "--trusted-root", filepath.Join(dir, "trusted_root.json"), "--new-bundle-format"} {
		if !strings.Contains(call, want) {
			t.Errorf("cosign args missing %q; got %v", want, runner.calls[0])
		}
	}
	if strings.Contains(call, "checksums.txt.pem") || strings.Contains(call, "checksums.txt.sig") {
		t.Errorf("bundle verification unexpectedly used legacy sidecars: %v", runner.calls[0])
	}
}

func TestVerifyChecksumsSignatureRejectsIncompleteBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt.bundle"), []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksumsSignature(context.Background(), &recordingRunner{}, "cosign", dir, DefaultRepo); err == nil {
		t.Fatal("bundle without trusted root must fail closed")
	}
}

func TestVerifyChecksumsSignatureFallsBackToLegacyForOldBundle(t *testing.T) {
	dir := t.TempDir()
	// Old-format cosign bundle (as published before --new-bundle-format):
	// the updater must ignore it and verify via the legacy sidecars.
	oldBundle := `{"base64Signature":"eA","cert":"eQ","rekorBundle":{}}`
	for name, content := range map[string]string{
		"checksums.txt.bundle": oldBundle,
		"checksums.txt.pem":    "fixture-cert",
		"checksums.txt.sig":    "fixture-sig",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &recordingRunner{}
	if err := VerifyChecksumsSignature(context.Background(), runner, "cosign", dir, DefaultRepo); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("expected exactly one cosign invocation, got %d", len(runner.calls))
	}
	call := strings.Join(runner.calls[0], "\x00")
	for _, want := range []string{"--certificate", "--signature"} {
		if !strings.Contains(call, want) {
			t.Errorf("cosign args missing %q; got %v", want, runner.calls[0])
		}
	}
	for _, notWant := range []string{"--bundle", "--trusted-root", "--new-bundle-format"} {
		if strings.Contains(call, notWant) {
			t.Errorf("cosign args must not contain %q for old-format bundle; got %v", notWant, runner.calls[0])
		}
	}
}

func TestIsNewFormatBundle(t *testing.T) {
	dir := t.TempDir()
	newBundle := filepath.Join(dir, "new.bundle")
	if err := os.WriteFile(newBundle, []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldBundle := filepath.Join(dir, "old.bundle")
	if err := os.WriteFile(oldBundle, []byte(`{"base64Signature":"eA","cert":"eQ","rekorBundle":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.bundle")
	if err := os.WriteFile(garbage, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "new format", path: newBundle, want: true},
		{name: "old format", path: oldBundle},
		{name: "invalid json", path: garbage},
		{name: "missing file", path: filepath.Join(dir, "does-not-exist.bundle")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNewFormatBundle(tt.path); got != tt.want {
				t.Errorf("isNewFormatBundle(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDownloadArtifactsFetchesSidecarsAlongsideBundle(t *testing.T) {
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	archName := fmt.Sprintf("caddy-analyzer_0.7.2_%s_%s%s", runtime.GOOS, runtime.GOARCH, ext)
	sum := strings.Repeat("ab", 32)
	bodies := map[string]string{
		"/checksums.txt":        sum + "  " + archName + "\n",
		"/checksums.txt.pem":    "pem",
		"/checksums.txt.sig":    "sig",
		"/checksums.txt.bundle": `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`,
		"/trusted_root.json":    "{}",
		"/" + archName:          "archive-bytes",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, b)
	}))
	defer srv.Close()
	asset := func(name string) Asset { return Asset{Name: name, URL: srv.URL + "/" + name} }

	t.Run("with bundle", func(t *testing.T) {
		rel := &Release{Tag: "v0.7.2", Assets: []Asset{
			asset("checksums.txt"), asset("checksums.txt.pem"), asset("checksums.txt.sig"),
			asset("checksums.txt.bundle"), asset("trusted_root.json"), asset(archName),
		}}
		dir := t.TempDir()
		sums, archivePath, err := downloadArtifacts(context.Background(), srv.Client(), rel, dir)
		if err != nil {
			t.Fatalf("downloadArtifacts: %v", err)
		}
		for _, name := range []string{"checksums.txt", "checksums.txt.pem", "checksums.txt.sig", "checksums.txt.bundle", "trusted_root.json", archName} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Errorf("expected staged %s: %v", name, err)
			}
		}
		if sums[archName] != sum {
			t.Errorf("sums[%q] = %q, want %q", archName, sums[archName], sum)
		}
		if filepath.Base(archivePath) != archName {
			t.Errorf("archive = %q, want %q", archivePath, archName)
		}
	})

	t.Run("without bundle", func(t *testing.T) {
		rel := &Release{Tag: "v0.7.1", Assets: []Asset{
			asset("checksums.txt"), asset("checksums.txt.pem"), asset("checksums.txt.sig"), asset(archName),
		}}
		dir := t.TempDir()
		if _, _, err := downloadArtifacts(context.Background(), srv.Client(), rel, dir); err != nil {
			t.Fatalf("downloadArtifacts: %v", err)
		}
		for _, name := range []string{"checksums.txt", "checksums.txt.pem", "checksums.txt.sig"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Errorf("expected staged %s: %v", name, err)
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "checksums.txt.bundle")); !os.IsNotExist(err) {
			t.Error("bundle must not be staged when the release has none")
		}
	})
}

func TestVerifyChecksumsSignatureFailsClosed(t *testing.T) {
	runner := &recordingRunner{err: errors.New("exit status 1: no matching certificate")}
	err := VerifyChecksumsSignature(context.Background(), runner, "cosign", "/t", DefaultRepo)
	if err == nil {
		t.Fatal("verification failure must return an error (fail closed)")
	}
	if !strings.Contains(err.Error(), "FAILED") {
		t.Errorf("error should make failure explicit, got: %v", err)
	}
}

func TestFindCosignFailClosed(t *testing.T) {
	if _, err := FindCosign(); err == nil && os.Getenv("CI_COSIGN_PRESENT") == "" {
		// cosign is usually absent in CI/dev shells; when present this test
		// simply exercises the happy path of LookPath.
		t.Logf("cosign not in PATH: fail-closed path confirmed (%v)", err)
	}
}

func TestCheckWritable(t *testing.T) {
	dir := t.TempDir()
	if err := CheckWritable(dir); err != nil {
		t.Fatalf("writable dir rejected: %v", err)
	}
	// A read-only directory must produce an actionable error. Skip on
	// Windows where directory chmod does not restrict writes.
	if runtime.GOOS == "windows" {
		t.Skip("directory chmod does not restrict writes on windows")
	}
	if runningAsRoot() {
		t.Skip("running as root: read-only dir check not meaningful")
	}
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(roDir, 0o700) }()
	if err := CheckWritable(roDir); err == nil {
		t.Fatal("unwritable dir accepted")
	} else if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("permission error should suggest sudo/--install-dir, got: %v", err)
	}
}

func TestReplaceBinaryPosixAtomicSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix rename path")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "caddy-analyze")
	newBin := filepath.Join(dir, "staged-caddy-analyze")

	old := []byte("#!/bin/sh\necho v1\n")
	if err := os.WriteFile(target, old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newBin, []byte("#!/bin/sh\necho v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ReplaceBinary(newBin, target); err != nil {
		t.Fatalf("replace failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("v2")) {
		t.Errorf("target not replaced, contains: %s", got)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode not preserved from old binary: %v", info.Mode().Perm())
	}
	if _, err := os.Stat(newBin); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staged file should have been consumed by rename, stat err: %v", err)
	}
}

func TestExtractBinaryTarGz(t *testing.T) {
	dir := t.TempDir()
	archive := buildTarGzFixture(t, dir)

	binPath, err := ExtractBinary(archive, "linux", dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	data, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "binary-payload" {
		t.Errorf("wrong payload extracted: %q", data)
	}
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
		t.Errorf("extracted binary not executable: %v", info.Mode())
	}
}

func TestExtractBinaryZip(t *testing.T) {
	dir := t.TempDir()
	archive := buildZipFixture(t, dir)

	binPath, err := ExtractBinary(archive, "windows", dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	data, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "binary-payload" {
		t.Errorf("wrong payload extracted: %q", data)
	}
}

func TestExtractBinaryMissingEntry(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "README.txt", Mode: 0o644, Size: 4})
	_, _ = tw.Write([]byte("read"))
	_ = tw.Close()
	_ = gz.Close()
	archive := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractBinary(archive, "linux", dir); err == nil {
		t.Fatal("missing binary entry must error")
	}
}

func buildTarGzFixture(t *testing.T, dir string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := "binary-payload"
	for _, h := range []*tar.Header{
		{Name: "caddy-analyzer_0.5.0_linux_amd64/README.txt", Mode: 0o644, Size: int64(len(body))},
		{Name: "caddy-analyzer_0.5.0_linux_amd64/caddy-analyze", Mode: 0o755, Size: int64(len(body))},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fixture.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildZipFixture(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "fixture.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("caddy-analyzer_0.5.0_windows_amd64/caddy-analyze.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("binary-payload")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func runningAsRoot() bool {
	return os.Geteuid() == 0
}
