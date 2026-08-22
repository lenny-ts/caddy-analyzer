package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Options configures one update run.
type Options struct {
	Repo       string        // GitHub slug; DefaultRepo when empty.
	CurrentVer string        // running version, e.g. cmd.Version ("0.5.0").
	TargetVer  string        // pinned release from --version ("v0.4.0"); "" = latest.
	CheckOnly  bool          // --check: report availability only.
	Force      bool          // --force: reinstall / allow downgrade.
	InstallDir string        // --install-dir: replace <dir>/binary instead of the running file.
	HTTPClient *http.Client  // injectable for tests; default with sane timeout.
	Runner     CommandRunner // injectable cosign runner; ExecRunner by default.
	Stdout     io.Writer     // progress and results (defaults to os.Stdout).
	Stderr     io.Writer     // diagnostics (defaults to os.Stderr).
}

func (o *Options) fill() {
	if o.Repo == "" {
		o.Repo = DefaultRepo
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Minute}
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
}

// Run performs the full update flow. A nil return means success OR a
// benign no-op; every error path leaves the running binary untouched —
// verification happens strictly before any replacement attempt.
func Run(ctx context.Context, opts *Options) error {
	opts.fill()

	rel, err := FetchRelease(ctx, opts.HTTPClient, opts.Repo, opts.TargetVer)
	if err != nil {
		// Rate-limited or offline during --check: degrade to the last
		// successful check instead of failing hard.
		if opts.CheckOnly {
			if cached := readCache(); cached != nil {
				fmt.Fprintf(opts.Stderr, "warning: %v\nusing cached release info from %s\n",
					err, cached.CheckedAt.Format(time.RFC3339))
				return reportAvailability(opts, currentLabel(opts.CurrentVer), cached.Tag)
			}
		}
		return err
	}
	saveCache(rel.Tag)

	cmp := CompareVersions(opts.CurrentVer, rel.Tag)

	if opts.CheckOnly {
		return reportAvailability(opts, currentLabel(opts.CurrentVer), rel.Tag)
	}

	if cmp == 0 && !opts.Force {
		fmt.Fprintf(opts.Stdout, "already running %s — nothing to do (use --force to reinstall)\n", rel.Tag)
		return nil
	}
	if cmp > 0 && !opts.Force {
		return fmt.Errorf("installed version %s is newer than release %s; refusing downgrade (use --force to install it anyway)",
			currentLabel(opts.CurrentVer), rel.Tag)
	}

	target, destDir, err := resolveTarget(opts.InstallDir)
	if err != nil {
		return err
	}
	// Fail fast on permission problems before spending bandwidth.
	if err := CheckWritable(destDir); err != nil {
		return err
	}
	// Fail closed if cosign is unavailable — never fall back to an
	// unverified download.
	cosignPath, err := FindCosign()
	if err != nil {
		return err
	}

	// Stage inside destDir so the final swap is an atomic same-filesystem rename.
	tmpDir, err := os.MkdirTemp(destDir, ".caddy-analyze-update-")
	if err != nil {
		return fmt.Errorf("create staging dir under %s: %w", destDir, err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	fmt.Fprintf(opts.Stdout, "downloading %s for %s/%s...\n", rel.Tag, runtime.GOOS, runtime.GOARCH)
	sums, archivePath, err := downloadArtifacts(ctx, opts.HTTPClient, rel, tmpDir)
	if err != nil {
		return err
	}

	if err := VerifyChecksumsSignature(ctx, opts.Runner, cosignPath, tmpDir, opts.Repo); err != nil {
		return err // fail closed: nothing has been replaced
	}
	if err := VerifyArchiveChecksum(archivePath, sums); err != nil {
		return err // fail closed
	}
	fmt.Fprintf(opts.Stdout, "verified cosign signature and SHA256 of %s\n", filepath.Base(archivePath))

	binTmp, err := ExtractBinary(archivePath, runtime.GOOS, tmpDir)
	if err != nil {
		return err
	}
	if err := ReplaceBinary(binTmp, target); err != nil {
		return err
	}

	fmt.Fprintf(opts.Stdout, "installed %s at %s\nthe running process keeps the old binary until restarted\n",
		rel.Tag, target)
	return nil
}

func currentLabel(v string) string {
	return NormalizeVersion(v)
}

// reportAvailability implements `update --check`: print current vs latest
// plus the action hint, and always succeed.
func reportAvailability(o *Options, current, latest string) error {
	switch CompareVersions(current, latest) {
	case 0:
		fmt.Fprintf(o.Stdout, "caddy-analyze is up to date (%s)\n", latest)
	case -1:
		fmt.Fprintf(o.Stdout, "update available: %s → %s\nrun `caddy-analyze update` to install it\n", current, latest)
	default:
		fmt.Fprintf(o.Stdout, "installed %s is newer than the latest published release %s\n", current, latest)
	}
	return nil
}

// resolveTarget picks what gets replaced: <installDir>/binary when set,
// otherwise the running executable itself. destDir is used as staging root.
func resolveTarget(installDir string) (target, destDir string, err error) {
	if installDir != "" {
		dir := installDir
		if abs, absErr := filepath.Abs(dir); absErr == nil {
			dir = abs
		}
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return "", "", fmt.Errorf("create install dir: %w", mkErr)
		}
		return filepath.Join(dir, BinaryName(runtime.GOOS)), dir, nil
	}
	exe, err := ExecutablePath()
	if err != nil {
		return "", "", err
	}
	return exe, filepath.Dir(exe), nil
}

// downloadArtifacts fetches checksums.txt and its .pem/.sig sidecars plus
// the platform archive into dir. It returns the parsed manifest and the
// staged archive path.
func downloadArtifacts(ctx context.Context, client *http.Client, rel *Release, dir string) (map[string]string, string, error) {
	for _, name := range [...]string{"checksums.txt", "checksums.txt.pem", "checksums.txt.sig"} {
		a, err := FindAsset(rel, name)
		if err != nil {
			return nil, "", fmt.Errorf("release %s lacks verification material: %w", rel.Tag, err)
		}
		if _, err := fetchNamed(ctx, client, *a, dir); err != nil {
			return nil, "", err
		}
	}
	archive, err := SelectAsset(rel.Assets, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, "", err
	}
	archivePath, err := fetchNamed(ctx, client, *archive, dir)
	if err != nil {
		return nil, "", err
	}
	rawSums, err := os.ReadFile(filepath.Join(dir, "checksums.txt")) // #nosec G304 -- staged by us from the verified download flow
	if err != nil {
		return nil, "", fmt.Errorf("read checksums.txt: %w", err)
	}
	return ParseChecksums(string(rawSums)), archivePath, nil
}

// fetchNamed downloads an asset into dir under its own base name so the
// cosign arguments and checksum lookups use stable, predictable paths.
func fetchNamed(ctx context.Context, client *http.Client, a Asset, dir string) (string, error) {
	name := filepath.Base(a.Name)
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, os.PathSeparator) {
		return "", fmt.Errorf("invalid asset name %q", a.Name)
	}
	tmp, err := DownloadTo(ctx, client, a.URL, dir)
	if err != nil {
		return "", err
	}
	final := filepath.Join(dir, name)
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("stage %s: %w", name, err)
	}
	return final, nil
}

type checkCache struct {
	Tag       string    `json:"tag"`
	CheckedAt time.Time `json:"checked_at"`
}

// cachePath is best-effort state used only to soften GitHub API rate
// limits during `--check`.
func cachePath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "caddy-analyzer", "update-check.json"), nil
}

func readCache() *checkCache {
	p, err := cachePath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var c checkCache
	if json.Unmarshal(data, &c) != nil || c.Tag == "" {
		return nil
	}
	return &c
}

func saveCache(tag string) {
	p, err := cachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return
	}
	data, err := json.Marshal(checkCache{Tag: tag, CheckedAt: time.Now()})
	if err != nil {
		return
	}
	_ = os.WriteFile(p, data, 0o600)
}
