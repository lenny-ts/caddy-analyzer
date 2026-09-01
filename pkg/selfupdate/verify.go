package selfupdate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// CommandRunner executes external programs (cosign). Tests replace it to
// record invocations or simulate failures.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

// ExecRunner shells out to real binaries.
type ExecRunner struct{}

// Run executes name with args, forwarding output so the user sees cosign's
// own diagnostics when verification fails.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// FindCosign locates the cosign binary. Verification is fail closed: a
// missing cosign aborts the update instead of falling back to an
// unverified download.
func FindCosign() (string, error) {
	path, err := exec.LookPath("cosign")
	if err != nil {
		return "", fmt.Errorf("cosign binary not found in PATH: refusing to update without signature verification; install it first (see https://github.com/sigstore/cosign#installation)")
	}
	return path, nil
}

// certIdentityRegexp builds the Sigstore certificate identity constraint
// for keyless signing from this repository's release workflow. Anchored to
// the workflow path and tag refs so only certificates minted by
// .github/workflows/release.yml in the target repo verify.
func certIdentityRegexp(repo string) string {
	wf := "https://github.com/" + repo + "/.github/workflows/release.yml@refs/tags/"
	return "^" + regexp.QuoteMeta(wf)
}

// oidcIssuer is the GitHub Actions token issuer embedded in Fulcio certs.
const oidcIssuer = "https://token.actions.githubusercontent.com"

// VerifyChecksumsSignature runs `cosign verify-blob` on the downloaded
// checksums manifest. New releases use a Sigstore bundle and trusted root;
// older releases are verified using certificate and signature sidecars.
func VerifyChecksumsSignature(ctx context.Context, runner CommandRunner, cosignPath, dir, repo string) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	bundle := filepath.Join(dir, "checksums.txt.bundle")
	args := []string{"verify-blob"}
	if _, err := os.Stat(bundle); err == nil {
		trustedRoot := filepath.Join(dir, "trusted_root.json")
		if _, err := os.Stat(trustedRoot); err != nil {
			return fmt.Errorf("cosign bundle is present but trusted root is unavailable: %w", err)
		}
		args = append(args, "--bundle", bundle, "--trusted-root", trustedRoot)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect cosign bundle: %w", err)
	} else {
		args = append(args, "--certificate", filepath.Join(dir, "checksums.txt.pem"), "--signature", filepath.Join(dir, "checksums.txt.sig"))
	}
	args = append(args, "--certificate-identity-regexp", certIdentityRegexp(repo), "--certificate-oidc-issuer", oidcIssuer, filepath.Join(dir, "checksums.txt"))
	if err := runner.Run(ctx, cosignPath, args...); err != nil {
		return fmt.Errorf("cosign verification FAILED: the download will not be installed (%w)", err)
	}
	return nil
}

// ParseChecksums parses a sha256sum-style manifest ("digest  filename")
// into a filename → digest map. Basenames are used as keys so entries are
// matched regardless of any directory prefix.
func ParseChecksums(content string) map[string]string {
	sums := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || len(fields[0]) != 64 {
			continue
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			continue
		}
		sums[filepath.Base(fields[1])] = strings.ToLower(fields[0])
	}
	return sums
}

// FileSHA256 computes the hex SHA256 of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from our own temp dir
	if err != nil {
		return "", fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", filepath.Base(path), err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyArchiveChecksum recomputes the archive digest and compares it
// (constant-time) against the signed manifest entry. Defense in depth:
// even if cosign were bypassed, a tampered archive cannot match the
// signed hash.
func VerifyArchiveChecksum(archivePath string, sums map[string]string) error {
	name := filepath.Base(archivePath)
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("archive %q is not listed in the signed checksums.txt", name)
	}
	got, err := FileSHA256(archivePath)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("SHA256 mismatch for %q: expected %s, got %s — possible tampering, aborting", name, want, got)
	}
	return nil
}
