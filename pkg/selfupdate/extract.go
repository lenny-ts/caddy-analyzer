package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ExtractBinary pulls the platform binary out of the downloaded release
// archive into destDir and returns its path. Archives produced by
// GoReleaser keep the binary at their root; nested layouts are matched by
// base name so future packaging tweaks stay compatible.
func ExtractBinary(archivePath, goos, destDir string) (string, error) {
	switch {
	case strings.HasSuffix(archivePath, ".zip"):
		return extractFromZip(archivePath, goos, destDir)
	default:
		return extractFromTarGz(archivePath, goos, destDir)
	}
}

func extractFromTarGz(archivePath, goos, destDir string) (string, error) {
	f, err := os.Open(archivePath) // #nosec G304 -- path comes from our own temp dir
	if err != nil {
		return "", fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	want := BinaryName(goos)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("binary %q not found inside archive", want)
		}
		if err != nil {
			return "", fmt.Errorf("read archive: %w", err)
		}
		if filepath.Base(hdr.Name) != want || hdr.Typeflag != tar.TypeReg {
			continue
		}
		mode := os.FileMode(0o755)
		if hdr.Mode > 0 && hdr.Mode <= 0o777 {
			mode = os.FileMode(hdr.Mode)
		}
		return writeFileFromReader(tr, destDir, want, mode)
	}
}

func extractFromZip(archivePath, goos, destDir string) (string, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = zr.Close() }()

	want := BinaryName(goos)
	for _, zf := range zr.File {
		if filepath.Base(zf.Name) != want || zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return "", fmt.Errorf("read %s from archive: %w", zf.Name, err)
		}
		mode := os.FileMode(0o755)
		if zf.Mode()&0o777 != 0 {
			mode = zf.Mode() & 0o777
		}
		path, err := writeFileFromReader(rc, destDir, want, mode)
		_ = rc.Close()
		return path, err
	}
	return "", fmt.Errorf("binary %q not found inside archive", want)
}

// writeFileFromReader streams an extracted binary into destDir under a
// temp name and makes it executable-ready before the atomic swap.
func writeFileFromReader(r io.Reader, destDir, name string, mode os.FileMode) (string, error) {
	out, err := os.CreateTemp(destDir, name+"-*")
	if err != nil {
		return "", fmt.Errorf("create temp binary: %w", err)
	}
	tmp := out.Name()
	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("extract binary: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmp, mode); err != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("chmod binary: %w", err)
		}
	}
	return tmp, nil
}
