package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCosignChecksumsURL(t *testing.T) {
	want := "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt"
	got := cosignReleaseURL("v3.1.3") + "/" + cosignChecksums
	if got != want {
		t.Fatalf("cosign checksums URL = %q, want %q", got, want)
	}
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestVerifyCosignChecksumMatch(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cosign")
	if err := os.WriteFile(binPath, []byte("fake-cosign-binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	expected := sha256Hex(t, binPath)
	checksumPath := filepath.Join(dir, "cosign-checksums.txt")
	if err := os.WriteFile(checksumPath, []byte(expected+"  cosign\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyCosignChecksum(binPath, checksumPath); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestVerifyCosignChecksumMismatch(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cosign")
	if err := os.WriteFile(binPath, []byte("fake-cosign-binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	checksumPath := filepath.Join(dir, "cosign-checksums.txt")
	if err := os.WriteFile(checksumPath, []byte("0000000000000000000000000000000000000000000000000000000000000000  cosign\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyCosignChecksum(binPath, checksumPath); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestVerifyCosignChecksumBinaryNotInFile(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cosign")
	if err := os.WriteFile(binPath, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	checksumPath := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(checksumPath, []byte("aabb  other-binary\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyCosignChecksum(binPath, checksumPath); err == nil {
		t.Fatal("expected binary not found error")
	}
}

func TestVerifyCosignChecksumMissingChecksumFile(t *testing.T) {
	if err := verifyCosignChecksum("/nonexistent/bin", "/nonexistent/checksums"); err == nil {
		t.Fatal("expected error for missing checksums file")
	}
}

func TestVerifyCosignChecksumMissingBinary(t *testing.T) {
	dir := t.TempDir()
	checksumPath := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(checksumPath, []byte("aabb  cosign\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyCosignChecksum("/nonexistent/bin", checksumPath); err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestVerifyCosignChecksumEmptyLines(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cosign")
	if err := os.WriteFile(binPath, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	expected := sha256Hex(t, binPath)
	checksumPath := filepath.Join(dir, "checksums.txt")
	content := "\n\n" + expected + "  cosign\n\n"
	if err := os.WriteFile(checksumPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyCosignChecksum(binPath, checksumPath); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}
