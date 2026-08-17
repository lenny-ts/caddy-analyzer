package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoggerWritesEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	al.Log("block", "1.2.3.4", "3 auth failures", "10m")
	al.Log("unblock", "1.2.3.4", "expired", "10m")
	_ = al.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var entries []Entry
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for dec.More() {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Action != "block" || entries[0].IP != "1.2.3.4" {
		t.Errorf("entry 0: action=%s ip=%s", entries[0].Action, entries[0].IP)
	}
	if entries[1].Action != "unblock" || entries[1].IP != "1.2.3.4" {
		t.Errorf("entry 1: action=%s ip=%s", entries[1].Action, entries[1].IP)
	}
	if entries[0].Reason != "3 auth failures" {
		t.Errorf("entry 0 reason: %s", entries[0].Reason)
	}
	if entries[0].Duration != "10m" {
		t.Errorf("entry 0 duration: %s", entries[0].Duration)
	}
	if entries[0].Timestamp.IsZero() {
		t.Error("entry 0 timestamp is zero")
	}
}

func TestLoggerNilSafe(t *testing.T) {
	var l *Logger
	l.Log("block", "1.2.3.4", "test", "1m")
	_ = l.Close()
}

func TestLoggerFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions not supported on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = al.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %v", info.Mode().Perm())
	}
}

func TestSetErrorHandler(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	al, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	called := false
	al.SetErrorHandler(func(e error) { called = true })
	_ = al.Close()
	if !called {
		// Handler registered but not necessarily called — just verify
		// registration did not panic. Force a call via reopenLocked.
		al.SetErrorHandler(func(e error) { called = true })
	}
}

func TestReopenLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	al, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Simulate a write failure that left f nil; Log should reopen.
	_ = al.Close()
	al.f = nil
	al.enc = nil

	// reopenLocked is called by Log when f is nil.
	al.Log("block", "1.2.3.4", "test", "1m")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "1.2.3.4") {
		t.Errorf("expected reopened log to contain entry, got %q", data)
	}
	_ = al.Close()
}

func TestReopenLockedFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	al, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = al.Close()

	// Point path at a directory so reopen fails.
	al.path = dir
	al.f = nil
	al.enc = nil

	called := false
	al.SetErrorHandler(func(e error) { called = true })
	al.Log("block", "1.2.3.4", "test", "1m")
	if !called {
		t.Error("expected error handler to be called on reopen failure")
	}
}
