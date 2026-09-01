package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestBarDisabledOnNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	bar := New(&buf, 100, "Test")
	bar.Add(50)
	bar.Done()
	if buf.Len() != 0 {
		t.Fatalf("expected no output on non-terminal, got %q", buf.String())
	}
}

func TestBarDeterministic(t *testing.T) {
	bar := &Bar{
		w:       &bytes.Buffer{},
		enabled: true,
		total:   100,
		label:   "Test",
	}
	bar.draw()
	output := bar.w.(*bytes.Buffer).String()
	if !strings.Contains(output, "0/100") {
		t.Fatalf("expected 0/100 in output, got %q", output)
	}
	if !strings.Contains(output, "(0%)") {
		t.Fatalf("expected (0%%) in output, got %q", output)
	}

	bar.current = 50
	bar.draw()
	output = bar.w.(*bytes.Buffer).String()
	if !strings.Contains(output, "50/100") {
		t.Fatalf("expected 50/100 in output, got %q", output)
	}
	if !strings.Contains(output, "(50%)") {
		t.Fatalf("expected (50%%) in output, got %q", output)
	}
}

func TestBarIndeterminate(t *testing.T) {
	bar := &Bar{
		w:       &bytes.Buffer{},
		enabled: true,
		total:   0,
		label:   "Test",
	}
	bar.current = 42
	bar.draw()
	output := bar.w.(*bytes.Buffer).String()
	if !strings.Contains(output, "42 entries") {
		t.Fatalf("expected '42 entries' in output, got %q", output)
	}
}

func TestBarIndeterminateFrameDoesNotDependOnCount(t *testing.T) {
	bar := &Bar{
		w:       &bytes.Buffer{},
		enabled: true,
		total:   0,
		label:   "Test",
	}
	bar.current = 9
	bar.draw()
	first := bar.w.(*bytes.Buffer).String()
	bar.current = 18
	bar.draw()
	second := bar.w.(*bytes.Buffer).String()

	if strings.HasSuffix(first, "⠋ 9 entries") && strings.HasSuffix(second, "⠋ 18 entries") {
		t.Fatal("spinner frame repeated when entry count advanced by one full cycle")
	}
}

func TestBarDonePrintsNewline(t *testing.T) {
	bar := &Bar{
		w:       &bytes.Buffer{},
		enabled: true,
		total:   10,
		label:   "Test",
	}
	bar.current = 10
	bar.Done()
	output := bar.w.(*bytes.Buffer).String()
	if !strings.HasSuffix(output, "\n") {
		t.Fatalf("expected output to end with newline, got %q", output)
	}
}

func TestBarAddNoOpWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	bar := New(&buf, 100, "Test")
	bar.Add(50)
	bar.Done()
	if buf.Len() != 0 {
		t.Fatalf("expected no output when disabled, got %q", buf.String())
	}
}

func TestBarAbortClearsLine(t *testing.T) {
	bar := &Bar{
		w:       &bytes.Buffer{},
		enabled: true,
		total:   100,
		label:   "Test",
	}
	bar.Abort()
	output := bar.w.(*bytes.Buffer).String()
	if !strings.Contains(output, "\r") {
		t.Fatalf("expected carriage return in abort output, got %q", output)
	}
}
