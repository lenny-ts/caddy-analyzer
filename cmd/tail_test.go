package cmd

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestTailPathStyleUsesTerminalForeground(t *testing.T) {
	if !styleTailPath.GetBold() {
		t.Fatal("path must be bold")
	}
	if _, ok := styleTailPath.GetForeground().(lipgloss.NoColor); !ok {
		t.Fatalf("path foreground = %v, want terminal default", styleTailPath.GetForeground())
	}
}
