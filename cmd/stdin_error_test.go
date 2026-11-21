package cmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestRunOnceReportsStdinReadFailure(t *testing.T) {
	input, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	previous, noDownload := os.Stdin, flagNoAutoDL
	os.Stdin, flagNoAutoDL = input, true
	t.Cleanup(func() { os.Stdin, flagNoAutoDL = previous, noDownload })

	err = runOnceMode(context.Background(), []types.LogSource{{Type: types.SourceStdin}}, types.Filters{})
	if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("expected stdin read failure, got %v", err)
	}
}
