package reader

import (
	"bufio"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestFollowKeepsOnlyBoundedPartialLine(t *testing.T) {
	const max = 64
	var pending boundedLine
	var lines []string
	var skipped []int64
	drain := func(chunk string) {
		t.Helper()
		err := pending.read(context.Background(), bufio.NewReader(strings.NewReader(chunk)), max, false,
			func(line string) error { lines = append(lines, line); return nil },
			func(n int64) { skipped = append(skipped, n) })
		if err != nil {
			t.Fatal(err)
		}
	}
	drain(strings.Repeat("x", 2*max))
	if cap(pending.content) > max+1 || len(lines) != 0 || len(skipped) != 0 {
		t.Fatalf("oversized partial line was buffered or reported at temporary EOF")
	}
	drain("tail\nok\npar")
	drain("tial\n")
	if !reflect.DeepEqual(skipped, []int64{2*max + 4}) || !reflect.DeepEqual(lines, []string{"ok", "partial"}) {
		t.Fatalf("lines = %q, skipped = %v", lines, skipped)
	}
}
