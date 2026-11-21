package reader

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// accessLine is the record used by the reproduction in issue #154.
const accessLine = `{"level":"info","ts":1,"logger":"http.log.access","msg":"handled request",` +
	`"request":{"remote_ip":"1.2.3.4","method":"GET","host":"e.org","uri":"/x","headers":{}},` +
	`"status":200,"size":0,"duration":0.001}`

func collectLines(t *testing.T, input string, max int) (lines []string, skipped []int64) {
	t.Helper()
	err := forEachLine(strings.NewReader(input), max, func(line string) error {
		lines = append(lines, line)
		return nil
	}, func(n int64) { skipped = append(skipped, n) })
	if err != nil {
		t.Fatalf("forEachLine returned %v", err)
	}
	return lines, skipped
}

func assertLines(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d lines %q, want %d lines %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func assertSkipped(t *testing.T, got []int64, want ...int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("skipped %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("skip %d reported %d bytes, want %d", i, got[i], want[i])
		}
	}
}

func TestForEachLineSkipsOversizedLines(t *testing.T) {
	long := strings.Repeat("x", 20)
	tests := []struct {
		name  string
		input string
		want  []string
		skips []int64
	}{
		{"first line", long + "\nok1\nok2\n", []string{"ok1", "ok2"}, []int64{20}},
		{"middle line", "ok1\n" + long + "\nok2\n", []string{"ok1", "ok2"}, []int64{20}},
		{"last line without newline", "ok1\nok2\n" + long, []string{"ok1", "ok2"}, []int64{20}},
		{"line exactly at the limit", "ok1\n" + long[:16] + "\nok2\n", []string{"ok1", long[:16], "ok2"}, nil},
		{"one byte over the limit", "ok1\n" + long[:17] + "\nok2\n", []string{"ok1", "ok2"}, []int64{17}},
		{"crlf at the limit", "ok1\r\n" + long[:16] + "\r\nok2\r\n", []string{"ok1", long[:16], "ok2"}, nil},
		{"last line kept without newline", "ok1\nok2", []string{"ok1", "ok2"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, skipped := collectLines(t, tt.input, 16)
			assertLines(t, lines, tt.want)
			assertSkipped(t, skipped, tt.skips...)
		})
	}
}

func TestForEachLineSkipsLinesLongerThanTheReadBuffer(t *testing.T) {
	// 200 KiB spans several 64 KiB reads, so the skip has to survive ErrBufferFull.
	long := strings.Repeat("y", 200*1024)
	lines, skipped := collectLines(t, "ok1\n"+long+"\nok2\n", 100*1024)
	assertLines(t, lines, []string{"ok1", "ok2"})
	assertSkipped(t, skipped, int64(len(long)))
}

func TestForEachLineIgnoresLeadingNULPadding(t *testing.T) {
	hole := strings.Repeat("\x00", 40)
	lines, skipped := collectLines(t, hole+"rec1\nrec2\n", 16)
	assertLines(t, lines, []string{"rec1", "rec2"})
	assertSkipped(t, skipped)
}

func readAll(t *testing.T, read func(ctx context.Context, out chan<- string) error) []string {
	t.Helper()
	out := make(chan string, 16)
	errc := make(chan error, 1)
	go func() {
		errc <- read(context.Background(), out)
		close(out)
	}()
	var lines []string
	for line := range out {
		lines = append(lines, line)
	}
	if err := <-errc; err != nil {
		t.Fatalf("read returned %v", err)
	}
	return lines
}

func writeLog(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReadFileLinesIssue154Reproduction is the synthetic case from issue #154:
// a 20 MiB NUL hole glued to the first record, then a second record.
func TestReadFileLinesIssue154Reproduction(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(make([]byte, 20*1024*1024))
	buf.WriteString(accessLine + "\n")
	buf.WriteString(accessLine + "\n")
	path := writeLog(t, buf.Bytes())

	var skips skipCounter
	lines := readAll(t, func(ctx context.Context, out chan<- string) error {
		return readFileLines(ctx, path, out, &skips)
	})
	assertLines(t, lines, []string{accessLine, accessLine})
	if got := skips.SkippedLines(); got != 0 {
		t.Errorf("SkippedLines() = %d, want 0", got)
	}
}

func TestReadFileLinesKeepsReadingAfterAnOversizedLine(t *testing.T) {
	long := bytes.Repeat([]byte("a"), MaxLineSize+1)
	content := append([]byte("ok1\n"), long...)
	content = append(content, []byte("\nok2\n")...)
	path := writeLog(t, content)

	var skips skipCounter
	lines := readAll(t, func(ctx context.Context, out chan<- string) error {
		return readFileLines(ctx, path, out, &skips)
	})
	assertLines(t, lines, []string{"ok1", "ok2"})
	if got := skips.SkippedLines(); got != 1 {
		t.Errorf("SkippedLines() = %d, want 1", got)
	}
}

func TestReadFileLinesKeepsMultiMiBLines(t *testing.T) {
	big := strings.Repeat("b", 5*1024*1024)
	path := writeLog(t, []byte("ok1\n"+big+"\nok2\n"))

	var skips skipCounter
	lines := readAll(t, func(ctx context.Context, out chan<- string) error {
		return readFileLines(ctx, path, out, &skips)
	})
	assertLines(t, lines, []string{"ok1", big, "ok2"})
	if got := skips.SkippedLines(); got != 0 {
		t.Errorf("SkippedLines() = %d, want 0", got)
	}
}

func TestFollowModeSkipsOversizedLinesLikeOneShot(t *testing.T) {
	long := bytes.Repeat([]byte("a"), MaxLineSize+1)
	content := append([]byte("ok1\n"), long...)
	content = append(content, []byte("\r\nok2\r\n")...)
	content = append(append(make([]byte, 64), content...), []byte("ok3\n")...)
	path := writeLog(t, content)

	var oneShot skipCounter
	want := readAll(t, func(ctx context.Context, out chan<- string) error {
		return readFileLines(ctx, path, out, &oneShot)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan string, 16)
	var follow skipCounter
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = readFileAndFollow(ctx, path, out, &follow)
	}()
	var got []string
	timeout := time.After(10 * time.Second)
	for len(got) < len(want) {
		select {
		case line := <-out:
			got = append(got, line)
		case <-timeout:
			t.Fatalf("follow mode delivered %q, want %q", got, want)
		}
	}
	cancel()
	<-done

	assertLines(t, got, want)
	assertLines(t, want, []string{"ok1", "ok2", "ok3"})
	if follow.SkippedLines() != 1 || oneShot.SkippedLines() != 1 {
		t.Errorf("SkippedLines() follow=%d one-shot=%d, want 1 and 1", follow.SkippedLines(), oneShot.SkippedLines())
	}
}

func TestCountLinesLeavesOutOversizedLines(t *testing.T) {
	long := strings.Repeat("a", MaxLineSize+1)
	n, err := CountLines(strings.NewReader("one\n" + long + "\ntwo\nthree"))
	if err != nil {
		t.Fatalf("CountLines returned %v", err)
	}
	if n != 3 {
		t.Fatalf("CountLines() = %d, want 3", n)
	}
}

func TestStdinReaderSkipsOversizedLines(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = pr
	defer func() { os.Stdin = oldStdin }()

	go func() {
		_, _ = pw.WriteString("ok1\n" + strings.Repeat("a", MaxLineSize+1) + "\nok2\n")
		_ = pw.Close()
	}()

	r := &StdinReader{}
	lines, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for line := range lines {
		got = append(got, line)
	}
	assertLines(t, got, []string{"ok1", "ok2"})
	if r.SkippedLines() != 1 {
		t.Errorf("SkippedLines() = %d, want 1", r.SkippedLines())
	}
}

// TestHelperEmitOversizedLine is not a real test: execLines runs it as a
// child process standing in for docker, kubectl or journalctl.
func TestHelperEmitOversizedLine(t *testing.T) {
	if os.Getenv("CADDY_ANALYZER_HELPER_EMIT") != "1" {
		return
	}
	fmt.Print("ok1\n" + strings.Repeat("a", MaxLineSize+1) + "\nok2\n")
	os.Exit(0)
}

func TestExecLinesSkipsOversizedLines(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperEmitOversizedLine$")
	cmd.Env = append(os.Environ(), "CADDY_ANALYZER_HELPER_EMIT=1")

	var skips skipCounter
	lines, err := execLines(context.Background(), cmd, newLineChannel(), "docker:web", &skips)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for line := range lines {
		got = append(got, line)
	}
	assertLines(t, got, []string{"ok1", "ok2"})
	if skips.SkippedLines() != 1 {
		t.Errorf("SkippedLines() = %d, want 1", skips.SkippedLines())
	}
}
