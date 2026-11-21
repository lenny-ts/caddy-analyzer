package reader

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type LogReader interface {
	Read(ctx context.Context) (<-chan string, error)
	Name() string
	// Err reports a streaming error after the lines channel has been drained.
	Err() error
}

// MaxLineSize is the largest log line accepted from any source. A longer line
// is skipped and reported; it never aborts the rest of the source.
const MaxLineSize = 16 * 1024 * 1024

// SkipCounter is implemented by readers that drop lines longer than
// MaxLineSize, so callers can surface the count in the report.
type SkipCounter interface {
	SkippedLines() int64
}

// skipCounter counts the over-long lines a reader dropped.
type skipCounter struct {
	skipped atomic.Int64
}

// SkippedLines reports how many lines longer than MaxLineSize were dropped.
func (c *skipCounter) SkippedLines() int64 { return c.skipped.Load() }

func (c *skipCounter) skip(source string, size int64) {
	c.skipped.Add(1)
	fmt.Fprintf(os.Stderr, "warning: skipped a %d-byte line in %s (limit is %d bytes)\n", size, source, MaxLineSize)
}

// normalizeLine drops a trailing "\r" and any leading NUL bytes. A log file
// truncated in place while its writer keeps its offset (logrotate's
// copytruncate) starts with a sparse hole of NULs glued to the next record.
func normalizeLine(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\r"))
	return bytes.TrimLeft(b, "\x00")
}

// forEachLine calls fn for every line read from r, without the line
// terminator. A line whose content is longer than max bytes is discarded up to
// its newline and passed to onSkip with its length; reading then continues
// with the next line. Leading NUL bytes do not count toward max, so a record
// written after a sparse hole is still delivered. Only read errors and errors
// returned by fn stop the iteration.
func forEachLine(r io.Reader, max int, fn func(string) error, onSkip func(int64)) error {
	var line boundedLine
	return line.read(context.Background(), bufio.NewReaderSize(r, 64*1024), max, true, fn, onSkip)
}

type boundedLine struct {
	content []byte
	raw     int64 // bytes consumed so far, newline excluded
	tooLong bool
}

// read drains through EOF. When following, EOF is temporary: retain only the
// bounded partial line and resume at the current offset on the next poll.
func (l *boundedLine) read(ctx context.Context, br *bufio.Reader, max int, final bool, fn func(string) error, onSkip func(int64)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, err := br.ReadSlice('\n')
		eof := errors.Is(err, io.EOF)
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !eof {
			return err
		}
		complete := err == nil
		data := chunk
		if complete {
			data = chunk[:len(chunk)-1]
		}
		l.raw += int64(len(data))
		if !l.tooLong {
			if len(l.content) == 0 {
				data = bytes.TrimLeft(data, "\x00")
			}
			if len(l.content)+len(data) > max+1 {
				// max+1 leaves room for a trailing "\r" that normalizeLine drops.
				l.tooLong = true
				l.content = l.content[:0]
			} else {
				l.content = append(l.content, data...)
			}
		}
		if complete || (final && eof && l.raw > 0) {
			if !l.tooLong {
				if content := normalizeLine(l.content); len(content) > max {
					l.tooLong = true
				} else if ferr := fn(string(content)); ferr != nil {
					return ferr
				}
			}
			if l.tooLong && onSkip != nil {
				onSkip(l.raw)
			}
			*l = boundedLine{content: l.content[:0]}
		}
		if eof {
			return nil
		}
	}
}

// CountLines counts the lines forEachLine would deliver from r, leaving out
// lines longer than MaxLineSize.
func CountLines(r io.Reader) (int64, error) {
	var n int64
	err := forEachLine(r, MaxLineSize, func(string) error {
		n++
		return nil
	}, nil)
	return n, err
}

// sendLine delivers one line unless ctx is done first.
func sendLine(ctx context.Context, out chan<- string, line string) error {
	select {
	case out <- line:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func FromSource(src types.LogSource) LogReader {
	return fromSource(src, false)
}

func FromSourceFollow(src types.LogSource) LogReader {
	return fromSource(src, true)
}

func fromSource(src types.LogSource, follow bool) LogReader {
	switch src.Type {
	case types.SourceStdin:
		return &StdinReader{}
	case types.SourceFile:
		return &FileReader{paths: expandPaths(src.Path), follow: follow}
	case types.SourceDocker:
		return &DockerReader{container: src.Path, follow: follow}
	case types.SourceK8s:
		return &K8sReader{pod: src.Path, namespace: src.Namespace, follow: follow}
	case types.SourceJournalctl:
		return &JournalctlReader{unit: src.Path, follow: follow}
	default:
		return &FileReader{paths: expandPaths(src.Path), follow: follow}
	}
}

func ParseSource(raw string) types.LogSource {
	if raw == "-" {
		return types.LogSource{Type: types.SourceStdin}
	}

	parts := strings.SplitN(raw, "://", 2)
	if len(parts) == 2 {
		switch parts[0] {
		case "docker":
			return types.LogSource{Type: types.SourceDocker, Path: parts[1]}
		case "k8s":
			return types.LogSource{Type: types.SourceK8s, Path: parts[1]}
		case "journalctl":
			return types.LogSource{Type: types.SourceJournalctl, Path: parts[1]}
		}
	}

	return types.LogSource{Type: types.SourceFile, Path: raw}
}

func expandPaths(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return []string{pattern}
	}
	return matches
}

func newLineChannel() chan string {
	return make(chan string, 1000)
}

type StdinReader struct {
	skipCounter
	err error
}

func (r *StdinReader) Err() error { return r.err }

func (r *StdinReader) Name() string { return "stdin" }

func (r *StdinReader) Read(ctx context.Context) (<-chan string, error) {
	// Defense-in-depth: resolveSources already refuses the stdin fallback
	// when stdin is a TTY, but a caller can still construct a StdinReader
	// directly (e.g. explicit "-"). Reading from a TTY with bufio.Scanner
	// blocks forever with no prompt, so reject it here with a clear error.
	if isTerminal() {
		return nil, fmt.Errorf("stdin is a terminal; pipe log lines (e.g. `tail -f access.log | caddy-analyze -`) or specify a file/docker://k8s://journalctl:// source")
	}
	out := newLineChannel()
	go func() {
		defer close(out)
		fmt.Fprintln(os.Stderr, "reading log lines from stdin... (Ctrl+D to end)")
		err := forEachLine(os.Stdin, MaxLineSize, func(line string) error {
			return sendLine(ctx, out, line)
		}, func(n int64) { r.skip(r.Name(), n) })
		if err != nil && !errors.Is(err, context.Canceled) {
			r.err = fmt.Errorf("read stdin: %w", err)
			printReadError(r.Name(), err)
		}
	}()
	return out, nil
}

type FileReader struct {
	skipCounter
	paths  []string
	follow bool
	err    error
}

func (r *FileReader) Err() error { return r.err }

func (r *FileReader) Name() string {
	if len(r.paths) == 1 {
		return r.paths[0]
	}
	return fmt.Sprintf("%d files", len(r.paths))
}

func (r *FileReader) Read(ctx context.Context) (<-chan string, error) {
	// Validate up front that every input exists, but do not abort the whole
	// read when only some paths are missing: process the available ones and
	// record the error so callers can surface a non-zero exit code. Use
	// os.Stat instead of open+close to avoid blocking twice on FIFOs.
	var once sync.Once
	recordError := func(path string, err error) {
		if errors.Is(err, context.Canceled) {
			return
		}
		printReadError(path, err)
		once.Do(func() { r.err = err })
	}
	r.err = nil
	available := make([]string, 0, len(r.paths))
	for _, path := range r.paths {
		if _, err := os.Stat(path); err != nil {
			recordError(path, err)
			continue
		}
		available = append(available, path)
	}
	if len(available) == 0 && r.err != nil {
		return nil, r.err
	}

	out := newLineChannel()
	if r.follow && len(available) > 1 {
		// In follow mode with multiple files, read them concurrently
		// so all files are tailed in parallel. Without this, the first
		// file blocks forever and the rest are never read.
		var wg sync.WaitGroup
		for _, path := range available {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				if err := readFileAndFollow(ctx, p, out, &r.skipCounter); err != nil {
					recordError(p, err)
				}
			}(path)
		}
		go func() {
			wg.Wait()
			close(out)
		}()
		return out, nil
	}
	go func() {
		defer close(out)
		for _, path := range available {
			if r.follow {
				if err := readFileAndFollow(ctx, path, out, &r.skipCounter); err != nil {
					recordError(path, err)
				}
			} else {
				if err := readFileLines(ctx, path, out, &r.skipCounter); err != nil {
					recordError(path, err)
				}
			}
		}
	}()
	return out, nil
}

func readFileLines(ctx context.Context, path string, out chan<- string, skips *skipCounter) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return forEachLine(f, MaxLineSize, func(line string) error {
		return sendLine(ctx, out, line)
	}, func(n int64) { skips.skip(path, n) })
}

func readFileAndFollow(ctx context.Context, path string, out chan<- string, skips *skipCounter) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	initialInfo, err := f.Stat()
	if err != nil {
		return err
	}

	buffer := bufio.NewReaderSize(f, 64*1024)
	var pending boundedLine
	drain := func() error {
		return pending.read(ctx, buffer, MaxLineSize, false, func(line string) error {
			return sendLine(ctx, out, line)
		}, func(n int64) { skips.skip(path, n) })
	}
	if err := drain(); err != nil {
		return err
	}

	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			if !os.SameFile(initialInfo, info) || info.Size() < pos {
				if err := f.Close(); err != nil {
					return err
				}
				f, err = os.Open(path)
				if err != nil {
					return err
				}
				initialInfo, err = f.Stat()
				if err != nil {
					return err
				}
				pending = boundedLine{}
				buffer.Reset(f)
			} else if info.Size() == pos {
				continue
			}

			if err := drain(); err != nil {
				return err
			}

			pos, err = f.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
		}
	}
}

type DockerReader struct {
	skipCounter
	container string
	follow    bool
	err       error
}

func (r *DockerReader) Err() error { return r.err }

func (r *DockerReader) Name() string { return "docker:" + r.container }

func (r *DockerReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel()
	args := []string{"logs"}
	if r.follow {
		args = append(args, "-f")
		if !isTerminal() {
			args = append(args, "--tail=all")
		}
	} else {
		args = append(args, "--tail=all")
	}
	args = append(args, r.container)

	cmd := exec.CommandContext(ctx, "docker", args...)
	return execLines(ctx, cmd, out, r.Name(), &r.skipCounter, &r.err)
}

type K8sReader struct {
	skipCounter
	pod       string
	namespace string
	follow    bool
	err       error
}

func (r *K8sReader) Err() error { return r.err }

func (r *K8sReader) Name() string {
	ns := r.namespace
	if ns == "" {
		ns = "default"
	}
	return fmt.Sprintf("k8s:%s (ns:%s)", r.pod, ns)
}

func (r *K8sReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel()
	args := []string{"logs", "--tail=-1"}
	if r.follow {
		args = append(args, "--follow")
	}
	if r.namespace != "" {
		args = append(args, "-n", r.namespace)
	}
	args = append(args, r.pod)

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	return execLines(ctx, cmd, out, r.Name(), &r.skipCounter, &r.err)
}

type JournalctlReader struct {
	skipCounter
	unit   string
	follow bool
	err    error
}

func (r *JournalctlReader) Err() error { return r.err }

func (r *JournalctlReader) Name() string { return "journalctl:" + r.unit }

func (r *JournalctlReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel()
	args := []string{"-u", r.unit, "--output=cat"}
	if r.follow {
		args = append(args, "--follow")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	return execLines(ctx, cmd, out, r.Name(), &r.skipCounter, &r.err)
}

func execLines(ctx context.Context, cmd *exec.Cmd, out chan string, name string, skips *skipCounter, errPtr *error) (<-chan string, error) {
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}

	go func() {
		_ = cmd.Wait()
		_ = pw.Close()
	}()

	go func() {
		defer close(out)
		defer func() { _ = pr.Close() }()
		err := forEachLine(pr, MaxLineSize, func(line string) error {
			return sendLine(ctx, out, line)
		}, func(n int64) { skips.skip(name, n) })
		if err != nil && ctx.Err() != nil {
			_ = cmd.Process.Kill()
			return
		}
		if err != nil {
			printReadError(name, err)
		}
		if errPtr != nil {
			*errPtr = err
		}
	}()

	return out, nil
}

func isTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func printReadError(path string, err error) {
	// Suppress "context canceled" errors — these are normal during graceful shutdown.
	if ctxErr := context.Canceled; errors.Is(err, ctxErr) {
		return
	}
	if os.IsPermission(err) || strings.Contains(err.Error(), "permission denied") {
		fmt.Fprintf(os.Stderr, "error: permission denied reading %s\n", path)
		fmt.Fprintf(os.Stderr, "💡 Hint: Run with sudo: sudo caddy-analyze %s\n", path)
		fmt.Fprintf(os.Stderr, "💡 Or add your user to the caddy group: sudo usermod -aG caddy $USER\n")
	} else {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
	}
}
