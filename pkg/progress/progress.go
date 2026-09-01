package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	refreshInterval = 100 * time.Millisecond
	barWidth        = 30
)

// Bar is a simple progress bar that writes to an io.Writer (typically os.Stderr).
// It is safe for concurrent use — all methods are no-ops if the bar is disabled.
type Bar struct {
	mu       sync.Mutex
	w        io.Writer
	enabled  bool
	total    int64
	current  int64
	frame    int
	lastDraw time.Time
	done     bool
	label    string
	stop     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

// New creates a progress bar writing to w. The bar is only enabled if w is
// a terminal (os.Stderr connected to a TTY). total is the expected number
// of items; if 0, an indeterminate spinner is shown.
func New(w io.Writer, total int64, label string) *Bar {
	enabled := false
	if f, ok := w.(*os.File); ok {
		info, err := f.Stat()
		if err == nil && info.Mode()&os.ModeCharDevice != 0 {
			enabled = true
		}
	}
	b := &Bar{
		w:       w,
		enabled: enabled,
		total:   total,
		label:   label,
	}
	if enabled && total <= 0 {
		b.stop = make(chan struct{})
		b.stopped = make(chan struct{})
		go b.animate()
	}
	return b
}

func (b *Bar) animate() {
	defer close(b.stopped)
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.mu.Lock()
			if !b.done {
				b.lastDraw = time.Now()
				b.draw()
			}
			b.mu.Unlock()
		case <-b.stop:
			return
		}
	}
}

func (b *Bar) stopAnimation() {
	if b.stop == nil {
		return
	}
	b.stopOnce.Do(func() { close(b.stop) })
	<-b.stopped
}

// Add increments the progress counter by n and redraws if the refresh
// interval has elapsed since the last draw.
func (b *Bar) Add(n int) {
	if !b.enabled {
		return
	}
	b.mu.Lock()
	b.current += int64(n)
	now := time.Now()
	if now.Sub(b.lastDraw) >= refreshInterval {
		b.lastDraw = now
		b.draw()
	}
	b.mu.Unlock()
}

// Done finalizes the bar, drawing a 100% state and a newline.
func (b *Bar) Done() {
	if !b.enabled {
		return
	}
	b.stopAnimation()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = true
	b.draw()
	fmt.Fprintln(b.w)
}

// Abort clears the progress bar line without drawing a final state.
func (b *Bar) Abort() {
	if !b.enabled {
		return
	}
	b.stopAnimation()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = true
	fmt.Fprintf(b.w, "\r%s\r", strings.Repeat(" ", 80))
}

func (b *Bar) draw() {
	if b.total > 0 {
		b.drawDeterministic()
	} else {
		b.drawIndeterminate()
	}
}

func (b *Bar) drawDeterministic() {
	pct := float64(b.current) / float64(b.total)
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Fprintf(b.w, "\r%s [%s] %d/%d (%.0f%%)", b.label, bar, b.current, b.total, pct*100)
}

func (b *Bar) drawIndeterminate() {
	// Spinner animation
	chars := `⠋⠙⠹⠸⠴⠦⠧⠇⠏`
	idx := b.frame % len(chars)
	b.frame++
	fmt.Fprintf(b.w, "\r%s %c %d entries", b.label, chars[idx], b.current)
}
