package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Sink receives an audit event. Implementations must not retain the event.
type Sink interface {
	Emit(context.Context, Entry) error
}

type LoggerSink struct{ Logger *Logger }

func (s LoggerSink) Emit(_ context.Context, e Entry) error {
	if s.Logger == nil {
		return nil
	}
	s.Logger.Log(e.Action, e.IP, e.Reason, e.Duration)
	return nil
}
func (s LoggerSink) Close() error {
	if s.Logger != nil {
		return s.Logger.Close()
	}
	return nil
}

// SyslogWriter is deliberately small so callers can inject a fake in tests.
type SyslogWriter interface {
	Write(string) error
	Close() error
}

type SyslogSink struct{ Writer SyslogWriter }

func (s SyslogSink) Emit(_ context.Context, e Entry) error {
	if s.Writer == nil {
		return nil
	}
	b, _ := json.Marshal(e)
	return s.Writer.Write(string(b))
}

func (s SyslogSink) Close() error {
	if s.Writer == nil {
		return nil
	}
	return s.Writer.Close()
}

// HTTPSink sends webhook-compatible JSON. Provider changes only the body;
// authentication remains in the configured URL/header and is never logged.
type HTTPSink struct {
	URL        string
	Provider   string
	RoutingKey string
	Client     *http.Client
}

func (s HTTPSink) Emit(ctx context.Context, e Entry) error {
	payload := any(e)
	switch strings.ToLower(s.Provider) {
	case "slack":
		payload = map[string]string{"text": fmt.Sprintf("[%s] %s %s: %s", e.Action, e.IP, e.Duration, e.Reason)}
	case "discord":
		payload = map[string]string{"content": fmt.Sprintf("[%s] %s %s: %s", e.Action, e.IP, e.Duration, e.Reason)}
	case "pagerduty":
		payload = map[string]any{"routing_key": s.RoutingKey, "event_action": "trigger", "payload": map[string]string{
			"summary": fmt.Sprintf("%s %s: %s", e.Action, e.IP, e.Reason), "source": "caddy-analyzer", "severity": "warning",
		}}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(b))
	if err != nil {
		return errors.New("webhook request could not be created")
	}
	req.Header.Set("Content-Type", "application/json")
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// net/http includes the request URL in many error strings. Never
		// propagate that string because webhook URLs commonly contain tokens.
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("webhook request timed out")
		}
		return errors.New("webhook request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

type Config struct {
	Sinks      []Sink
	QueueSize  int
	Workers    int
	Timeout    time.Duration
	Retries    int // retries after the initial attempt; capped at 5
	RetryDelay time.Duration
	PerIPRate  time.Duration // minimum interval between events for one IP
	OnError    func(error)
}

type Dispatcher struct {
	cfg    Config
	queue  chan Entry
	stop   chan struct{}
	done   chan struct{}
	mu     sync.Mutex
	last   map[string]time.Time
	closed bool
	once   sync.Once
}

func NewDispatcher(cfg Config) *Dispatcher {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 100 * time.Millisecond
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.Retries > 5 {
		cfg.Retries = 5
	}
	d := &Dispatcher{cfg: cfg, queue: make(chan Entry, cfg.QueueSize), stop: make(chan struct{}), done: make(chan struct{}), last: make(map[string]time.Time)}
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.worker() }()
	}
	go func() { wg.Wait(); close(d.done) }()
	return d
}

// Log is non-blocking. A full queue is intentionally dropped rather than
// delaying firewall decisions; OnError makes loss observable to operators.
func (d *Dispatcher) Log(action, ip, reason, duration string) {
	if d == nil {
		return
	}
	e := Entry{Timestamp: time.Now().UTC(), Action: action, IP: ip, Reason: reason, Duration: duration}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.queue <- e:
	default:
		d.report(fmt.Errorf("audit dispatcher queue full"))
	}
}

func (d *Dispatcher) worker() {
	for e := range d.queue {
		if !d.allow(e.IP) {
			continue
		}
		for attempt := 0; attempt <= d.cfg.Retries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Timeout)
			err := d.emit(ctx, e)
			cancel()
			if err == nil {
				break
			}
			if attempt == d.cfg.Retries {
				d.report(err)
				break
			}
			t := time.NewTimer(d.cfg.RetryDelay * time.Duration(attempt+1))
			<-t.C
		}
	}
}

func (d *Dispatcher) emit(ctx context.Context, e Entry) error {
	var first error
	for _, s := range d.cfg.Sinks {
		if err := s.Emit(ctx, e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (d *Dispatcher) allow(ip string) bool {
	if d.cfg.PerIPRate <= 0 || ip == "" || ip == "-" {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if last, ok := d.last[ip]; ok && now.Sub(last) < d.cfg.PerIPRate {
		return false
	}
	d.last[ip] = now
	return true
}

func (d *Dispatcher) report(err error) {
	if d.cfg.OnError != nil {
		d.cfg.OnError(err)
	}
}

// Close stops accepting events, drains queued events, then closes closeable sinks.
func (d *Dispatcher) Close() error {
	if d == nil {
		return nil
	}
	d.once.Do(func() { d.mu.Lock(); d.closed = true; close(d.stop); close(d.queue); d.mu.Unlock() })
	<-d.done
	var first error
	for _, s := range d.cfg.Sinks {
		if c, ok := s.(io.Closer); ok {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// SafeURL is suitable for diagnostics: credentials, query strings and
// fragments are removed so webhook secrets cannot enter logs.
func SafeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<redacted-url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
