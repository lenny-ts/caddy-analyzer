package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcherRetriesAndFlushesWebhook(t *testing.T) {
	var attempts atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("secret"); got != "" {
			t.Error("query must not be used as a log value")
		}
		if attempts.Add(1) == 1 {
			http.Error(w, "try again", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	d := NewDispatcher(Config{Sinks: []Sink{HTTPSink{URL: s.URL, Provider: "generic"}}, Retries: 1, RetryDelay: time.Millisecond})
	d.Log("block", "1.2.3.4", "test", "10m")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
}

type fakeSink struct{ n atomic.Int32 }

func (f *fakeSink) Emit(context.Context, Entry) error { f.n.Add(1); return nil }

func TestDispatcherRateLimitsPerIP(t *testing.T) {
	f := new(fakeSink)
	d := NewDispatcher(Config{Sinks: []Sink{f}, PerIPRate: time.Hour})
	d.Log("block", "1.2.3.4", "a", "")
	d.Log("unblock", "1.2.3.4", "b", "")
	d.Log("block", "5.6.7.8", "c", "")
	_ = d.Close()
	if f.n.Load() != 2 {
		t.Fatalf("events = %d, want 2", f.n.Load())
	}
}

func TestSafeURL(t *testing.T) {
	got := SafeURL("https://user:pass@example.test/hook?token=secret#x")
	if got != "https://example.test/hook" {
		t.Fatalf("SafeURL = %q", got)
	}
}

type fakeSyslog struct {
	last   string
	closed bool
}

func (f *fakeSyslog) Write(v string) error { f.last = v; return nil }
func (f *fakeSyslog) Close() error         { f.closed = true; return nil }

func TestSyslogSinkIsCloseable(t *testing.T) {
	f := new(fakeSyslog)
	d := NewDispatcher(Config{Sinks: []Sink{SyslogSink{Writer: f}}})
	d.Log("block", "192.0.2.1", "test", "permanent")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.closed || f.last == "" {
		t.Fatalf("syslog sink was not flushed and closed: %#v", f)
	}
}
