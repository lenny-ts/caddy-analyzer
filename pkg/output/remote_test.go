package output

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestElasticsearchExporterBulkAndRetry(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Basic dXNlcjpwYXNz" {
			t.Errorf("authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"_index":"reports"`) || !strings.Contains(string(body), `"total_requests":2`) {
			t.Errorf("unexpected bulk body: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":false,"items":[{"index":{"status":201}}]}`))
	}))
	defer ts.Close()
	e, err := NewElasticsearchExporter(RemoteConfig{URL: ts.URL, Index: "reports", Username: "user", Password: "pass", Retries: 1, Backoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	err = e.Export(context.Background(), []json.RawMessage{json.RawMessage(`{"total_requests":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
}

func TestElasticsearchExporterRejectsItemErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"index":{"error":{"reason":"bad mapping"}}}]}`))
	}))
	defer ts.Close()
	e, err := NewElasticsearchExporter(RemoteConfig{URL: ts.URL, Index: "reports"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Export(context.Background(), []json.RawMessage{json.RawMessage(`{}`)}); err == nil || !strings.Contains(err.Error(), "item errors") {
		t.Fatalf("expected item error, got %v", err)
	}
}

func TestLokiExporterPush(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/push" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"job":"caddy-analyzer"`) {
			t.Errorf("unexpected Loki body: %s", body)
		}
	}))
	defer ts.Close()
	e, err := NewLokiExporter(RemoteConfig{URL: ts.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Export(context.Background(), []json.RawMessage{json.RawMessage(`{"total_requests":1}`)}); err != nil {
		t.Fatal(err)
	}
}
