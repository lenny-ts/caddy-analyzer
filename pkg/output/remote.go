package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RemoteExporter receives complete, aggregated report documents. Entries are
// deliberately not exported: the normal analyzer path only retains counters.
type RemoteExporter interface {
	Export(context.Context, []json.RawMessage) error
}

type RemoteConfig struct {
	URL       string
	Index     string
	Username  string
	Password  string
	Token     string
	Client    *http.Client
	BatchSize int
	Retries   int
	Backoff   time.Duration
	Timeout   time.Duration
}

func (c RemoteConfig) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	t := c.Timeout
	if t <= 0 {
		t = 10 * time.Second
	}
	return &http.Client{Timeout: t}
}

func (c RemoteConfig) normalized() RemoteConfig {
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.Retries < 0 {
		c.Retries = 0
	}
	if c.Backoff <= 0 {
		c.Backoff = 250 * time.Millisecond
	}
	return c
}

type ElasticsearchExporter struct{ cfg RemoteConfig }

func NewElasticsearchExporter(cfg RemoteConfig) (*ElasticsearchExporter, error) {
	if _, err := validURL(cfg.URL); err != nil {
		return nil, fmt.Errorf("elasticsearch endpoint: %w", err)
	}
	if cfg.Index == "" {
		return nil, fmt.Errorf("elasticsearch index is required")
	}
	return &ElasticsearchExporter{cfg: cfg.normalized()}, nil
}

func (e *ElasticsearchExporter) Export(ctx context.Context, docs []json.RawMessage) error {
	for start := 0; start < len(docs); start += e.cfg.BatchSize {
		end := start + e.cfg.BatchSize
		if end > len(docs) {
			end = len(docs)
		}
		var body bytes.Buffer
		for _, doc := range docs[start:end] {
			meta, _ := json.Marshal(map[string]map[string]string{"index": {"_index": e.cfg.Index}})
			body.Write(meta)
			body.WriteByte('\n')
			body.Write(doc)
			body.WriteByte('\n')
		}
		endpoint, _ := validURL(e.cfg.URL)
		endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/_bulk"
		if err := e.post(ctx, endpoint.String(), body.Bytes(), "application/x-ndjson"); err != nil {
			return fmt.Errorf("elasticsearch bulk export: %w", err)
		}
	}
	return nil
}

func (e *ElasticsearchExporter) post(ctx context.Context, endpoint string, body []byte, contentType string) error {
	return postWithRetry(ctx, e.cfg, endpoint, body, contentType, func(b []byte) error {
		var response struct {
			Errors bool `json:"errors"`
		}
		if err := json.Unmarshal(b, &response); err == nil && response.Errors {
			return fmt.Errorf("bulk response contains item errors: %s", compactBody(b))
		}
		return nil
	})
}

type LokiExporter struct{ cfg RemoteConfig }

func NewLokiExporter(cfg RemoteConfig) (*LokiExporter, error) {
	if _, err := validURL(cfg.URL); err != nil {
		return nil, fmt.Errorf("loki endpoint: %w", err)
	}
	return &LokiExporter{cfg: cfg.normalized()}, nil
}

func (l *LokiExporter) Export(ctx context.Context, docs []json.RawMessage) error {
	for start := 0; start < len(docs); start += l.cfg.BatchSize {
		end := start + l.cfg.BatchSize
		if end > len(docs) {
			end = len(docs)
		}
		values := make([][2]string, 0, end-start)
		for _, doc := range docs[start:end] {
			values = append(values, [2]string{fmt.Sprintf("%d", time.Now().UnixNano()), string(doc)})
		}
		payload := map[string]interface{}{"streams": []interface{}{map[string]interface{}{"stream": map[string]string{"job": "caddy-analyzer", "source": "report"}, "values": values}}}
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode loki payload: %w", err)
		}
		endpoint, _ := validURL(l.cfg.URL)
		if endpoint.Path == "" || endpoint.Path == "/" {
			endpoint.Path = "/loki/api/v1/push"
		}
		if err := postWithRetry(ctx, l.cfg, endpoint.String(), body, "application/json", nil); err != nil {
			return fmt.Errorf("loki export: %w", err)
		}
	}
	return nil
}

func validURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("URL must be an absolute http(s) URL")
	}
	return u, nil
}

func postWithRetry(ctx context.Context, cfg RemoteConfig, endpoint string, body []byte, contentType string, check func([]byte) error) error {
	var last error
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", contentType)
		if cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
		} else if cfg.Username != "" {
			req.SetBasicAuth(cfg.Username, cfg.Password)
		}
		resp, err := cfg.client().Do(req)
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				err = readErr
			} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				err = fmt.Errorf("HTTP %s: %s", resp.Status, compactBody(data))
			} else if check != nil {
				err = check(data)
			}
		}
		if err == nil {
			return nil
		}
		last = err
		if attempt < cfg.Retries {
			delay := cfg.Backoff * time.Duration(1<<attempt)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("after %d attempt(s): %w", cfg.Retries+1, last)
}

func compactBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		return s[:512] + "..."
	}
	return s
}
