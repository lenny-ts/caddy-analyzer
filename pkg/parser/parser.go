package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type rawLog struct {
	Level       string              `json:"level"`
	TS          json.Number         `json:"ts"`
	Logger      string              `json:"logger"`
	Msg         string              `json:"msg"`
	Request     *rawRequest         `json:"request"`
	Status      json.Number         `json:"status"`
	Size        json.Number         `json:"size"`
	Duration    json.Number         `json:"duration"`
	Latency     json.Number         `json:"latency"`
	LatencyS    json.Number         `json:"latency_seconds"`
	RespHeaders map[string][]string `json:"resp_headers"`
}

type rawRequest struct {
	Method     string              `json:"method"`
	URI        string              `json:"uri"`
	Host       string              `json:"host"`
	RemoteAddr string              `json:"remote_addr"`
	RemoteIP   string              `json:"remote_ip"`
	Proto      string              `json:"proto"`
	Headers    map[string][]string `json:"headers"`
	TLS        *rawTLS             `json:"tls"`
}

type rawTLS struct {
	Resumed     bool        `json:"resumed"`
	Version     json.Number `json:"version"`
	CipherSuite json.Number `json:"cipher_suite"`
	Proto       string      `json:"proto"`
	ServerName  string      `json:"server_name"`
}

func Parse(line string) (types.Entry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	var raw rawLog
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("json parse: %w", err)
	}

	if raw.Msg == "handled request" {
		return buildHTTPEntry(&raw, line), nil
	}
	return buildOperationalEntry(&raw, line), nil
}

func buildHTTPEntry(raw *rawLog, line string) *types.LogEntry {
	entry := &types.LogEntry{
		Level:  raw.Level,
		Logger: raw.Logger,
		Raw:    line,
	}

	if raw.TS.String() != "" {
		ts, err := raw.TS.Float64()
		if err == nil {
			sec := int64(ts)
			nsec := int64((ts - float64(sec)) * 1e9)
			entry.Timestamp = time.Unix(sec, nsec)
		}
	}

	if raw.Request != nil {
		entry.Method = raw.Request.Method
		entry.URI = raw.Request.URI
		entry.Host = raw.Request.Host
		entry.RemoteAddr = raw.Request.RemoteAddr
		entry.RemoteIP = raw.Request.RemoteIP
		entry.Proto = normalizeProto(raw.Request.Proto)
		if len(raw.Request.Headers) > 0 {
			entry.Headers = make(map[string][]string, len(raw.Request.Headers))
			for name, values := range raw.Request.Headers {
				entry.Headers[name] = append([]string(nil), values...)
			}
		}

		if ua, ok := requestHeader(raw.Request.Headers, "User-Agent"); ok && len(ua) > 0 {
			entry.UserAgent = ua[0]
			classifyUserAgent(entry)
		}
		if ref, ok := requestHeader(raw.Request.Headers, "Referer"); ok && len(ref) > 0 {
			entry.Referer = ref[0]
			entry.RefererDomain = extractDomain(ref[0])
		}
		if xff, ok := requestHeader(raw.Request.Headers, "X-Forwarded-For"); ok && len(xff) > 0 {
			for _, h := range xff {
				for _, hop := range strings.Split(h, ",") {
					hop = strings.TrimSpace(hop)
					if hop != "" {
						entry.ForwardedFor = append(entry.ForwardedFor, hop)
					}
				}
			}
		}
		if xri, ok := requestHeader(raw.Request.Headers, "X-Real-Ip"); ok && len(xri) > 0 {
			entry.RealIP = strings.TrimSpace(xri[0])
		}
		if auth, ok := requestHeader(raw.Request.Headers, "Authorization"); ok && len(auth) > 0 {
			a := auth[0]
			if len(a) > 500 {
				a = a[:500]
			}
			entry.Authorization = a
		}

		if entry.RemoteIP == "" && entry.RemoteAddr != "" {
			entry.RemoteIP = extractIP(entry.RemoteAddr)
		}

		if raw.Request.TLS != nil {
			entry.TLSVersion = formatTLSVersion(raw.Request.TLS.Version)
			entry.TLSCipher = raw.Request.TLS.CipherSuite.String()
			entry.TLSServerName = raw.Request.TLS.ServerName
		}
	}

	if raw.RespHeaders != nil {
		if ct, ok := raw.RespHeaders["Content-Type"]; ok && len(ct) > 0 {
			entry.ContentType = ct[0]
		}
	}

	if raw.Status.String() != "" {
		s, err := raw.Status.Int64()
		if err == nil {
			entry.Status = int(s)
		}
	}

	if raw.Size.String() != "" {
		s, err := raw.Size.Int64()
		if err == nil {
			entry.Size = s
		}
	}

	entry.Duration = parseDuration(raw.Duration, raw.LatencyS, raw.Latency)

	return entry
}

func requestHeader(headers map[string][]string, name string) ([]string, bool) {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}
	return nil, false
}

func buildOperationalEntry(raw *rawLog, line string) *types.OperationalEntry {
	entry := &types.OperationalEntry{
		Level:  raw.Level,
		Logger: raw.Logger,
		Msg:    raw.Msg,
		Raw:    line,
	}

	if raw.TS.String() != "" {
		ts, err := raw.TS.Float64()
		if err == nil {
			sec := int64(ts)
			nsec := int64((ts - float64(sec)) * 1e9)
			entry.Timestamp = time.Unix(sec, nsec)
		}
	}

	// Capture all fields not covered by the typed struct into Extra so
	// callers can display upstream targets, error messages, config paths,
	// etc. without the parser needing to know every possible key.
	var all map[string]json.RawMessage
	if json.Unmarshal([]byte(line), &all) == nil {
		for k, v := range all {
			switch k {
			case "level", "ts", "logger", "msg", "request", "status",
				"size", "duration", "latency", "latency_seconds", "resp_headers":
			default:
				if entry.Extra == nil {
					entry.Extra = make(map[string]json.RawMessage)
				}
				entry.Extra[k] = v
			}
		}
	}

	return entry
}

func extractIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, "[") {
		if end := strings.Index(addr, "]"); end > 0 {
			return addr[1:end]
		}
	}
	if strings.Count(addr, ":") == 1 {
		if idx := strings.LastIndex(addr, ":"); idx > 0 {
			return addr[:idx]
		}
	}
	return addr
}

func parseDuration(values ...json.Number) float64 {
	for _, v := range values {
		if v.String() != "" {
			d, err := v.Float64()
			if err == nil {
				return d
			}
		}
	}
	return 0
}

func formatTLSVersion(num json.Number) string {
	if num.String() == "" {
		return ""
	}
	v, err := num.Int64()
	if err != nil {
		return num.String()
	}
	switch v {
	case 772:
		return "TLS 1.3"
	case 771:
		return "TLS 1.2"
	case 770:
		return "TLS 1.1"
	case 769:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("TLS 0x%x", v)
	}
}

func normalizeProto(p string) string {
	if p == "" {
		return "HTTP/1.1"
	}
	pUpper := strings.ToUpper(p)
	if strings.HasPrefix(pUpper, "HTTP/2") || pUpper == "H2" {
		return "HTTP/2.0"
	}
	if strings.HasPrefix(pUpper, "HTTP/3") || pUpper == "H3" {
		return "HTTP/3.0"
	}
	return p
}

func extractDomain(referer string) string {
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil || u.Host == "" {
		return referer
	}
	return u.Host
}

type botEntry struct {
	key  string
	name string
}

var botList = []botEntry{
	{"googlebot", "Googlebot"},
	{"google-read-aloud", "Google-Read-Aloud"},
	{"bingbot", "Bingbot"},
	{"yandexbot", "YandexBot"},
	{"duckduckbot", "DuckDuckBot"},
	{"baiduspider", "Baiduspider"},
	{"gptbot", "GPTBot"},
	{"chatgpt-user", "ChatGPT-User"},
	{"claudebot", "ClaudeBot"},
	{"anthropic-ai", "anthropic-ai"},
	{"bytespider", "Bytespider"},
	{"ccbot", "CCBot"},
	{"amazonbot", "Amazonbot"},
	{"applebot-extended", "Applebot-Extended"},
	{"perplexitybot", "PerplexityBot"},
	{"meta-externalagent", "meta-externalagent"},
	{"dataforseobot", "DataForSeoBot"},
	{"ahrefsbot", "AhrefsBot"},
	{"semrushbot", "SemrushBot"},
	{"mj12bot", "MJ12bot"},
	{"facebookexternalhit", "FacebookBot"},
	{"twitterbot", "TwitterBot"},
	{"python-requests", "Python Requests"},
	{"curl", "cURL"},
	{"wget", "Wget"},
	{"sqlmap", "sqlmap"},
	{"nikto", "Nikto"},
	{"gobuster", "GoBuster"},
	{"dirbuster", "DirBuster"},
}

func classifyUserAgent(entry *types.LogEntry) {
	ua := strings.ToLower(entry.UserAgent)
	if ua == "" {
		return
	}

	for _, b := range botList {
		if strings.Contains(ua, b.key) {
			entry.IsBot = true
			entry.BotName = b.name
			break
		}
	}

	switch {
	case strings.Contains(ua, "android"):
		entry.OS = "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		entry.OS = "iOS"
	case strings.Contains(ua, "windows"):
		entry.OS = "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		entry.OS = "macOS"
	case strings.Contains(ua, "linux"):
		entry.OS = "Linux"
	}

	switch {
	case strings.Contains(ua, "edg/"):
		entry.Browser = "Edge"
	case strings.Contains(ua, "chrome/"):
		entry.Browser = "Chrome"
	case strings.Contains(ua, "firefox/"):
		entry.Browser = "Firefox"
	case strings.Contains(ua, "safari/") && !strings.Contains(ua, "chrome/"):
		entry.Browser = "Safari"
	}
}
