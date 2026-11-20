package analysis

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type Explanation struct {
	Detection Detection
	RuleID    string // Empty for behavioral detections.
	Source    string
	Matched   string
	Stages    []NormalizationStage
}

type NormalizationStage struct {
	Name  string
	Value string
}

// SetExplain observes the detections returned by DetectAll, after confidence
// deduplication. The observer runs synchronously and must not mutate the detector.
func (d *Detector) SetExplain(observe func(Explanation)) {
	d.explain = observe
}

type matchEvidence struct {
	pattern    compiledPattern
	source     string
	text       string
	start, end int
}

type headerEvidence struct {
	name, value string
	start, end  int
}

func (m matchEvidence) explanation(det Detection, entry *types.LogEntry, lowerURI string, headers []headerEvidence) Explanation {
	x := Explanation{Detection: det, Source: m.source}
	if m.source == "" {
		x.Source = "request history"
		return x
	}

	// Content-based IDs do not shift when unrelated rules are added or reordered.
	p := m.pattern
	id := sha256.Sum256([]byte(fmt.Sprintf("%q:%q:%q:%q:%t:%t:%t",
		p.dtype, p.desc, p.re.String(), p.source, p.uaOnly, p.matchUA, p.matchAuth)))
	x.RuleID = fmt.Sprintf("%s-%X", strings.ToUpper(string(p.dtype)), id[:8])
	x.Matched = m.text[m.start:m.end]

	add := func(name, value string) {
		x.Stages = append(x.Stages, NormalizationStage{name, value})
	}
	if m.source == "uri_and_user_agent" {
		if m.end <= len(lowerURI) && m.start < len(lowerURI) {
			m.source, m.text = "uri", lowerURI
		} else if m.start > len(lowerURI) {
			m.source, m.text = "user_agent", m.text[len(lowerURI)+1:]
		}
		x.Source = m.source
	}
	switch m.source {
	case "uri", "raw_uri":
		if q := strings.IndexByte(entry.URI, '?'); q >= 0 {
			path := entry.URI[:q]
			if m.source == "uri" {
				if decoded, err := url.PathUnescape(path); err == nil {
					path = decoded
				}
			}
			if m.start > len(strings.ToLower(path)) {
				x.Source = "query string"
			}
		}
		add("raw URI", entry.URI)
		if m.source == "uri" {
			add("URL decode", decodeURI(entry.URI))
		}
	case "user_agent":
		add("raw User-Agent", entry.UserAgent)
	case "uri_and_user_agent":
		add("raw URI + User-Agent", entry.URI+"\n"+entry.UserAgent)
		add("URL decode URI", decodeURI(entry.URI)+"\n"+entry.UserAgent)
	case "authorization":
		x.Source, x.Matched = "header: Authorization", "[redacted]"
		add("raw Authorization", "[redacted]")
		if decoded := decodeJWTHeader(entry.Authorization); decoded != entry.Authorization {
			add("JWT header decode", "[redacted]")
		}
		return x
	case "header":
		for _, h := range headers {
			if m.start >= h.start && m.start < h.end && m.end <= h.end {
				x.Source = "header: " + h.name
				switch strings.ToLower(h.name) {
				case "authorization", "proxy-authorization", "cookie", "set-cookie":
					x.Matched = "[redacted]"
					add("raw header", "[redacted]")
					return x
				}
				add("raw header", h.name+": "+h.value)
				add("lowercase", m.text[h.start:h.end])
				return x
			}
		}
		// A match spanning multiple header lines might contain credentials.
		x.Source, x.Matched = "headers", "[redacted]"
		return x
	}
	add("lowercase", m.text)
	return x
}
