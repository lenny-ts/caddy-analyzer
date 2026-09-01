package analysis

import (
	"container/list"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type DetectionType string

const (
	DetSQLInjection   DetectionType = "sql_injection"
	DetNoSQLi         DetectionType = "nosql_injection"
	DetXSS            DetectionType = "xss"
	DetSSTI           DetectionType = "ssti"
	DetSSRF           DetectionType = "ssrf"
	DetRCE            DetectionType = "rce"
	DetPathTraversal  DetectionType = "path_traversal"
	DetLFIWrapper     DetectionType = "lfi_wrapper_abuse"
	DetGraphQL        DetectionType = "graphql_introspection"
	DetLog4j          DetectionType = "log4j_jndi"
	DetSensitiveFile  DetectionType = "sensitive_file_probe"
	DetAdminProbe     DetectionType = "admin_probe"
	DetWPProbe        DetectionType = "wordpress_probe"
	DetCGIProbe       DetectionType = "cgi_probe"
	DetScanner        DetectionType = "scanner"
	DetXXE            DetectionType = "xxe"
	DetOpenRedirect   DetectionType = "open_redirect"
	DetLDAPInjection  DetectionType = "ldap_injection"
	DetXPathInjection DetectionType = "xpath_injection"
	DetCRLFInjection  DetectionType = "crlf_injection"
	DetProtoPollution DetectionType = "prototype_pollution"
	DetSSIInjection   DetectionType = "ssi_injection"
	DetUARotation     DetectionType = "ua_rotation"
	DetJWTAbuse       DetectionType = "jwt_abuse"
	DetObjectEnum     DetectionType = "object_enumeration"
	DetBeaconing      DetectionType = "beaconing"
)

type Detection struct {
	Type       DetectionType `json:"type"`
	IP         string        `json:"ip"`
	URI        string        `json:"uri"`
	Status     int           `json:"status"`
	Desc       string        `json:"description"`
	Confidence int           `json:"confidence"`
	Techniques []string      `json:"techniques,omitempty"`
}

// DetectionPattern is the JSON representation of a custom signature.
type DetectionPattern struct {
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Confidence  int    `json:"confidence"`
	Source      string `json:"source"`
	MITRE       string `json:"mitre,omitempty"`
}

const (
	maxCustomPatternFileSize = 10 << 20
	maxCustomPatterns        = 1000
)

// LoadCustomPatterns reads and validates a JSON array of custom signatures.
func LoadCustomPatterns(path string) ([]DetectionPattern, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("custom patterns %q: %w", path, err)
	}
	if info.Size() > maxCustomPatternFileSize {
		return nil, fmt.Errorf("custom patterns %q is larger than %d bytes", path, maxCustomPatternFileSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open custom patterns %q: %w", path, err)
	}
	defer f.Close()
	var patterns []DetectionPattern
	dec := json.NewDecoder(f)
	if err := dec.Decode(&patterns); err != nil {
		return nil, fmt.Errorf("decode custom patterns %q: %w", path, err)
	}
	if patterns == nil {
		return nil, fmt.Errorf("custom patterns %q must contain a JSON array", path)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("custom patterns %q contains trailing JSON", path)
	} else if err != io.EOF {
		return nil, fmt.Errorf("custom patterns %q has invalid trailing JSON: %w", path, err)
	}
	if len(patterns) > maxCustomPatterns {
		return nil, fmt.Errorf("custom patterns %q contains more than %d patterns", path, maxCustomPatterns)
	}
	for i := range patterns {
		p := &patterns[i]
		p.Type = strings.TrimSpace(p.Type)
		p.Pattern = strings.TrimSpace(p.Pattern)
		p.Description = strings.TrimSpace(p.Description)
		p.Source = strings.ToLower(strings.TrimSpace(p.Source))
		if p.Type == "" || p.Pattern == "" || p.Description == "" {
			return nil, fmt.Errorf("custom pattern %d: type, pattern, and description are required", i+1)
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(p.Type) {
			return nil, fmt.Errorf("custom pattern %d: invalid type %q", i+1, p.Type)
		}
		if p.Confidence < 1 || p.Confidence > 10 {
			return nil, fmt.Errorf("custom pattern %d: confidence must be between 1 and 10", i+1)
		}
		switch p.Source {
		case "uri", "header", "user_agent", "all":
		default:
			return nil, fmt.Errorf("custom pattern %d: source must be uri, header, user_agent, or all", i+1)
		}
		if _, err := regexp.Compile(p.Pattern); err != nil {
			return nil, fmt.Errorf("custom pattern %d: invalid regex: %w", i+1, err)
		}
	}
	return patterns, nil
}

// detectionTechniques maps each DetectionType to its MITRE ATT&CK technique
// IDs. Populated once at package init; referenced by DetectAll to tag every
// detection with the adversary techniques it corresponds to. This lets SOC
// analysts build ATT&CK Navigator coverage layers from caddy-analyzer output
// and export detections as Sigma rules with proper tags.
var detectionTechniques = map[DetectionType][]string{
	DetSQLInjection:   {"T1190"},
	DetNoSQLi:         {"T1190"},
	DetXSS:            {"T1059.007", "T1189"},
	DetSSTI:           {"T1190"},
	DetSSRF:           {"T1190"},
	DetRCE:            {"T1059", "T1190"},
	DetPathTraversal:  {"T1083"},
	DetLFIWrapper:     {"T1083", "T1190"},
	DetGraphQL:        {"T1595.002"},
	DetLog4j:          {"T1190", "T1059"},
	DetSensitiveFile:  {"T1083", "T1552.001"},
	DetAdminProbe:     {"T1595.002"},
	DetWPProbe:        {"T1595.002"},
	DetCGIProbe:       {"T1595.002"},
	DetScanner:        {"T1595"},
	DetXXE:            {"T1190"},
	DetOpenRedirect:   {"T1566.002"},
	DetLDAPInjection:  {"T1190"},
	DetXPathInjection: {"T1190"},
	DetCRLFInjection:  {"T1190", "T1059"},
	DetProtoPollution: {"T1190", "T1059.007"},
	DetSSIInjection:   {"T1190", "T1059"},
	DetUARotation:     {"T1595.001"},
	DetJWTAbuse:       {"T1550.001", "T1190"},
	DetObjectEnum:     {"T1595.002", "T1190"},
	DetBeaconing:      {"T1071.001", "T1573"},
}

// TechniquesFor returns the MITRE ATT&CK technique IDs for a detection type.
func TechniquesFor(dt DetectionType) []string {
	return detectionTechniques[dt]
}

type IPDetStats struct {
	AuthFailures   int
	NotFound       int
	Total          int
	UserAgents     map[string]struct{}
	PathIDs        map[string]map[int]struct{}
	PathTimestamps map[string][]time.Time
	PathWriteCount map[string]int
}

const (
	beaconMinSamples      = 10
	beaconMaxSamples      = 50
	beaconJitterThreshold = 0.25
	objEnumThreshold      = 10
	objEnumMaxIDs         = 200
	pathCapPerIP          = 1000
)

// defaultUARotationThreshold is the number of distinct User-Agents from one
// IP that triggers a scanner/rotation heuristic. Bots and credential-stuffing
// tools rotate UAs to evade fingerprinting; legitimate clients are stable.
const defaultUARotationThreshold = 10

// compiledPattern is a single detection signature: a compiled regex plus its
// metadata. Named type (instead of an anonymous struct) so the slice can be
// shared safely across Detector instances.
type compiledPattern struct {
	re         *regexp.Regexp
	dtype      DetectionType
	desc       string
	confidence int
	matchUA    bool     // additionally match the User-Agent
	uaOnly     bool     // match the User-Agent instead of the URI
	matchAuth  bool     // match the Authorization header instead of the URI
	gate       string   // if non-empty, source must contain this substring (case-insensitive) before regex runs
	hasMarkers bool     // true if isMarkerCovered returns true for this pattern
	literals   []string // if non-empty, pattern is a pure literal alternation; match with strings.Contains instead of regex
	source     string
	techniques []string
}

// compiledPatternsCache holds the result of compilePatterns() so the ~150
// regexes are compiled exactly once per process, not once per NewDetector()
// call. guard.Tick(), runFollowMode, runIntervalMode and runWatch all create a
// fresh Detector per window — recompiling on every tick was pure waste.
// Patterns are read-only after compilation and *regexp.Regexp is safe for
// concurrent use, so sharing is safe.
var (
	compiledPatternsOnce  sync.Once
	compiledPatternsCache []compiledPattern
	uriMarkers            []string
	uaMarkers             []string
	authMarkers           []string
	rawMarkers            []string
)

func getCompiledPatterns() []compiledPattern {
	compiledPatternsOnce.Do(func() {
		compiledPatternsCache = compilePatterns()
		for i := range compiledPatternsCache {
			compiledPatternsCache[i].gate = extractGate(compiledPatternsCache[i].re.String())
		}
		uriMarkers, uaMarkers, authMarkers = buildMarkers(compiledPatternsCache)
	})
	return compiledPatternsCache
}

type Detector struct {
	patterns            []compiledPattern
	customPatterns      []compiledPattern
	ipStats             map[string]*IPDetStats
	ipOrder             *list.List // LRU tracking: least recent at front
	ipNodes             map[string]*list.Element
	ipCap               int // max tracked IPs (0 = unlimited)
	uaRotationThreshold int
}

// DefaultIPCaps is the default cap on tracked IPs in --detect offline mode,
// to bound memory on huge logs. The guard resets the detector each tick so
// its growth is naturally bounded by the window.
const DefaultIPCap = 100000

func NewDetector() *Detector {
	return NewDetectorWithPatterns(nil)
}

// NewDetectorWithPatterns keeps custom signatures local while sharing the
// built-in compiled slice and its sync.Once cache.
func NewDetectorWithPatterns(custom []DetectionPattern) *Detector {
	compiled := make([]compiledPattern, 0, len(custom))
	for _, p := range custom {
		compiled = append(compiled, compiledPattern{
			re:         compileLowercase(p.Pattern),
			dtype:      DetectionType(p.Type),
			desc:       p.Description,
			confidence: p.Confidence,
			source:     p.Source,
			techniques: splitTechniques(p.MITRE),
			literals:   extractPureLiterals(p.Pattern),
		})
	}
	return &Detector{
		patterns:            getCompiledPatterns(),
		customPatterns:      compiled,
		ipStats:             make(map[string]*IPDetStats),
		ipOrder:             list.New(),
		ipNodes:             make(map[string]*list.Element),
		ipCap:               DefaultIPCap,
		uaRotationThreshold: defaultUARotationThreshold,
	}
}

func splitTechniques(value string) []string {
	var out []string
	for _, v := range strings.Split(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// SetIPCap configures the maximum number of tracked IPs. 0 disables eviction.
func (d *Detector) SetIPCap(cap int) {
	d.ipCap = cap
	if cap <= 0 {
		return
	}
	for len(d.ipStats) > cap {
		d.evictOldestIP()
	}
}

// SetUARotationThreshold configures how many distinct User-Agents from one
// IP trigger the scanner/rotation heuristic. Values <= 0 reset to default.
func (d *Detector) SetUARotationThreshold(n int) {
	if n <= 0 {
		n = defaultUARotationThreshold
	}
	d.uaRotationThreshold = n
}

// UARotationThreshold returns the current UA rotation threshold.
func (d *Detector) UARotationThreshold() int { return d.uaRotationThreshold }

// evictOldestIP drops the least recently used IP, bounding memory on logs
// with many distinct clients. Uses LRU order (ipOrder) so actively-used IPs
// are never evicted. The guard resets the detector each tick so this
// primarily protects long-running offline --detect runs.
func (d *Detector) evictOldestIP() {
	if elem := d.ipOrder.Front(); elem != nil {
		ip := elem.Value.(string)
		delete(d.ipStats, ip)
		delete(d.ipNodes, ip)
		d.ipOrder.Remove(elem)
	}
}

// touchIP moves ip to the end of ipOrder, marking it as most recently used.
// This implements true LRU eviction so actively-used IPs are never dropped.
func (d *Detector) touchIP(ip string) {
	if elem, ok := d.ipNodes[ip]; ok {
		d.ipOrder.MoveToBack(elem)
	}
}

// extractGate walks the regex syntax tree and finds the longest literal
// substring that MUST appear in any match (i.e. it is not inside an
// alternation or optional quantifier). This literal is used as a fast
// pre-filter: if strings.Contains(lowercasedSource, gate) is false, the
// regex is skipped entirely. For benign log entries (~90% of traffic) this
// eliminates nearly all of the ~150 regex evaluations per entry.
func extractGate(pattern string) string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return ""
	}
	best := ""
	var walk func(r *syntax.Regexp, required bool)
	walk = func(r *syntax.Regexp, required bool) {
		switch r.Op {
		case syntax.OpLiteral:
			if required && len(r.Rune) >= 3 {
				s := strings.ToLower(string(r.Rune))
				if len(s) > len(best) {
					best = s
				}
			}
		case syntax.OpConcat, syntax.OpCapture:
			for _, sub := range r.Sub {
				walk(sub, required)
			}
		case syntax.OpPlus:
			if len(r.Sub) > 0 {
				walk(r.Sub[0], required)
			}
		case syntax.OpRepeat:
			if r.Min >= 1 && len(r.Sub) > 0 {
				walk(r.Sub[0], required)
			}
		case syntax.OpAlternate:
			for _, sub := range r.Sub {
				walk(sub, false)
			}
		}
	}
	walk(re, true)
	return best
}

// extractMarkers collects ALL literal substrings (>= 3 chars) from the
// regex, including those inside alternations. These are used to build a
// single "triage" regex: if the triage regex does not match, NONE of the
// individual patterns can match, and the entire detection loop is skipped.
func extractMarkers(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	var markers []string
	var walk func(r *syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpLiteral:
			if len(r.Rune) >= 2 {
				markers = append(markers, strings.ToLower(string(r.Rune)))
			}
		default:
			for _, sub := range r.Sub {
				walk(sub)
			}
		}
	}
	walk(re)
	return markers
}

// buildMarkers collects all unique literal markers (>= 3 chars) from the
// compiled patterns, split by source type (URI, UA, auth). Sets hasMarkers
// for patterns where every match path contains at least one marker.
func buildMarkers(patterns []compiledPattern) (uri, ua, auth []string) {
	seenURI := make(map[string]struct{})
	seenUA := make(map[string]struct{})
	seenAuth := make(map[string]struct{})
	var uriM, uaM, authM []string
	for i, p := range patterns {
		if isMarkerCovered(p.re.String()) {
			patterns[i].hasMarkers = true
		}
		for _, m := range extractMarkers(p.re.String()) {
			switch {
			case p.matchAuth:
				if _, ok := seenAuth[m]; !ok {
					seenAuth[m] = struct{}{}
					authM = append(authM, m)
				}
			case p.uaOnly:
				if _, ok := seenUA[m]; !ok {
					seenUA[m] = struct{}{}
					uaM = append(uaM, m)
				}
			case p.matchUA:
				if _, ok := seenURI[m]; !ok {
					seenURI[m] = struct{}{}
					uriM = append(uriM, m)
				}
				if _, ok := seenUA[m]; !ok {
					seenUA[m] = struct{}{}
					uaM = append(uaM, m)
				}
			default:
				if _, ok := seenURI[m]; !ok {
					seenURI[m] = struct{}{}
					uriM = append(uriM, m)
				}
			}
		}
	}
	return uriM, uaM, authM
}

// matchMarkers checks if any of the marker substrings is present in src.
// This replaces the triage regex approach, which was too slow due to the
// massive NFA generated by hundreds of alternation keywords. A simple loop
// of strings.Contains is faster because each call short-circuits on the
// first byte, and most markers start with distinctive bytes that rarely
// appear in benign traffic.
func matchMarkers(src string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(src, m) {
			return true
		}
	}
	return false
}

// isMarkerCovered returns true if every possible match of the regex must
// contain at least one literal substring >= 2 chars. This means the pattern
// can be safely skipped when none of the markers (collected by extractMarkers)
// are present in the source.
//
// For alternations, ALL branches must be covered (otherwise a match via an
// uncovered branch would contain no marker). For optional quantifiers (? and *),
// the result is false (the child might not match at all).
func isMarkerCovered(pattern string) bool {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	var walk func(r *syntax.Regexp) bool
	walk = func(r *syntax.Regexp) bool {
		switch r.Op {
		case syntax.OpLiteral:
			return len(r.Rune) >= 2
		case syntax.OpConcat, syntax.OpCapture:
			for _, sub := range r.Sub {
				if walk(sub) {
					return true
				}
			}
			return false
		case syntax.OpAlternate:
			for _, sub := range r.Sub {
				if !walk(sub) {
					return false
				}
			}
			return len(r.Sub) > 0
		case syntax.OpPlus:
			if len(r.Sub) > 0 {
				return walk(r.Sub[0])
			}
			return false
		case syntax.OpRepeat:
			if r.Min >= 1 && len(r.Sub) > 0 {
				return walk(r.Sub[0])
			}
			return false
		default:
			return false
		}
	}
	return walk(re)
}

// extractPureLiterals checks if a pattern is a pure alternation of literal
// strings (no quantifiers, character classes, or anchors). If so, it returns
// the lowercased literals — the caller can use strings.Contains instead of
// the regex engine, which is ~100x faster.
func extractPureLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	for re.Op == syntax.OpCapture && len(re.Sub) == 1 {
		re = re.Sub[0]
	}
	var literals []string
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) >= 2 {
			literals = []string{strings.ToLower(string(re.Rune))}
		}
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			lit, ok := literalFromNode(sub)
			if !ok {
				return nil
			}
			if len(lit) < 2 {
				return nil
			}
			literals = append(literals, strings.ToLower(lit))
		}
	default:
		return nil
	}
	if len(literals) == 0 {
		return nil
	}
	return literals
}

// literalFromNode extracts a literal string from a regex node, handling
// OpLiteral, OpCapture, and OpConcat of OpLiteral children. Returns false
// if the node contains any non-literal construct (quantifiers, classes, etc.).
func literalFromNode(r *syntax.Regexp) (string, bool) {
	switch r.Op {
	case syntax.OpLiteral:
		return string(r.Rune), true
	case syntax.OpCapture, syntax.OpConcat:
		var sb strings.Builder
		for _, sub := range r.Sub {
			s, ok := literalFromNode(sub)
			if !ok {
				return "", false
			}
			sb.WriteString(s)
		}
		return sb.String(), true
	default:
		return "", false
	}
}

// compileLowercase compiles a case-insensitive regex pattern into a
// case-sensitive regex where all literals are lowercased. This eliminates
// the unicode.SimpleFold overhead (~8% of CPU time) during matching. The
// caller must lowercase the source string before matching.
func compileLowercase(pattern string) *regexp.Regexp {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return regexp.MustCompile(pattern)
	}
	lowercaseFold(re)
	return regexp.MustCompile(re.String())
}

// lowercaseFold recursively lowercases all OpLiteral runes and clears the
// FoldCase flag from all nodes in the syntax tree. OpCharClass ranges are
// also lowercased so that patterns like [A-Z] correctly match lowercase
// source text.
func lowercaseFold(r *syntax.Regexp) {
	r.Flags &^= syntax.FoldCase
	switch r.Op {
	case syntax.OpLiteral:
		for i := range r.Rune {
			r.Rune[i] = unicode.ToLower(r.Rune[i])
		}
	case syntax.OpCharClass:
		for i := 0; i < len(r.Rune); i += 2 {
			r.Rune[i] = unicode.ToLower(r.Rune[i])
			r.Rune[i+1] = unicode.ToLower(r.Rune[i+1])
		}
	}
	for _, sub := range r.Sub {
		lowercaseFold(sub)
	}
}

func compilePatterns() []compiledPattern {
	var p []compiledPattern

	add := func(pattern string, dtype DetectionType, desc string, confidence int) {
		lits := extractPureLiterals(pattern)
		p = append(p, compiledPattern{
			re:         compileLowercase(pattern),
			dtype:      dtype,
			desc:       desc,
			confidence: confidence,
			gate:       extractGate(pattern),
			literals:   lits,
		})
	}

	addUA := func(pattern string, dtype DetectionType, desc string, confidence int, uaOnly bool) {
		lits := extractPureLiterals(pattern)
		p = append(p, compiledPattern{
			re:         compileLowercase(pattern),
			dtype:      dtype,
			desc:       desc,
			confidence: confidence,
			matchUA:    true,
			uaOnly:     uaOnly,
			gate:       extractGate(pattern),
			literals:   lits,
		})
	}

	addAuth := func(pattern string, desc string, confidence int) {
		lits := extractPureLiterals(pattern)
		p = append(p, compiledPattern{
			re:         compileLowercase(pattern),
			dtype:      DetJWTAbuse,
			desc:       desc,
			confidence: confidence,
			matchAuth:  true,
			gate:       extractGate(pattern),
			literals:   lits,
		})
	}

	// SQL Injection
	add(`(?i)(\bUNION\s+(?:ALL\s+|DISTINCT\s+)?SELECT\b|\bSELECT\b\s+.{0,200}?\bFROM\b\s+\w)`, DetSQLInjection, "SQL injection: UNION SELECT", 10)
	add(`(?i)\bUNION\b(?:\s|/\*[^*]*\*/)+(?:ALL\b(?:\s|/\*[^*]*\*/)+|DISTINCT\b(?:\s|/\*[^*]*\*/)+)?\bSELECT\b`, DetSQLInjection, "SQL injection: comment-bypass UNION SELECT", 10)
	add(`(?i)(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)\b(?:\s|/\*[^*]*\*/){1,4}\b(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|AND|OR)\b`, DetSQLInjection, "SQL injection: comment-separated keywords", 8)
	add(`(?i)/\*!?\s*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|AND|OR)\b`, DetSQLInjection, "SQL injection: keyword in inline comment", 8)
	add(`(?i)(\bOR\s+1\s*=\s*1|1\s*=\s*1\s*--|\bOR\s+'1'\s*=\s*'1'|'(\s*OR\s*|\s*AND\s*)'1'='1|"(\s*OR\s*|\s*AND\s*)"1"="1)`, DetSQLInjection, "SQL injection: tautology", 8)
	add(`(?i)(\bOR\s+\d+\s*[<>]=?\s*\d+|\bOR\s+'[^']+'\s*=\s*'[^']+'|\bAND\s+\d+\s*[<>]=?\s*\d+|\bAND\s+'[^']+'\s*=\s*'[^']+')`, DetSQLInjection, "SQL injection: relational/string tautology", 7)
	add(`(?i)('.{0,50}?--|\bDROP\s+TABLE\b|;\s*DROP\s+|DELETE\s+FROM\b|TRUNCATE\b)`, DetSQLInjection, "SQL injection: destructive", 9)
	add(`(?i)(INFORMATION_SCHEMA|PG_CATALOG|MYSQL_HELP|SYSTEM_USER|CURRENT_USER|SESSION_USER|USER\s*\(\))`, DetSQLInjection, "SQL injection: system info", 9)
	add(`(?i)(pg_sleep|SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|DBMS_LOCK\.SLEEP|SIGN\s*\(|EXP\s*\(|POW\s*\(|IF\s*\(.*SLEEP|SLEEP\s*$)`, DetSQLInjection, "SQL injection: time-based blind", 9)
	add(`(?i)(CONVERT\s*\(.*INT|CAST\s*\(.*INT|EXTRACTVALUE\s*\(|UPDATEXML\s*\(|GROUP_CONCAT\s*\()`, DetSQLInjection, "SQL injection: error-based", 8)
	add(`(?i)(xp_cmdshell|sp_executesql|sp_makewebtask|OPENROWSET|OPENDATASOURCE|xp_regread|xp_regwrite|xp_enumdsn|xp_availablemedia|xp_fileexist|xp_subdirs|xp_dirtree)`, DetSQLInjection, "SQL injection: out-of-band / OS", 10)
	add(`(?i)(INTO\s+(OUTFILE|DUMPFILE)|LOAD_FILE\s*\(|INFILE\s+)`, DetSQLInjection, "SQL injection: file operation", 9)
	add(`(?i)(@@version|@@basedir|@@datadir|@@hostname|@@servername|@@langid|@@language|@@microsoftversion|@@max_connections)`, DetSQLInjection, "SQL injection: global variables", 7)
	add(`(?i)(HAVING\s+\d+|ORDER\s+BY\s+\d+|GROUP\s+BY\s+\d+)`, DetSQLInjection, "SQL injection: column enumeration", 6)
	add(`(?i)(CHAR\s*\(|ASCII\s*\(|SUBSTRING\s*\(|SUBSTR\s*\(|MID\s*\(|ORD\s*\()`, DetSQLInjection, "SQL injection: blind functions", 6)
	add(`(?i)(EXEC\s+(xp_|sp_)|EXECUTE\s+(xp_|sp_))`, DetSQLInjection, "SQL injection: stored procedure", 9)
	add(`(?i)(pg_sleep|pg_read_file|pg_read_binary_file|pg_ls_dir|COPY\s+.*\s+FROM\s+PROGRAM)`, DetSQLInjection, "SQL injection: postgres superuser", 9)
	add(`(?i)(DECLARE\s+@|SET\s+@|EXEC\s*\(|EXECUTE\s*\()`, DetSQLInjection, "SQL injection: SQL Server variables", 7)
	add(`(?i)(UNION\s+ALL\s+SELECT\s+NULL|UNION\s+SELECT\s+NULL)`, DetSQLInjection, "SQL injection: column number discovery", 8)

	// NoSQL Injection
	add(`(?i)(\$ne|\$gt|\$gte|\$lt|\$lte|\$regex|\$where|\$exists|\$nin|\$in|\$all|\$elemMatch|\$size|\$mod|\$type|\$slice|\$comment|\$or|\$and|\$nor|\$not)`, DetNoSQLi, "NoSQL injection: MongoDB operators", 8)
	add(`(?i)(%24ne|%24gt|%24gte|%24lt|%24lte|%24regex|%24where|%24exists|%24nin|%24in|%24all|%24elemMatch|%24size)`, DetNoSQLi, "NoSQL injection: URL-encoded operators", 7)
	add(`(?i)('\s*\|\|\s*'1'\s*==\s*'1|'\s*\|\|\s*1\s*==\s*1|true\);\s*return\s+true)`, DetNoSQLi, "NoSQL injection: JavaScript eval", 8)

	// XSS
	add(`(?i)(<script[^>]*>|<\/script>|<\s*script|<img[^>]*\s+src|<\s*img\s|<\s*iframe\s|<\s*body\s|<\s*input\s|<\s*svg\s|<\s*details\s|<\s*marquee\s|<\s*embed\s|<\s*object\s|<\s*video\s|<\s*audio\s|<\s*link\s+rel=\s*stylesheet|<\s*style[^>]*>|<\s*math\s|<\s*et\s|<\s*template\s|<<script|<<svg)`, DetXSS, "XSS: HTML tag injection", 8)
	add(`(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onmouseout\s*=|onfocus\s*=|onblur\s*=|onsubmit\s*=|onreset\s*=|onchange\s*=|onkeydown\s*=|onkeypress\s*=|onkeyup\s*=|ondblclick\s*=|onabort\s*=|onbeforeunload\s*=|onhashchange\s*=|oninput\s*=|oninvalid\s*=|onplay\s*=|onprogress\s*=|onscroll\s*=|onselect\s*=|ontoggle\s*=|onwheel\s*=|onauxclick\s*=|ongotpointercapture\s*=|onlostpointercapture\s*=|onpointerdown\s*=|onpointermove\s*=|onpointerup\s*=|onpointerover\s*=|onpointerenter\s*=|onpointerleave\s*=|onpointerout\s*=|onpointercancel\s*=)`, DetXSS, "XSS: event handler", 8)
	add(`(?i)(javascript:|vbscript:|livescript:|data:\s*text/html|data:\s*text/javascript|data:\s*application/x-javascript|data:\s*image/svg\+xml|data:\s*[^,]*,.*base64|blob:)`, DetXSS, "XSS: protocol handler", 9)
	add(`(?i)(alert\s*\(|prompt\s*\(|confirm\s*\(|print\s*\(|setTimeout\s*\(|setInterval\s*\(|execScript\s*\(|Function\s*\(|setImmediate\s*\()`, DetXSS, "XSS: dangerous JS function", 7)
	add(`(?i)(document\.cookie|document\.location|document\.write|document\.writeln|document\.domain|document\.URI|document\.URL|document\.baseURI|document\.referrer|document\.documentURI|\.innerHTML|\.outerHTML|window\.location|location\.href|location\.hash|location\.search|location\.pathname|location\.replace|navigator\.sendBeacon)`, DetXSS, "XSS: DOM access", 7)
	add(`(?i)(String\.fromCharCode|String\.fromCodePoint|escape\s*\(|unescape\s*\(|encodeURI|decodeURI|atob\s*\(|btoa\s*\()`, DetXSS, "XSS: encoding/bypass function", 5)
	add(`(?i)(expression\s*\(|-moz-binding|behavior\s*:|url\s*\(\s*javascript|progid:DXImageTransform|@import\s+url)`, DetXSS, "XSS: CSS expression", 6)
	add(`(?i)(@import\s+url|@import\s+"[^"]*\.css|@charset\s+|@font-face\s*\{)`, DetXSS, "XSS: CSS import", 5)
	add(`(?i)(<![CDATA\[|]]>|<\?xml)`, DetXSS, "XSS: XML/SSI injection", 6)
	add(`(?i)(<\?php|<\?=)`, DetRCE, "RCE: PHP code injection", 8)
	add(`(?i)(%3C|%3E|&#x?3[Cc]|&#x?3[Ee]|&lt;|&gt;)`, DetXSS, "XSS: encoded angle brackets", 5)
	add(`(?i)(%22|%27|%0D|%0A|%09|%00|&#x?2[27]|&quot;|&#x?0[dDaA])`, DetXSS, "XSS: encoded characters", 2)
	add(`(?i)(fetch\s*\(|XMLHttpRequest|ActiveXObject|WebSocket\s*\(|postMessage\s*\()`, DetXSS, "XSS: HTTP request API", 4)
	add(`(?i)(constructor\.prototype|prototype\s*\[)`, DetXSS, "XSS: prototype manipulation", 7)
	add(`(?i)(import\s*\(|require\s*\()`, DetXSS, "XSS: dynamic import", 5)
	add(`(?i)(srcdoc\s*=|autofocus\s*=|accesskey\s*=|tabindex\s*=|contenteditable\s*=)`, DetXSS, "XSS: HTML attribute injection", 6)
	add(`(?i)(xlink:href=|xlink:type=|xlink:show=|xlink:actuate=)`, DetXSS, "XSS: XLink injection", 7)
	add(`(?i)(formaction\s*=|formmethod\s*=|formenctype\s*=|formtarget\s*=)`, DetXSS, "XSS: form attribute override", 7)

	// Log4j / JNDI (before SSTI to avoid ${...} overlap)
	addUA(`(?i)(\$\{jndi:|class\.module\.classLoader|\$\{lower:jndi|\$\{upper:jndi|\$\{::-j|\$\{env:|\$\{sys:|\$\{log4j:|\$\{ctx:|\$\{java:|\$\{date:|\$\{docker:|\$\{k8s:|\$\{spring:|\$\{main:|\$\{bundle:|\$\{map:|\$\{mdc:|\$\{name:|\$\{marker:|\$\{exception:)`, DetLog4j, "Log4j: JNDI lookup", 10, false)
	addUA(`(?i)(jndi:ldap://|jndi:rmi://|jndi:ldaps://|jndi:dns://|jndi:iiop://|jndi:http://|jndi:https://)`, DetLog4j, "Log4j: JNDI protocol", 10, false)
	addUA(`(?i)(\$\{(?:[^}]*:){2,}[^}]*\}|%24\{|%2524\{)`, DetLog4j, "Log4j: encoded lookup", 5, false)

	// SSRF (before SSTI to avoid ${...} overlap)
	add(`(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata\.compute\.internal|metadata\.goog|100\.100\.100\.200|168\.63\.129\.16|fd00:ec2::23)`, DetSSRF, "SSRF: cloud metadata endpoint", 10)
	add(`(?i)(0x7f000001|0x7f\.0\.0\.1|2130706433|017700000001|0o17700000001)`, DetSSRF, "SSRF: loopback IP variants", 8)
	add(`(?i)://\d{8,10}\b`, DetSSRF, "SSRF: decimal IP host", 7)
	add(`(?i)(\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\blocalhost\b)`, DetSSRF, "SSRF: loopback/localhost", 7)
	add(`(?i)(\[::1\]|\[0:0:0:0:0:0:0:1\]|\[0::1\]|\[0000:0000:0000:0000:0000:0000:0000:0001\]|\b::1\b)`, DetSSRF, "SSRF: loopback IPv6", 7)
	add(`(?i)(gopher://|dict://|ftp://|tftp://|ldap://|ldaps://|redis://|mysql://|postgres://|ssh://|smb://|sftp://)`, DetSSRF, "SSRF: protocol smuggling", 8)
	add(`(?i)(\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b)`, DetSSRF, "SSRF: private IP probe", 6)
	add(`(?i)(instance-data|latest/meta-data|latest/user-data|computeMetadata|dynamic/instance-identity|/metadata/\w)`, DetSSRF, "SSRF: cloud metadata path", 8)

	// SSTI (after Log4j/SSRF to avoid pattern overlap)
	add(`(?i)(\{\{7\*7\}\}|\$\{7\*7\}|\$\{\{7\*7\}\}|#\{7\*7\}|\*\{7\*7\})`, DetSSTI, "SSTI: arithmetic probe", 8)
	add(`(?i)(__class__|__mro__|__subclasses__|__globals__|__builtins__|__init__|__dict__|__bases__|__import__)`, DetSSTI, "SSTI: Python MRO exploit", 9)
	add(`(?i)(freemarker|nunjucks|range\.constructor|lipsum|cycler|joiner)`, DetSSTI, "SSTI: template engine globals", 8)
	add(`(?i)(os\.popen|os\.system|subprocess\.|subprocess\.Popen|os\.environ|os\.getenv)`, DetSSTI, "SSTI: OS command access", 9)
	add(`(?i)(class\.getResource|java\.lang|Runtime\.getRuntime|ProcessBuilder|javax\.script|org\.apache\.velocity)`, DetSSTI, "SSTI: Java class access", 9)
	add(`(?i)(<#assign\s|<#\w+\s|__\$\{.*\}__|<%=.*%>)`, DetSSTI, "SSTI: FreeMarker/ERB/Thymeleaf probe", 9)

	// RCE
	add(`(?i)(/bin/sh|/bin/bash|/bin/zsh|/bin/dash|/bin/ksh|/bin/csh|/bin/tcsh|/bin/fish)`, DetRCE, "RCE: shell path", 9)
	add(`(?i)(whoami$|whoami\s|id\s*;|\bid\s+\||whoami\s*;|whoami\s+\||pwd\s*;|\bcat\s+/etc\b)`, DetRCE, "RCE: basic recon command", 9)
	add(`(?i)(/dev/tcp/|/dev/udp/|bash\s+-i|sh\s+-i|/tmp/rev|nc\s+-e|socat\s+|ncat\s+)`, DetRCE, "RCE: reverse shell connection", 10)
	add(`(?i)([;&|`+"`"+`]\s*(?:curl|wget|fetch|axel|aria2c)\s+|(?:curl|wget|fetch|axel|aria2c)\s+(?:https?://|ftp://|file://))`, DetRCE, "RCE: download tool in shell context", 7)
	add(`(?i)(powershell|pwsh|cmd\.exe|cmd\.com|%COMSPEC%)`, DetRCE, "RCE: Windows shell", 8)
	add(`(?i)(certutil\s+-urlcache|bitsadmin\s+/transfer|mshta\s+|rundll32\s+|regsvr32\s+/[su])`, DetRCE, "RCE: LOLBin download", 9)
	add(`(?i)(eval\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|proc_close\s*\(|assert\s*\(|create_function\s*\(|call_user_func\s*\()`, DetRCE, "RCE: PHP function", 9)
	add(`(?i)(phpinfo\s*\(|ini_set\s*\(|ini_alter\s*\(|set_time_limit\s*\(|ignore_user_abort\s*\()`, DetRCE, "RCE: PHP config manipulation", 8)
	add(`(?i)(include\s*\(|require\s*\(|include_once\s*\(|require_once\s*\(|allow_url_include|auto_prepend_file|auto_append_file)`, DetRCE, "RCE: PHP file inclusion", 8)
	add(`(?i)(wmic\s+|ipconfig|systeminfo|tasklist|schtasks\s+|vssadmin\s+|net\s+(user|group|localgroup|view|share|use)\s+|net1\s+(user|group))`, DetRCE, "RCE: Windows recon", 7)
	add(`(?i)(python\s+-c|python3\s+-c|perl\s+-[eE]|ruby\s+-e|php\s+-r|node\s+-e|java\s+-jar|javaw\s+-jar)`, DetRCE, "RCE: code execution interpreter", 8)
	add(`(?i)(mail\s*\(|mb_send_mail\s*\(|imap_open\s*\()`, DetRCE, "RCE: PHP mail injection", 7)
	add(`(?i)(preg_replace\s*\(.*\/[eie]|mb_ereg_replace\s*\(.*\/[eie]|preg_filter\s*\(.*\/[eie])`, DetRCE, "RCE: regex eval modifier", 8)
	add(`(?i)(O:\d+:.*:\d+:\{|C:\d+:.*:\d+:\{|__destruct|__wakeup|__toString|__call|__callStatic|__get|__set|__invoke|__sleep|__isset|__unset)`, DetRCE, "RCE: deserialization gadget", 9)
	add(`(?i)(java\.lang\.Runtime|java\.lang\.ProcessBuilder|Runtime\.getRuntime|AccessController\.doPrivileged|Unsafe\.defineClass|URLClassLoader\.newInstance)`, DetRCE, "RCE: Java runtime access", 9)
	add("(?i)(\\$\\{.{0,200}?\\}\\s*\\(|`[^`\\s][^`]{0,100}`|\\$\\(.{0,200}?\\)|;.{0,100}?\\b(bash|sh|python|perl|ruby|php|node)\\s)", DetRCE, "RCE: command substitution", 7)
	add(`(?i)(\$IFS|\$\{IFS\}|\$\{IFS[+:}])`, DetRCE, "RCE: IFS variable substitution bypass", 8)
	add(`(?i)(base64\s+-d\s*[|]|base64\s+--decode\s*[|]|base64\s+-d\s*>\s*/)`, DetRCE, "RCE: base64 decode pipe to shell", 8)
	add(`(?i)(<\s*/etc/(passwd|shadow|hosts|group)|<\s*/proc/self/(environ|cmdline|fd))`, DetRCE, "RCE: stdin redirect to read system files", 8)
	add(`(?i)(>\s*/dev/tcp/|>\s*/dev/udp/|<<\s*EOF)`, DetRCE, "RCE: heredoc / device redirect", 7)
	add(`(?i)(cmd\.exe\s+[/\/][ck]|command\s*=\s*cmd|exec\s*=\s*cmd|wscript\.exe|cscript\.exe)`, DetRCE, "RCE: Windows command execution", 8)
	add(`(?i)(rO0AB|_\$\$ND_FUNC\$\$_)`, DetRCE, "RCE: serialized object fingerprint (Java/Node)", 9)

	// XXE / XML Injection (before path traversal to catch SYSTEM file references)
	add(`(?i)(<!DOCTYPE|<!ENTITY|<!ELEMENT|<!ATTLIST|<!NOTATION|%xxe|&xxe|<!\[%xxe)`, DetXXE, "XXE: entity declaration", 8)
	add(`(?i)(<!DOCTYPE\s+\w+\s+(SYSTEM|PUBLIC)\s+")`, DetXXE, "XXE: external DTD", 9)
	add(`(?i)(<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+")`, DetXXE, "XXE: external entity", 9)
	add(`(?i)(ENTITY\s+%\s+\w+\s+SYSTEM|<!ENTITY\s+%\s+\w+\s+")`, DetXXE, "XXE: parameter entity", 8)
	add(`(?i)(/xinclude|xmlns:xi=|xi:include|xi:fallback|xpointer|jar:file://|jar:http://|jar:https://)`, DetXXE, "XXE: XInclude / jar protocol attack", 8)
	add(`(?i)(<!DOCTYPE\s+[a-zA-Z].{0,300}?\[.{0,300}?<!ENTITY)`, DetXXE, "XXE: internal DTD entity", 8)

	// Path Traversal / LFI
	add(`(?i)(\.\./|\.\.\\|\.\.%2[fF]|\.\.%5[cC]|%2e%2e%2[fF]|%2e%2e%5[cC])`, DetPathTraversal, "LFI: directory traversal", 8)
	add(`(?i)(\.\.%00|%00\.\.|\.\.\\x00|\\x00\.\.|\.\.%2500|\.\.\\0)`, DetPathTraversal, "LFI: null byte injection", 8)
	add(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/etc/issue|/etc/group|/etc/fstab|/etc/crontab|/etc/mtab|/etc/resolv\.conf|/etc/hostname|/etc/hosts\.allow|/etc/hosts\.deny|/etc/ssh/sshd_config|/etc/ssh/ssh_config|/etc/ssl/certs)`, DetPathTraversal, "LFI: Unix system files", 9)
	add(`(?i)(/proc/self|/proc/1/|/proc/self/environ|/proc/self/fd|/proc/self/cmdline|/proc/self/maps|/proc/self/mem|/proc/self/root|/proc/self/cwd|/proc/net/|/proc/version|/proc/cpuinfo|/proc/meminfo|/proc/diskstats|/proc/modules|/proc/mounts|/proc/cmdline)`, DetPathTraversal, "LFI: /proc filesystem probe", 9)
	add(`(?i)(/windows/win\.ini|/windows/system32/|/windows/system|/windows/system|/windows/temp/|/boot\.ini|/autoexec\.bat|/windows/repair|/windows/regedit\.exe|/windows/explorer\.exe|/windows/notepad\.exe|/winnt/|pagefile\.sys|ntldr|NTDETECT\.COM|boot\.ini)`, DetPathTraversal, "LFI: Windows system files", 9)
	add(`(?i)(/\.ssh/|/\.git/)`, DetPathTraversal, "LFI: dotfile access", 8)
	add(`(?i)(/root/|/home/|/Users/)[^?]*/(\.ssh/|\.bash_history|\.bashrc|\.profile|\.zshrc|\.config|\.local|\.cache)`, DetPathTraversal, "LFI: user home data", 7)
	add(`(?i)(/var/log/|/var/mail/|/var/spool/|/var/backups/|/var/www/|/var/www/html/|/var/www/cgi-bin/|/usr/local/etc/|/usr/local/bin/)`, DetPathTraversal, "LFI: var/usr files", 6)
	add(`(?i)(\.\w+://\w+\.\w+\.\w+|\.\w+://\d+\.\d+\.\d+\.\d+)`, DetSSRF, "SSRF: protocol wrapper", 6)

	// LFI Wrapper Abuse
	add(`(?i)(phar://|zip://|rar://|bz2://|zlib://|data://text/plain|data://text/html|data://text/javascript|data://application|expect://|php://input|php://filter|php://temp|php://memory|php://stdin|php://stdout|php://output|compress\.zlib|compress\.bzip2|compress\.lzf)`, DetLFIWrapper, "LFI: PHP stream wrapper", 9)
	add(`(?i)(convert\.base64-encode|convert\.iconv|resource=.*\.php|read=convert\.base64)`, DetLFIWrapper, "LFI: filter chain wrapper", 8)

	// GraphQL Introspection
	add(`(?i)(__schema|__type|__typename|__field|__directive|__enumValue|__InputValue|IntrospectionQuery|type\s*\{[^}]*\})`, DetGraphQL, "GraphQL: introspection query", 8)
	add(`(?i)({__schema|{__type|{__typename)`, DetGraphQL, "GraphQL: schema discovery", 7)
	add(`(?i)(query\s*\{[^}]*\{[^}]*\}|mutation\s*\{[^}]*\{|subscription\s*\{)`, DetGraphQL, "GraphQL: operation discovery", 6)

	// WordPress Probe (before sensitive file to catch wp paths first)
	add(`(?i)(/wp-content/plugins/|/wp-content/themes/|/wp-content/uploads/|/wp-content/languages/|/wp-content/cache/|/wp-content/upgrade/|/wp-content/index\.php)`, DetWPProbe, "WordPress: content directory probe", 7)
	add(`(?i)(/wp-json/wp/v2/|/wp-json/oembed/|/wp-json/|/index\.php/rest_route)`, DetWPProbe, "WordPress: REST API probe", 7)
	add(`(?i)(/wp-includes/|/wp-admin/js/|/wp-admin/css/|/wp-admin/images/)`, DetWPProbe, "WordPress: core directory probe", 6)
	add(`(?i)(/xmlrpc\.php|/xmlrpc\.php\?rsd)`, DetWPProbe, "WordPress: XML-RPC probe", 8)
	add(`(?i)(/wp-cron\.php|/wp-activate\.php|/wp-signup\.php|/wp-trackback\.php|/wp-mail\.php|/wp-links-opml\.php)`, DetWPProbe, "WordPress: misc endpoint probe", 7)
	add(`(?i)(/wp-content/plugins/woocommerce|/wp-content/plugins/elementor|/wp-content/plugins/contact-form-7|/wp-content/plugins/wordfence|/wp-content/plugins/akismet|/wp-content/plugins/yoast|/wp-content/plugins/jetpack|/wp-content/plugins/redirection|/wp-content/plugins/tablepress|/wp-content/plugins/nextend|/wp-content/plugins/gravityforms)`, DetWPProbe, "WordPress: popular plugin probe", 7)
	add(`(?i)(/wp-content/upgrade/|/wp-content/backup-|/wp-content/ai1wm-backups|/wp-content/snapshots)`, DetWPProbe, "WordPress: backup directory probe", 8)
	add(`(?i)(/wp-content/debug\.log|/wp-content/error\.log|/wp-content/install\.php|/wp-content/setup\.php)`, DetWPProbe, "WordPress: sensitive file probe", 8)

	// Sensitive File Probe
	add(`(?i)((^|[/?&#])\.env([/?&#]|$)|\.env\.(local|prod|dev|stage|example))`, DetSensitiveFile, "Sensitive: environment file", 8)
	add(`(?i)(\.git/config|\.git/HEAD|\.git/index|\.git/objects|\.git/refs|\.gitignore|\.gitattributes|\.gitmodules)`, DetSensitiveFile, "Sensitive: git file", 8)
	add(`(?i)(wp-config\.php|wp-config\.txt|wp-config\.bak|wp-config\.old|wp-config\.inc)`, DetSensitiveFile, "Sensitive: WordPress config", 9)
	add(`(?i)(id_rsa|id_rsa\.pub|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|\.ssh/)`, DetSensitiveFile, "Sensitive: SSH key", 9)
	add(`(?i)(\.aws/credentials|\.aws/config|\.azure/credentials|\.azure/config|\.gcp/credentials|\.gcp/config|credentials\.json|service-account\.json|application_default_credentials\.json)`, DetSensitiveFile, "Sensitive: cloud credential file", 9)
	add(`(?i)(\.htaccess|\.htpasswd|\.htgroup)`, DetSensitiveFile, "Sensitive: htaccess file", 7)
	add(`(?i)(docker-compose\.yml|docker-compose\.override\.yml|Dockerfile|docker\.env)`, DetSensitiveFile, "Sensitive: Docker config", 6)
	add(`(?i)(composer\.json|composer\.lock|package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|Gemfile|Gemfile\.lock|Pipfile|Pipfile\.lock|setup\.py|requirements\.txt)`, DetSensitiveFile, "Sensitive: dependency file", 4)
	add(`(?i)(\.npmrc|\.yarnrc|\.gemrc|\.pypirc|\.pypi\.json|netrc|\.netrc|_netrc)`, DetSensitiveFile, "Sensitive: package manager config", 6)
	add(`(?i)(config\.php|config\.inc\.php|database\.php|db\.config|db\.php|connection\.php|settings\.php|settings\.json|app\.config|app\.conf|web\.config|application\.config)`, DetSensitiveFile, "Sensitive: app config file", 6)
	add(`(?i)(dump\.sql|backup\.sql|db\.sql|database\.sql|export\.sql|mysqldump|pgdump|db_backup|\.ibd|\.frm|\.myd|\.myi|\.sqlite|\.sqlite3|\.db)`, DetSensitiveFile, "Sensitive: database export", 8)
	add(`(?i)(\.bak|\.backup|\.~bk|\.sav|\.save|\.old|\.orig|\.sw[op]|\.copy|\.tmp|\.temp|\.dump|\.dump\.gz|\.backup\.gz|\.tar\.gz|\.zip|\.rar)`, DetSensitiveFile, "Sensitive: backup file", 5)
	add(`(?i)(/var/log/|access\.log|error\.log|debug\.log|app\.log|laravel\.log|wp-content/debug\.log)`, DetSensitiveFile, "Sensitive: log file", 5)
	add(`(?i)(\.pem|\.key|\.crt|\.cert|\.p12|\.pfx|\.jks|\.keystore|\.truststore|ca-certificates)`, DetSensitiveFile, "Sensitive: certificate/key file", 7)
	add(`(?i)(wp_filemanager\.php|wp-file-manager|elfinder|ckfinder|uploader\.php)`, DetSensitiveFile, "Sensitive: file manager probe", 8)
	add(`(?i)(phpinfo\.php|phpinfo\.txt|info\.php|test\.php|debug\.php|php\.php|info\.asp|info\.jsp|test\.asp|test\.jsp)`, DetSensitiveFile, "Sensitive: info page probe", 7)
	add(`(?i)(\.gitignore|\.dockerignore|\.editorconfig|\.prettierrc|\.eslintrc|\.jshintrc|\.stylelintrc|browserslist|postcss\.config|webpack\.config|vite\.config|rollup\.config)`, DetSensitiveFile, "Sensitive: dev config file", 4)

	// Admin Interface Probe
	add(`(?i)(/phpmyadmin|/pma|/mysql/admin|/adminer|/phppgadmin|/pgadmin|/admin/mysql)`, DetAdminProbe, "Admin: database interface", 8)
	add(`(?i)(/actuator/|/actuator/env|/actuator/health|/actuator/info|/actuator/metrics|/actuator/dump|/actuator/heapdump|/actuator/threaddump|/actuator/logfile|/actuator/shutdown|/actuator/configprops|/actuator/beans|/actuator/mappings|/actuator/conditions)`, DetAdminProbe, "Admin: Spring Boot actuator", 9)
	add(`(?i)(/console/|/h2-console|/h2/|/h2-console\.do|/h2-console\.action)`, DetAdminProbe, "Admin: H2 database console", 8)
	add(`(?i)(/heapdump|/heap\.dmp|/dump\.bin|/dumptofile|/jvm\.dump)`, DetAdminProbe, "Admin: heap dump access", 9)
	add(`(?i)(/jolokia|/jolokia/|/actuator/jolokia|/jmx|/jmx-console|/jmxinvoke)`, DetAdminProbe, "Admin: JMX/jolokia endpoint", 8)
	add(`(?i)^/(admin|administrator|adm|panel|cpanel|dashboard|manage|management|manager|backend|backoffice)(?:/|\.|$)`, DetAdminProbe, "Admin: admin panel", 6)
	add(`(?i)(/swagger|/swagger-ui|/swagger-resources|/api-docs|/v2/api-docs|/v3/api-docs|/openapi\.json|/swagger\.json)`, DetAdminProbe, "Admin: API documentation", 5)
	add(`(?i)(/solr/|/elasticsearch/|/zabbix/|/grafana/|/prometheus/|/kibana/|/nagios/|/cacti/|/munin/|/monitoring/)`, DetAdminProbe, "Admin: monitoring tool", 6)
	add(`(?i)(/wp-login\.php|/wp-admin/|/wp-admin/admin-ajax\.php|/administrator/)`, DetAdminProbe, "Admin: WordPress admin", 7)
	add(`(?i)(/\.svn/|/\.svn/entries|/\.svn/wc\.db|/\.DS_Store|/Thumbs\.db|/\.hg/|/\.bzr/|/WEB-INF/|/WEB-INF/web\.xml|/WEB-INF/database\.properties)`, DetAdminProbe, "Admin: VCS / metadata", 7)
	add(`(?i)(/debug/|/api/debug|/api/v1/debug|/debug\.php|/dev/|/api/dev|/test/|/testing/|/staging/)`, DetAdminProbe, "Admin: debug/dev endpoint", 6)
	add(`(?i)(/cgi-bin/phpinfo|/cgi-bin/php|/aws-tools/|/server-info|/server-status|/info\.aspx|/trace\.axd|/elb-status)`, DetAdminProbe, "Admin: server info page", 6)
	add(`(?i)(/\.aws/|/\.azure/|/\.gcp/|/credentials|/secrets|/tokens|/keys|/passwords)`, DetAdminProbe, "Admin: credential path", 7)

	// CGI Probe
	add(`(?i)(/cgi-bin/|/cgi-bin/test\.cgi|/cgi-sys/|/fcgi-bin/|/CGI-BIN/|/cgi-bin/.*\.(?:cgi|pl|fcgi))`, DetCGIProbe, "CGI: cgi-bin probe", 7)
	add(`(?i)(\.cgi(?:[/?&#]|$)|\.pl(?:[/?&#]|$)|\.fcgi(?:[/?&#]|$))`, DetCGIProbe, "CGI: script extension probe", 5)

	// Open Redirect
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=https?://)`, DetOpenRedirect, "Open redirect: URL parameter", 7)
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=//)`, DetOpenRedirect, "Open redirect: protocol-relative parameter", 7)
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=/\\)`, DetOpenRedirect, "Open redirect: backslash bypass", 7)
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=[^&]*@)`, DetOpenRedirect, "Open redirect: userinfo @ bypass", 7)
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=%2f%2f)`, DetOpenRedirect, "Open redirect: encoded protocol-relative", 7)

	// LDAP Injection
	add(`(?i)(\(&\(|\(\|\(|\)\|\(|\)&\(|\(uid=\*|\(cn=\*|\(samaccountname=\*|\(userAccountControl=|\(objectClass=|\(objectCategory=)`, DetLDAPInjection, "LDAP: filter injection", 8)
	add(`(?i)(%28%26%28|%28%7c%28|%29%7c%28|%29%26%28|%2a%29%28|%29%28%7c)`, DetLDAPInjection, "LDAP: URL-encoded filter injection", 7)

	// XPath Injection
	add(`(?i)('(\s*or\s*)'1'='1|"(\s*or\s*)"1"="1)`, DetXPathInjection, "XPath: tautology injection", 7)
	add(`(?i)(\]\|\s*//\s*\*|\.//\s*\*)`, DetXPathInjection, "XPath: path manipulation", 7)

	// CRLF / Log Injection
	add(`(?i)(%0[dD]%0[aA].{0,50}?[a-zA-Z-]+:|%0d%0a%0d%0a|%0d%0aContent-Length|%0d%0aLocation|%0d%0aSet-Cookie|%0d%0aWWW-Authenticate|%0d%0aHost:)`, DetCRLFInjection, "CRLF: HTTP header injection", 8)
	add(`(?i)(\r\n\s*[a-zA-Z-]+:|\r\n\r\n)`, DetCRLFInjection, "CRLF: literal header injection", 7)

	// Prototype Pollution
	add(`(?i)(__proto__|constructor\.prototype|\[constructor\]\.prototype)`, DetProtoPollution, "Prototype pollution: __proto__ access", 8)
	add(`(?i)(\"__proto__\"\s*:|\'__proto__\'\s*:|\"constructor\"\s*:\s*\{\s*\"prototype")`, DetProtoPollution, "Prototype pollution: JSON payload", 7)

	// SSI Injection
	add(`(?i)(<!--#include\s+|<!--#exec\s+|<!--#echo\s+|<!--#set\s+|<!--#printenv\s+|<!--#config\s+|<!--#flastmod\s+|<!--#fsize\s+)`, DetSSIInjection, "SSI: server-side include directive", 8)
	add(`(?i)(<!--#exec\s+cmd=|<!--#exec\s+cgi=|<!--#include\s+virtual=|<!--#include\s+file=)`, DetSSIInjection, "SSI: exec/include attempt", 9)
	add(`(?i)(#exec\s+cmd=|#exec\s+cgi=|#include\s+virtual=|#include\s+file=|#echo\s+var=)`, DetSSIInjection, "SSI: short-form directive", 7)

	// Scanner tools
	scannerUAs := []string{
		"sqlmap", "nikto", "dirbuster", "gobuster", "wfuzz", "nmap",
		"zap", "burpsuite", "burp suite", "acunetix", "netsparker", "arachni",
		"masscan", "hydra", "medusa", "openvas", "nessus", "snort",
		"libwww-perl", "scrapy", "aiohttp",
		"httpx", "nuclei", "ffuf", "katana", "jaeles", "arjun",
		"dalfox", "xsstrike", "commix", "tplmap", "nosqlmap",
		"whatweb", "wpscan", "joomscan", "droopescan",
		"qualys", "nexpose",
		"crackmapexec",
		"responder", "bettercap",
		"golismero", "wapiti", "skipfish", "uniscan", "webscarab",
		"paros", "vega", "appscan", "probely", "crashtest",
		"metasploit", "beef", "maltego", "shodan", "censys",
		"zgrab", "zmap", "massdns", "dnsx", "subfinder",
		"assetfinder", "amass", "waybackurls",
		"gau", "httprobe", "tlsx", "rustscan",
		"naabu", "maigret", "sherlock", "holehe", "socialscan",
	}
	scannerPat := "(?i)(" + strings.Join(scannerUAs, "|") + ")"
	addUA(scannerPat, DetScanner, "Scanner / automated tool detected", 9, true)

	// JWT / Token Abuse
	add(`(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.`, DetJWTAbuse, "JWT: token in URI (leaked credential)", 9)
	add(`(?i)Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ`, DetJWTAbuse, "JWT: Bearer token in URI (credential leak)", 8)
	addAuth(`(?i)alg\"?\s*:\s*\"none\"`, "JWT: none algorithm (auth bypass)", 10)
	addAuth(`(?i)kid\"?\s*:\s*\"[^"]*(?:\.\.\/|\.\.\\|%2e%2e)`, "JWT: path traversal in kid (injection risk)", 8)
	addAuth(`(?i)kid[=:][^&\s]*\.\./`, "JWT: kid path traversal", 9)
	addAuth(`(?i)kid[=:][^&\s]*[|;`+"`"+`]`, "JWT: kid command injection", 9)
	addAuth(`(?i)^Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.`, "JWT: Bearer token in Authorization header", 4)

	return p
}

var rawPatterns []compiledPattern

func init() {
	addRaw := func(pattern string, dtype DetectionType, desc string, confidence int) {
		lits := extractPureLiterals(pattern)
		rawPatterns = append(rawPatterns, compiledPattern{
			re:         compileLowercase(pattern),
			dtype:      dtype,
			desc:       desc,
			confidence: confidence,
			gate:       extractGate(pattern),
			literals:   lits,
		})
	}

	addRaw(`(?i)(%2e%2e%2f|%2e%2e/|\.%2e/|%2e\.%2f|%252e%252e%252f|\.\.%252f|.%2e%2e%2f|%c0%ae%c0%ae%c0%af|%c0%ae%c0%ae/|%252e%252e%252f|..%c0%af|%c0%ae%c0%ae)`, DetPathTraversal, "LFI: encoded path traversal (raw URI)", 7)
	addRaw(`(?i)(127\.0\.0\.1|localhost|0x7f000001|2130706433)(:|%3a|%3A)`, DetSSRF, "SSRF: internal host probe (raw URI)", 7)
	addRaw(`(?i)(%22|%27|%3c|%3e|%3C|%3E|%00|%0d|%0a|%09)`, DetXSS, "XSS: raw encoded payload", 3)
	addRaw(`(?i)(%2524{|%2525|%252e%252e%252f|%252f..|..%252f|%252f)`, DetPathTraversal, "LFI: double-encoded traversal (raw URI)", 8)
	addRaw(`(?i)(\.\w+://\w+\.\w+|\.\w+://\d+\.\d+\.\d+\.\d+)`, DetSSRF, "SSRF: protocol wrapper (raw URI)", 7)
	addRaw(`(?i)(\$%7bjndi|\$%7b.{0,100}?jndi|\$%7blower:jndi|\$%7bupper:jndi)`, DetLog4j, "Log4j: URL-encoded JNDI (raw URI)", 9)
	addRaw(`(?i)(%00|%0d|%0a|%0D|%0A|%09)`, DetCRLFInjection, "CRLF: encoded control char (raw URI)", 5)
	addRaw(`(?i)(%E5%98%8A|%E5%98%8D)`, DetCRLFInjection, "CRLF: Java ghost bits bypass (raw URI)", 8)

	rawMarkers, _, _ = buildMarkers(rawPatterns)
}
func (d *Detector) Detect(entry *types.LogEntry) *Detection {
	dets := d.DetectAll(entry)
	if len(dets) > 0 {
		first := dets[0]
		return &first
	}
	return nil
}

func decodeURI(uri string) string {
	// Split path and query: '+' is literal in the path but means space in
	// the query string. Decoding the whole URI with one function corrupts one
	// of the two halves.
	if idx := strings.IndexByte(uri, '?'); idx >= 0 {
		pathPart := uri[:idx]
		queryPart := uri[idx:]
		if p, err := url.PathUnescape(pathPart); err == nil {
			pathPart = p
		}
		if q, err := url.QueryUnescape(queryPart); err == nil {
			queryPart = q
		}
		return pathPart + queryPart
	}
	if u, err := url.PathUnescape(uri); err == nil {
		return u
	}
	// Fallback: manual percent-decode (handles invalid sequences gracefully).
	var b strings.Builder
	b.Grow(len(uri))
	for i := 0; i < len(uri); i++ {
		if c := uri[i]; c == '%' && i+2 < len(uri) {
			if hi, ok := unhex(uri[i+1]); ok {
				if lo, ok := unhex(uri[i+2]); ok {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(uri[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func (d *Detector) DetectAll(entry *types.LogEntry) []Detection {
	rawURI := entry.URI
	uri := decodeURI(rawURI)
	ua := entry.UserAgent
	auth := entry.Authorization

	stats := d.ipStats[entry.RemoteIP]
	if stats == nil {
		if d.ipCap > 0 && len(d.ipStats) >= d.ipCap {
			d.evictOldestIP()
		}
		stats = &IPDetStats{
			UserAgents:     make(map[string]struct{}),
			PathIDs:        make(map[string]map[int]struct{}),
			PathTimestamps: make(map[string][]time.Time),
			PathWriteCount: make(map[string]int),
		}
		d.ipStats[entry.RemoteIP] = stats
		d.ipNodes[entry.RemoteIP] = d.ipOrder.PushBack(entry.RemoteIP)
	} else {
		d.touchIP(entry.RemoteIP)
	}
	stats.Total++

	if entry.Status == 401 || entry.Status == 403 {
		stats.AuthFailures++
	}
	if entry.Status == 404 {
		stats.NotFound++
	}

	// Track timestamps per-path for beaconing detection (ring buffer).
	// Per-path, not per-IP, so that sequential ID enumeration (/api/users/1,
	// /api/users/2, ...) does not false-positive as C2 beaconing.
	pathKey := entry.Path()
	if pathKey != "" && len(stats.PathTimestamps) < pathCapPerIP {
		ts := stats.PathTimestamps[pathKey]
		stats.PathWriteCount[pathKey]++
		if len(ts) < beaconMaxSamples {
			ts = append(ts, entry.Timestamp)
		} else {
			ts[(stats.PathWriteCount[pathKey]-1)%beaconMaxSamples] = entry.Timestamp
		}
		stats.PathTimestamps[pathKey] = ts
	}

	index := make(map[DetectionType]int)
	var dets []Detection

	if ua := entry.UserAgent; ua != "" {
		if _, ok := stats.UserAgents[ua]; !ok {
			stats.UserAgents[ua] = struct{}{}
			n := len(stats.UserAgents)
			if n >= d.uaRotationThreshold && n%d.uaRotationThreshold == 0 {
				dets = append(dets, Detection{
					Type:       DetUARotation,
					IP:         entry.RemoteIP,
					URI:        entry.URI,
					Status:     entry.Status,
					Desc:       fmt.Sprintf("User-Agent rotation: %d distinct UAs from one IP", d.uaRotationThreshold),
					Confidence: 6,
					Techniques: detectionTechniques[DetUARotation],
				})
				index[DetUARotation] = 0
			}
		}
	}

	// BOLA / IDOR enumeration: track numeric IDs in path per IP
	if pathOnly := entry.Path(); pathOnly != "" {
		if tmpl, id, ok := extractIDFromPath(pathOnly); ok {
			ids := stats.PathIDs[tmpl]
			if ids == nil {
				ids = make(map[int]struct{})
				stats.PathIDs[tmpl] = ids
			}
			if len(ids) < objEnumMaxIDs {
				ids[id] = struct{}{}
			}
			if len(ids) >= objEnumThreshold {
				if _, ok := index[DetObjectEnum]; !ok {
					dets = append(dets, Detection{
						Type:       DetObjectEnum,
						IP:         entry.RemoteIP,
						URI:        entry.URI,
						Status:     entry.Status,
						Desc:       fmt.Sprintf("Object enumeration: %d distinct IDs on %s", len(ids), tmpl),
						Confidence: 7,
						Techniques: detectionTechniques[DetObjectEnum],
					})
					index[DetObjectEnum] = len(dets) - 1
				}
			}
		}
	}

	// Beaconing / C2: check inter-arrival regularity per-path.
	// A C2 beacon hits the SAME endpoint at regular intervals; object
	// enumeration hits DIFFERENT endpoints and must not trigger this.
	if pathKey != "" {
		ts := stats.PathTimestamps[pathKey]
		if len(ts) >= beaconMinSamples && isBeaconing(ts) {
			if _, ok := index[DetBeaconing]; !ok {
				dets = append(dets, Detection{
					Type:       DetBeaconing,
					IP:         entry.RemoteIP,
					URI:        entry.URI,
					Status:     entry.Status,
					Desc:       fmt.Sprintf("Beaconing: %d requests to %s with regular intervals (low jitter)", len(ts), pathKey),
					Confidence: 6,
					Techniques: detectionTechniques[DetBeaconing],
				})
				index[DetBeaconing] = len(dets) - 1
			}
		}
	}

	var appendDetection func(compiledPattern)
	consider := func(p compiledPattern, lowerSrc string) {
		var matched bool
		if len(p.literals) > 0 {
			for _, lit := range p.literals {
				if strings.Contains(lowerSrc, lit) {
					matched = true
					break
				}
			}
		} else {
			matched = p.re.MatchString(lowerSrc)
		}
		if !matched {
			return
		}
		appendDetection(p)
	}
	appendDetection = func(p compiledPattern) {
		techniques := p.techniques
		if len(techniques) == 0 {
			techniques = detectionTechniques[p.dtype]
		}
		det := Detection{
			Type:       p.dtype,
			IP:         entry.RemoteIP,
			URI:        entry.URI,
			Status:     entry.Status,
			Desc:       p.desc,
			Confidence: p.confidence,
			Techniques: techniques,
		}
		if idx, ok := index[p.dtype]; ok {
			if p.confidence > dets[idx].Confidence {
				dets[idx] = det
			}
			return
		}
		index[p.dtype] = len(dets)
		dets = append(dets, det)
	}

	lowerURI := strings.ToLower(uri)
	lowerUA := strings.ToLower(ua)
	lowerRaw := strings.ToLower(rawURI)
	authDecoded := decodeJWTHeader(auth)
	lowerAuth := strings.ToLower(authDecoded)

	uriTriage := matchMarkers(lowerURI, uriMarkers)
	uaTriage := matchMarkers(lowerUA, uaMarkers)
	authTriage := matchMarkers(lowerAuth, authMarkers)
	triageRawOK := matchMarkers(lowerRaw, rawMarkers)

	for _, p := range d.patterns {
		if p.hasMarkers {
			skip := false
			switch {
			case p.uaOnly:
				skip = !uaTriage
			case p.matchAuth:
				skip = !authTriage
			case p.matchUA:
				skip = !uriTriage && !uaTriage
			default:
				skip = !uriTriage
			}
			if skip {
				continue
			}
		}
		lowerSrc := lowerURI
		switch {
		case p.uaOnly:
			lowerSrc = lowerUA
		case p.matchAuth:
			lowerSrc = lowerAuth
		case p.matchUA:
			lowerSrc = lowerURI + "\n" + lowerUA
		}
		if p.gate != "" && !strings.Contains(lowerSrc, p.gate) {
			continue
		}
		consider(p, lowerSrc)
	}
	for _, p := range rawPatterns {
		if p.hasMarkers && !triageRawOK {
			continue
		}
		if p.gate != "" && !strings.Contains(lowerRaw, p.gate) {
			continue
		}
		consider(p, lowerRaw)
	}

	// Custom signatures deliberately bypass built-in marker triage: their
	// source and regex are user-defined, so an inferred marker could skip a
	// valid match. They still use compiled regexes and literal fast paths.
	headerText := ""
	for name, values := range entry.Headers {
		for _, value := range values {
			headerText += strings.ToLower(name) + ": " + strings.ToLower(value) + "\n"
		}
	}
	for _, p := range d.customPatterns {
		match := func(src string) bool {
			if len(p.literals) > 0 {
				for _, lit := range p.literals {
					if strings.Contains(src, lit) {
						return true
					}
				}
				return false
			}
			return p.re.MatchString(src)
		}
		matched := false
		switch p.source {
		case "uri":
			matched = match(lowerURI) || match(lowerRaw)
		case "header":
			matched = match(headerText)
		case "user_agent":
			matched = match(lowerUA)
		case "all":
			matched = match(lowerURI) || match(lowerRaw) || match(headerText) || match(lowerUA)
		}
		if matched {
			appendDetection(p)
		}
	}

	return dets
}

// extractIDFromPath extracts the trailing numeric ID from a path.
// /api/users/123 → template /api/users/{id}, ID 123.
// /api/orders/456/items → no match (ID not in last segment).
func extractIDFromPath(path string) (template string, id int, ok bool) {
	// Strip query string
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	// Find last path segment
	last := strings.LastIndexByte(path, '/')
	if last < 0 || last >= len(path)-1 {
		return "", 0, false
	}
	seg := path[last+1:]
	// Try to parse as integer
	n, err := parseInt(seg)
	if err != nil || n <= 0 {
		return "", 0, false
	}
	tmpl := path[:last+1] + "{id}"
	return tmpl, n, true
}

func parseInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		if n > (1<<31-1)/10 {
			return 0, fmt.Errorf("overflow")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// isBeaconing returns true if the timestamps show regular intervals
// (low jitter = C2 beaconing pattern). Computes coefficient of variation
// of inter-arrival times; CV < beaconJitterThreshold indicates beaconing.
func isBeaconing(timestamps []time.Time) bool {
	if len(timestamps) < beaconMinSamples {
		return false
	}
	// Sort timestamps (ring buffer may be out of order)
	sorted := make([]time.Time, len(timestamps))
	copy(sorted, timestamps)
	sortTimes(sorted)

	// Compute inter-arrival intervals
	intervals := make([]float64, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		intervals[i-1] = sorted[i].Sub(sorted[i-1]).Seconds()
	}

	// Compute mean
	var sum float64
	for _, iv := range intervals {
		sum += iv
	}
	mean := sum / float64(len(intervals))
	if mean <= 0 {
		return false
	}

	// Compute standard deviation
	var sqSum float64
	for _, iv := range intervals {
		diff := iv - mean
		sqSum += diff * diff
	}
	stddev := math.Sqrt(sqSum / float64(len(intervals)))

	// Coefficient of variation
	cv := stddev / mean
	return cv < beaconJitterThreshold
}

func sortTimes(t []time.Time) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j].Before(t[j-1]); j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}

func (d *Detector) IPStats() map[string]*IPDetStats {
	return d.ipStats
}

func (d *Detector) IsSuspicious(ip string, authThreshold, notFoundThreshold, totalThreshold int) bool {
	stats := d.ipStats[ip]
	if stats == nil {
		return false
	}
	if stats.AuthFailures >= authThreshold {
		return true
	}
	if stats.NotFound >= notFoundThreshold {
		return true
	}
	if stats.Total >= totalThreshold {
		return true
	}
	return false
}

// SigmaRuleInfo contiene le informazioni necessarie per generare una regola
// Sigma YAML per una categoria di detection.
type SigmaRuleInfo struct {
	Type           DetectionType
	Title          string
	Description    string
	URIPatterns    []string
	UAPatterns     []string
	AuthPatterns   []string
	RawPatterns    []string
	MaxConfidence  int
	Techniques     []string
	FalsePositives []string
}

// sigmaTitles mappa ogni DetectionType a un titolo e descrizione human-readable.
var sigmaTitles = map[DetectionType]struct{ title, desc string }{
	DetSQLInjection:   {"SQL Injection Detection", "Detects SQL injection attempts in Caddy access logs"},
	DetNoSQLi:         {"NoSQL Injection Detection", "Detects NoSQL injection attempts in Caddy access logs"},
	DetXSS:            {"Cross-Site Scripting Detection", "Detects XSS attempts in Caddy access logs"},
	DetSSTI:           {"Server-Side Template Injection Detection", "Detects SSTI attempts in Caddy access logs"},
	DetSSRF:           {"Server-Side Request Forgery Detection", "Detects SSRF attempts in Caddy access logs"},
	DetRCE:            {"Remote Code Execution Detection", "Detects RCE attempts in Caddy access logs"},
	DetPathTraversal:  {"Path Traversal Detection", "Detects path traversal and LFI attempts in Caddy access logs"},
	DetLFIWrapper:     {"LFI Wrapper Abuse Detection", "Detects PHP stream wrapper abuse in Caddy access logs"},
	DetGraphQL:        {"GraphQL Introspection Detection", "Detects GraphQL introspection queries in Caddy access logs"},
	DetLog4j:          {"Log4j/JNDI Detection", "Detects Log4j/JNDI injection attempts in Caddy access logs"},
	DetSensitiveFile:  {"Sensitive File Probe Detection", "Detects sensitive file access in Caddy access logs"},
	DetAdminProbe:     {"Admin Interface Probe Detection", "Detects admin interface probing in Caddy access logs"},
	DetWPProbe:        {"WordPress Probe Detection", "Detects WordPress probing in Caddy access logs"},
	DetCGIProbe:       {"CGI Probe Detection", "Detects CGI probing in Caddy access logs"},
	DetScanner:        {"Scanner Tool Detection", "Detects known scanner tools in Caddy access logs"},
	DetXXE:            {"XXE Detection", "Detects XXE injection attempts in Caddy access logs"},
	DetOpenRedirect:   {"Open Redirect Detection", "Detects open redirect attempts in Caddy access logs"},
	DetLDAPInjection:  {"LDAP Injection Detection", "Detects LDAP injection attempts in Caddy access logs"},
	DetXPathInjection: {"XPath Injection Detection", "Detects XPath injection attempts in Caddy access logs"},
	DetCRLFInjection:  {"CRLF Injection Detection", "Detects CRLF injection attempts in Caddy access logs"},
	DetProtoPollution: {"Prototype Pollution Detection", "Detects prototype pollution attempts in Caddy access logs"},
	DetSSIInjection:   {"SSI Injection Detection", "Detects SSI injection attempts in Caddy access logs"},
	DetUARotation:     {"User-Agent Rotation Detection", "Detects User-Agent rotation from a single IP"},
	DetJWTAbuse:       {"JWT Abuse Detection", "Detects JWT abuse and token leakage in Caddy access logs"},
	DetObjectEnum:     {"Object Enumeration Detection", "Detects BOLA/IDOR enumeration patterns in Caddy access logs"},
	DetBeaconing:      {"Beaconing Detection", "Detects C2 beaconing patterns (regular intervals) in Caddy access logs"},
}

var sigmaFalsePositives = map[DetectionType][]string{
	DetSQLInjection:  {"Legitimate queries containing SQL keywords"},
	DetXSS:           {"Legitimate HTML content in parameters"},
	DetScanner:       {"Security scans from authorized tools"},
	DetSensitiveFile: {"Legitimate access to dependency files"},
	DetAdminProbe:    {"Legitimate admin access from known IPs"},
	DetGraphQL:       {"Legitimate GraphQL introspection in development"},
	DetJWTAbuse:      {"Legitimate JWT tokens in Authorization headers"},
	DetObjectEnum:    {"Legitimate API pagination through sequential IDs"},
	DetBeaconing:     {"Legitimate polling/heartbeat endpoints"},
}

// ExportSigmaInfo restituisce le informazioni per generare regole Sigma YAML
// per ogni categoria di detection. I pattern sono raggruppati per source
// (URI, User-Agent, Authorization, raw URI).
func ExportSigmaInfo() []SigmaRuleInfo {
	patterns := getCompiledPatterns()
	byType := make(map[DetectionType]*SigmaRuleInfo)

	ensure := func(dt DetectionType) *SigmaRuleInfo {
		if r, ok := byType[dt]; ok {
			return r
		}
		info := sigmaTitles[dt]
		r := &SigmaRuleInfo{
			Type:           dt,
			Title:          info.title,
			Description:    info.desc,
			Techniques:     detectionTechniques[dt],
			FalsePositives: sigmaFalsePositives[dt],
		}
		byType[dt] = r
		return r
	}

	for _, p := range patterns {
		r := ensure(p.dtype)
		patStr := p.re.String()
		switch {
		case p.matchAuth:
			r.AuthPatterns = append(r.AuthPatterns, patStr)
		case p.uaOnly:
			r.UAPatterns = append(r.UAPatterns, patStr)
		case p.matchUA:
			r.URIPatterns = append(r.URIPatterns, patStr)
			r.UAPatterns = append(r.UAPatterns, patStr)
		default:
			r.URIPatterns = append(r.URIPatterns, patStr)
		}
		if p.confidence > r.MaxConfidence {
			r.MaxConfidence = p.confidence
		}
	}

	for _, p := range rawPatterns {
		r := ensure(p.dtype)
		r.RawPatterns = append(r.RawPatterns, p.re.String())
		if p.confidence > r.MaxConfidence {
			r.MaxConfidence = p.confidence
		}
	}

	result := make([]SigmaRuleInfo, 0, len(byType))
	for _, dt := range allDetectionTypes() {
		if r, ok := byType[dt]; ok {
			result = append(result, *r)
		}
	}
	return result
}

// allDetectionTypes returns all detection types in declaration order.
func allDetectionTypes() []DetectionType {
	return []DetectionType{
		DetSQLInjection, DetNoSQLi, DetXSS, DetSSTI, DetSSRF, DetRCE,
		DetPathTraversal, DetLFIWrapper, DetGraphQL, DetLog4j,
		DetSensitiveFile, DetAdminProbe, DetWPProbe, DetCGIProbe,
		DetScanner, DetXXE, DetOpenRedirect, DetLDAPInjection,
		DetXPathInjection, DetCRLFInjection, DetProtoPollution,
		DetSSIInjection, DetUARotation, DetJWTAbuse, DetObjectEnum, DetBeaconing,
	}
}

// SigmaLevel returns the Sigma severity level for a confidence value.
func SigmaLevel(confidence int) string {
	switch {
	case confidence >= 9:
		return "critical"
	case confidence >= 7:
		return "high"
	case confidence >= 5:
		return "medium"
	default:
		return "low"
	}
}

// decodeJWTHeader extracts and base64-decodes the header segment of a JWT
// from an Authorization header value. JWT patterns like alg":"none" must
// match against the decoded JSON, not the raw base64 header. Returns the
// raw input unchanged if it's not a Bearer JWT, so non-JWT auth schemes
// (Basic, Digest) are still passed through to the patterns.
func decodeJWTHeader(auth string) string {
	if auth == "" {
		return ""
	}
	// Strip "Bearer " prefix
	token := auth
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = token[7:]
	}
	// JWT format: header.payload.signature
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return auth
	}
	header := token[:dot]
	// base64url decode (RawURLEncoding handles unpadded base64url)
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return auth
	}
	return auth + "\n" + string(decoded)
}
