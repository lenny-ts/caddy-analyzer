package cmd

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestAcceptEntryAppliesFollowModeFilters(t *testing.T) {
	get := &types.LogEntry{Method: "GET", Status: 200, URI: "/index.html", RemoteIP: "1.1.1.1"}
	post := &types.LogEntry{Method: "POST", Status: 500, URI: "/admin", RemoteIP: "8.8.8.8"}
	ok500 := &types.LogEntry{Method: "GET", Status: 500, URI: "/fail", RemoteIP: "9.9.9.9"}

	cases := []struct {
		name    string
		entry   *types.LogEntry
		filters types.Filters
		want    bool
	}{
		{"method POST keeps POST", post, types.Filters{Method: "POST"}, true},
		{"method POST drops GET", get, types.Filters{Method: "POST"}, false},
		{"status 500 keeps 500", ok500, types.Filters{Status: []int{500}}, true},
		{"status 500 drops 200", get, types.Filters{Status: []int{500}}, false},
		{"only-5xx keeps 500", post, types.Filters{Only5xx: true}, true},
		{"only-5xx drops 200", get, types.Filters{Only5xx: true}, false},
		{"ip keeps match", get, types.Filters{RemoteIP: "1.1.1.1"}, true},
		{"ip drops other", post, types.Filters{RemoteIP: "1.1.1.1"}, false},
		{"grep admin keeps /admin", post, types.Filters{GrepPattern: "admin"}, true},
		{"grep admin drops /index", get, types.Filters{GrepPattern: "admin"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := *tc.entry
			if got := acceptEntry(&entry, tc.filters); got != tc.want {
				t.Fatalf("acceptEntry = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAcceptEntryRewritesForwardedIPBeforeFilter(t *testing.T) {
	entry := &types.LogEntry{
		Method:       "GET",
		Status:       200,
		URI:          "/",
		RemoteIP:     "10.0.0.1",
		ForwardedFor: []string{"203.0.113.9"},
	}
	filters := types.Filters{TrustForwarded: true, RemoteIP: "203.0.113.9"}
	if !acceptEntry(entry, filters) {
		t.Fatal("forwarded public client IP should match after rewrite")
	}
	if entry.RemoteIP != "203.0.113.9" {
		t.Fatalf("RemoteIP = %q, want rewritten client address", entry.RemoteIP)
	}
}

func TestTopAndTailRewriteForwardedIP(t *testing.T) {
	entry := &types.LogEntry{
		RemoteIP:     "10.0.0.1",
		ForwardedFor: []string{"203.0.113.9"},
	}
	applyForwarded(entry, types.Filters{TrustForwarded: true})
	if entry.RemoteIP != "203.0.113.9" {
		t.Fatalf("RemoteIP = %q, want rewritten client address", entry.RemoteIP)
	}
}

type countingGeo struct {
	hits []string
}

func (c *countingGeo) Lookup(ip string) (types.GeoInfo, error) {
	c.hits = append(c.hits, ip)
	return types.GeoInfo{CountryCode: "US"}, nil
}

func TestTakeEntryRunsNextOnlyForAcceptedRows(t *testing.T) {
	filters := types.Filters{Method: "POST"}
	geo := &countingGeo{}
	get := &types.LogEntry{Method: "GET", Status: 200, URI: "/index.html", RemoteIP: "1.1.1.1"}
	post := &types.LogEntry{Method: "POST", Status: 200, URI: "/api", RemoteIP: "8.8.8.8"}

	var processed []string
	next := func(e *types.LogEntry) { processed = append(processed, e.Method) }

	takeEntry(get, filters, geo, next)
	takeEntry(post, filters, geo, next)

	if len(processed) != 1 || processed[0] != "POST" {
		t.Fatalf("processed = %v, want [POST]", processed)
	}
	if get.Geo.CountryCode != "" {
		t.Fatal("rejected entry must not be enriched")
	}
	if post.Geo.CountryCode != "US" {
		t.Fatalf("accepted entry Geo.CountryCode = %q", post.Geo.CountryCode)
	}
	if len(geo.hits) != 1 || geo.hits[0] != "8.8.8.8" {
		t.Fatalf("lookups = %v, want only the accepted IP", geo.hits)
	}
}

func TestFollowAndIntervalCallTakeEntry(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "root.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"runFollowMode": false, "runIntervalMode": false}
	followPassesProcess := false
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Body == nil {
			return true
		}
		name := fn.Name.Name
		if _, tracked := want[name]; !tracked {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "takeEntry" {
				return true
			}
			want[name] = true
			if name == "runFollowMode" && len(call.Args) == 4 {
				if sel, ok := call.Args[3].(*ast.SelectorExpr); ok && sel.Sel.Name == "Process" {
					followPassesProcess = true
				}
			}
			return true
		})
		return true
	})
	for name, called := range want {
		if !called {
			t.Errorf("%s does not call takeEntry", name)
		}
	}
	if !followPassesProcess {
		t.Error("runFollowMode must pass engine.Process to takeEntry")
	}
}

func TestRunIntervalModeDoesNotBucketRejectedRows(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	outPath := filepath.Join(dir, "out.txt")

	// GET at t=1000s and POST at t=4600s sit in different 1h buckets.
	// Filtering to POST must not emit the empty GET bucket.
	const getLine = `{"level":"info","ts":1000.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"1.1.1.1","method":"GET","uri":"/","headers":{"User-Agent":["curl"]}},"status":200}`
	const postLine = `{"level":"info","ts":4600.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"8.8.8.8","method":"POST","uri":"/api","headers":{"User-Agent":["curl"]}},"status":200}`
	if err := os.WriteFile(logPath, []byte(getLine+"\n"+postLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origFormat, origOutput, origDetect, origTop := flagFormat, flagOutput, flagDetect, flagTop
	defer func() {
		flagFormat, flagOutput, flagDetect, flagTop = origFormat, origOutput, origDetect, origTop
	}()
	flagFormat = "json"
	flagOutput = outPath
	flagDetect = false
	flagTop = 10

	err := runIntervalMode(
		context.Background(),
		[]types.LogSource{{Type: types.SourceFile, Path: logPath}},
		types.Filters{Method: "POST"},
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if n := strings.Count(text, "\n--- "); n != 1 {
		t.Fatalf("interval reports = %d, want 1 (rejected GET must not open a bucket)\n%s", n, text)
	}
	if !strings.Contains(text, `"POST"`) {
		t.Fatalf("expected POST in the kept bucket, got:\n%s", text)
	}
	if strings.Contains(text, `"GET"`) {
		t.Fatalf("rejected GET must not appear in the report:\n%s", text)
	}
}

func TestPrepareEntryEnrichesBeforeMatchForGeoFilters(t *testing.T) {
	geo := &countingGeo{}

	// countingGeo always returns US: with --country IT the row must be
	// dropped even though enrichment happened before matching.
	it := &types.LogEntry{Method: "GET", Status: 200, URI: "/", RemoteIP: "1.1.1.1"}
	if prepareEntry(it, types.Filters{Country: []string{"IT"}}, geo) {
		t.Fatal("country allowlist must drop a US-enriched row")
	}
	if it.Geo.CountryCode != "US" {
		t.Fatalf("rejected row Geo = %q, want enriched before match", it.Geo.CountryCode)
	}

	us := &types.LogEntry{Method: "GET", Status: 200, URI: "/", RemoteIP: "8.8.8.8"}
	if !prepareEntry(us, types.Filters{ExcludeCountry: []string{"CN"}}, geo) {
		t.Fatal("denylist must keep a non-CN row")
	}
	if len(geo.hits) != 2 || geo.hits[0] != "1.1.1.1" || geo.hits[1] != "8.8.8.8" {
		t.Fatalf("lookups = %v, want both rows looked up", geo.hits)
	}

	// Non-geo runs keep the filter-first optimization: rejected rows are
	// never looked up.
	geo2 := &countingGeo{}
	get := &types.LogEntry{Method: "GET", Status: 200, URI: "/"}
	if prepareEntry(get, types.Filters{Method: "POST"}, geo2) {
		t.Fatal("method filter must drop GET")
	}
	if len(geo2.hits) != 0 {
		t.Fatalf("lookups = %v, want none for rejected rows without geo filters", geo2.hits)
	}
}
