package parser

import (
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// FuzzParse feeds arbitrary log lines into the parser, which sits at the
// trust boundary between untrusted Caddy output and the rest of the tool.
// Invariants checked:
//  1. Parse never panics on any input.
//  2. An error implies a nil entry, and vice versa (nil, nil is allowed
//     for blank lines).
//  3. A non-nil entry is always one of the two concrete Entry types.
//  4. The Raw field preserves the trimmed input line.
func FuzzParse(f *testing.F) {
	f.Add(`{"level":"info","ts":1700000000.123,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/index.html","host":"example.com","remote_ip":"1.2.3.4"},"status":200,"size":1024,"duration":0.005}`)
	f.Add(`{"level":"error","ts":1700000000.789,"logger":"http.log.error","msg":"dialing upstream","upstream":"10.0.0.5:8080","error":"connection refused"}`)
	f.Add(`{"level":"info","ts":1700000000.5,"msg":"serving initial configuration"}`)
	f.Add(`{}`)
	f.Add(`{"msg":"handled request"}`)
	f.Add(`{"ts":"not-a-number","msg":"handled request"}`)
	f.Add(`{"level":123,"ts":[1,2],"logger":{"nested":true},"msg":"handled request"}`)
	f.Add(`not json at all`)
	f.Add(`   `)
	f.Add(`[1,2,3]`)
	f.Add(`"just a string"`)

	f.Fuzz(func(t *testing.T, line string) {
		entry, err := Parse(line)
		if err != nil {
			if entry != nil {
				t.Fatalf("Parse(%q) returned both error %v and entry %T", line, err, entry)
			}
			return
		}
		if entry == nil {
			return
		}
		switch e := entry.(type) {
		case *types.LogEntry:
			checkRaw(t, line, e.Raw)
		case *types.OperationalEntry:
			checkRaw(t, line, e.Raw)
		default:
			t.Fatalf("Parse(%q) returned unexpected entry type %T", line, entry)
		}
	})
}

func checkRaw(t *testing.T, line, raw string) {
	t.Helper()
	if want := strings.TrimSpace(line); raw != want {
		t.Fatalf("Raw field %q does not preserve trimmed input %q", raw, want)
	}
}
