package analysis

import (
	"encoding/json"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// FuzzMatchOperationalProcess exercises the operational filter and
// aggregation engine with arbitrary entry fields and grep patterns.
// Invariants checked:
//  1. MatchOperational never panics on any input combination.
//  2. OperationalEngine.Process never panics and only ever increments
//     counters (stats stay internally consistent).
//  3. An entry rejected by MatchOperational is never counted by Process.
//
// Go's regexp (RE2) has linear-time matching, so hostile grep patterns
// cannot trigger catastrophic backtracking; this fuzz target guards the
// rest of the pipeline against malformed field values instead.
func FuzzMatchOperationalProcess(f *testing.F) {
	f.Add("error", "http.log.error", "dialing upstream", "upstream", "10.0.0.5:8080", "error")
	f.Add("", "", "", "", "", "")
	f.Add("info", "tls", "certificate obtained successfully", "identifier", "example.com", "cert")
	f.Add("weird level", "logger with spaces", "msg", "key", "=cmd|'/c calc'!A0", "(")
	f.Add("error", "l", "m", "k", "\x1b[31mred\x1b[0m", "[a-")

	f.Fuzz(func(t *testing.T, level, logger, msg, extraKey, extraVal, grep string) {
		entry := &types.OperationalEntry{
			Level:  level,
			Logger: logger,
			Msg:    msg,
			Extra: map[string]json.RawMessage{
				extraKey: json.RawMessage(extraVal),
			},
		}
		filters := types.Filters{GrepPattern: grep}

		matched := MatchOperational(entry, filters)

		eng := NewOperationalEngine(filters)
		eng.Process(entry)
		s := eng.Stats()

		if !matched && s.TotalEvents != 0 {
			t.Fatalf("entry rejected by MatchOperational was still counted (TotalEvents=%d)", s.TotalEvents)
		}
		if matched && s.TotalEvents != 1 {
			t.Fatalf("matched entry not counted exactly once (TotalEvents=%d)", s.TotalEvents)
		}
	})
}
