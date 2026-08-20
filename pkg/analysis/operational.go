package analysis

import (
	"strings"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// OperationalEngine aggregates non-HTTP Caddy log entries (config loads,
// TLS handshakes, upstream errors, etc.) into an OperationalStats. It is
// intentionally separate from Engine so HTTP-specific fields, detectors,
// and the LRU sliding window never see operational data.
type OperationalEngine struct {
	stats   *types.OperationalStats
	filters types.Filters
}

func NewOperationalEngine(filters types.Filters) *OperationalEngine {
	return &OperationalEngine{
		stats:   types.NewOperationalStats(),
		filters: filters,
	}
}

func (e *OperationalEngine) Stats() *types.OperationalStats {
	return e.stats
}

func (e *OperationalEngine) Process(entry *types.OperationalEntry) {
	if !MatchOperational(entry, e.filters) {
		return
	}
	s := e.stats
	s.TotalEvents++

	if !entry.Timestamp.IsZero() {
		if s.StartTime.IsZero() || entry.Timestamp.Before(s.StartTime) {
			s.StartTime = entry.Timestamp
		}
		if entry.Timestamp.After(s.EndTime) {
			s.EndTime = entry.Timestamp
		}
	}

	lvl := entry.Level
	if lvl == "" {
		lvl = "info"
	}
	s.LevelCounts[lvl]++
	s.LoggerCounts[entry.Logger]++
	s.MsgCounts[entry.Msg]++
	if lvl == "error" {
		s.Errors++
	}
}

// MatchOperational applies the subset of filters that are meaningful for
// non-HTTP entries: time range, level, and grep (matched against msg,
// logger, and extra fields). HTTP-specific filters (status, method, path,
// latency, size, bots) are ignored.
func MatchOperational(entry *types.OperationalEntry, filters types.Filters) bool {
	if filters.HasFrom && entry.Timestamp.Before(filters.From) {
		return false
	}
	if filters.HasTo && entry.Timestamp.After(filters.To) {
		return false
	}
	if len(filters.Level) > 0 {
		lvl := entry.Level
		if lvl == "" {
			lvl = "info"
		}
		found := false
		for _, l := range filters.Level {
			if strings.EqualFold(l, lvl) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if filters.GrepPattern != "" {
		var b strings.Builder
		b.WriteString(entry.Msg)
		b.WriteByte(' ')
		b.WriteString(entry.Logger)
		for k, v := range entry.Extra {
			b.WriteByte(' ')
			b.WriteString(k)
			b.WriteByte('=')
			b.Write(v)
		}
		if !grepCompile(filters.GrepPattern).match(b.String()) {
			return false
		}
	}
	return true
}
