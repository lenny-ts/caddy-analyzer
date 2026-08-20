package analysis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestOperationalEngineProcess(t *testing.T) {
	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	entries := []*types.OperationalEntry{
		{Timestamp: base, Level: "info", Logger: "admin", Msg: "serving initial configuration"},
		{Timestamp: base.Add(5 * time.Second), Level: "info", Logger: "tls", Msg: "certificate obtained successfully"},
		{Timestamp: base.Add(10 * time.Second), Level: "error", Logger: "http", Msg: "dialing upstream"},
		{Timestamp: base.Add(15 * time.Second), Level: "warn", Logger: "tls", Msg: "certificate renewal approaching"},
		{Timestamp: base.Add(20 * time.Second), Level: "", Logger: "admin", Msg: "stopped"},
	}

	eng := NewOperationalEngine(types.Filters{})
	for _, e := range entries {
		eng.Process(e)
	}

	s := eng.Stats()
	if s.TotalEvents != 5 {
		t.Errorf("TotalEvents: got %d, want 5", s.TotalEvents)
	}
	if s.Errors != 1 {
		t.Errorf("Errors: got %d, want 1", s.Errors)
	}
	if s.LevelCounts["info"] != 3 { // includes the empty-level entry
		t.Errorf("LevelCounts[info]: got %d, want 3", s.LevelCounts["info"])
	}
	if s.LevelCounts["error"] != 1 {
		t.Errorf("LevelCounts[error]: got %d, want 1", s.LevelCounts["error"])
	}
	if s.LevelCounts["warn"] != 1 {
		t.Errorf("LevelCounts[warn]: got %d, want 1", s.LevelCounts["warn"])
	}
	if s.LoggerCounts["tls"] != 2 {
		t.Errorf("LoggerCounts[tls]: got %d, want 2", s.LoggerCounts["tls"])
	}
	if s.LoggerCounts["admin"] != 2 {
		t.Errorf("LoggerCounts[admin]: got %d, want 2", s.LoggerCounts["admin"])
	}
	if s.MsgCounts["dialing upstream"] != 1 {
		t.Errorf("MsgCounts[dialing upstream]: got %d, want 1", s.MsgCounts["dialing upstream"])
	}
	if !s.StartTime.Equal(base) {
		t.Errorf("StartTime: got %v, want %v", s.StartTime, base)
	}
	if !s.EndTime.Equal(base.Add(20 * time.Second)) {
		t.Errorf("EndTime: got %v, want %v", s.EndTime, base.Add(20*time.Second))
	}
}

func TestOperationalEngineProcessZeroTimestamp(t *testing.T) {
	eng := NewOperationalEngine(types.Filters{})
	eng.Process(&types.OperationalEntry{Level: "info", Logger: "tls", Msg: "no timestamp"})
	s := eng.Stats()
	if s.TotalEvents != 1 {
		t.Fatalf("TotalEvents: got %d, want 1", s.TotalEvents)
	}
	if !s.StartTime.IsZero() || !s.EndTime.IsZero() {
		t.Errorf("zero-timestamp entry should not modify StartTime/EndTime; got start=%v end=%v", s.StartTime, s.EndTime)
	}
}

func TestMatchOperational(t *testing.T) {
	ts := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	entry := &types.OperationalEntry{
		Timestamp: ts,
		Level:     "error",
		Logger:    "http",
		Msg:       "dialing upstream",
		Extra: map[string]json.RawMessage{
			"upstream": json.RawMessage(`"10.0.0.5:8080"`),
		},
	}

	tests := []struct {
		name    string
		filters types.Filters
		want    bool
	}{
		{
			name:    "no filters",
			filters: types.Filters{},
			want:    true,
		},
		{
			name: "level match",
			filters: types.Filters{
				Level: []string{"error", "warn"},
			},
			want: true,
		},
		{
			name: "level no match",
			filters: types.Filters{
				Level: []string{"info", "debug"},
			},
			want: false,
		},
		{
			name: "level case insensitive",
			filters: types.Filters{
				Level: []string{"ERROR"},
			},
			want: true,
		},
		{
			name: "empty entry level defaults to info — matches info filter",
			filters: types.Filters{
				Level: []string{"info"},
			},
			want: true,
		},
		{
			name: "from boundary inclusive",
			filters: types.Filters{
				HasFrom: true,
				From:    ts,
			},
			want: true,
		},
		{
			name: "from after entry",
			filters: types.Filters{
				HasFrom: true,
				From:    ts.Add(1 * time.Second),
			},
			want: false,
		},
		{
			name: "to boundary inclusive",
			filters: types.Filters{
				HasTo: true,
				To:    ts,
			},
			want: true,
		},
		{
			name: "to before entry",
			filters: types.Filters{
				HasTo: true,
				To:    ts.Add(-1 * time.Second),
			},
			want: false,
		},
		{
			name: "grep matches msg",
			filters: types.Filters{
				GrepPattern: "upstream",
			},
			want: true,
		},
		{
			name: "grep matches logger",
			filters: types.Filters{
				GrepPattern: "http",
			},
			want: true,
		},
		{
			name: "grep matches extra field key",
			filters: types.Filters{
				GrepPattern: "10.0.0.5",
			},
			want: true,
		},
		{
			name: "grep no match",
			filters: types.Filters{
				GrepPattern: "nonexistent",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The "empty entry level defaults to info" case needs a
			// separate entry with an empty Level field.
			e := entry
			if tt.name == "empty entry level defaults to info — matches info filter" {
				e = &types.OperationalEntry{
					Timestamp: ts,
					Level:     "",
					Logger:    "admin",
					Msg:       "started",
				}
			}
			got := MatchOperational(e, tt.filters)
			if got != tt.want {
				t.Errorf("MatchOperational: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchOperationalProcessIntegration(t *testing.T) {
	// Process only accepts entries that pass MatchOperational, so a
	// level filter should reduce TotalEvents accordingly.
	eng := NewOperationalEngine(types.Filters{
		Level: []string{"error"},
	})
	entries := []*types.OperationalEntry{
		{Level: "info", Logger: "admin", Msg: "started"},
		{Level: "error", Logger: "http", Msg: "failed"},
		{Level: "warn", Logger: "tls", Msg: "renewal"},
	}
	for _, e := range entries {
		eng.Process(e)
	}
	s := eng.Stats()
	if s.TotalEvents != 1 {
		t.Errorf("TotalEvents: got %d, want 1 (only error level)", s.TotalEvents)
	}
	if s.Errors != 1 {
		t.Errorf("Errors: got %d, want 1", s.Errors)
	}
}
