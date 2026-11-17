package doctor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestReportSummaryAndExitCode(t *testing.T) {
	tests := []struct {
		name       string
		checks     []Check
		wantOK     int
		wantWarn   int
		wantFail   int
		wantCrit   int
		wantStatus Status
		wantExit   int
	}{
		{
			name:       "empty",
			checks:     nil,
			wantStatus: StatusOK,
			wantExit:   0,
		},
		{
			name:       "all ok",
			checks:     []Check{Pass("a", "ok"), Pass("b", "ok")},
			wantOK:     2,
			wantStatus: StatusOK,
			wantExit:   0,
		},
		{
			name:       "warning only",
			checks:     []Check{Pass("a", "ok"), Warning("b", "warn")},
			wantOK:     1,
			wantWarn:   1,
			wantStatus: StatusWarn,
			wantExit:   0,
		},
		{
			name:       "non-critical failure",
			checks:     []Check{Failure("a", "bad")},
			wantFail:   1,
			wantStatus: StatusFail,
			wantExit:   0,
		},
		{
			name:       "critical failure",
			checks:     []Check{Warning("a", "warn"), CriticalFailure("b", "bad")},
			wantWarn:   1,
			wantFail:   1,
			wantCrit:   1,
			wantStatus: StatusFail,
			wantExit:   1,
		},
		{
			name:       "multiple critical failures",
			checks:     []Check{CriticalFailure("a", "bad"), CriticalFailure("b", "worse")},
			wantFail:   2,
			wantCrit:   2,
			wantStatus: StatusFail,
			wantExit:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport([]Group{{Name: "Test", Checks: tt.checks}})
			if r.Summary.OK != tt.wantOK || r.Summary.Warn != tt.wantWarn ||
				r.Summary.Fail != tt.wantFail || r.Summary.CriticalFailures != tt.wantCrit {
				t.Fatalf("summary counts = %+v, want ok=%d warn=%d fail=%d critical=%d",
					r.Summary, tt.wantOK, tt.wantWarn, tt.wantFail, tt.wantCrit)
			}
			if r.Summary.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", r.Summary.Status, tt.wantStatus)
			}
			if r.Summary.ExitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d", r.Summary.ExitCode, tt.wantExit)
			}
		})
	}
}

func TestWriteJSONShape(t *testing.T) {
	r := NewReport([]Group{
		{Name: "Runtime", Checks: []Check{
			Pass("runtime.version", "version: test"),
			CriticalFailure("runtime.state_dir", "state directory not writable"),
		}},
	})

	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var got struct {
		Groups []struct {
			Name   string `json:"name"`
			Checks []struct {
				ID       string `json:"id"`
				Status   Status `json:"status"`
				Message  string `json:"message"`
				Critical bool   `json:"critical"`
			} `json:"checks"`
		} `json:"groups"`
		Summary struct {
			OK               int    `json:"ok"`
			Warn             int    `json:"warn"`
			Fail             int    `json:"fail"`
			CriticalFailures int    `json:"critical_failures"`
			Status           Status `json:"status"`
			ExitCode         int    `json:"exit_code"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal JSON: %v\n%s", err, buf.String())
	}

	if len(got.Groups) != 1 || got.Groups[0].Name != "Runtime" {
		t.Fatalf("groups = %+v, want one Runtime group", got.Groups)
	}
	if len(got.Groups[0].Checks) != 2 {
		t.Fatalf("checks = %d, want 2", len(got.Groups[0].Checks))
	}
	first := got.Groups[0].Checks[0]
	if first.ID != "runtime.version" || first.Status != StatusOK || first.Critical {
		t.Errorf("first check = %+v", first)
	}
	second := got.Groups[0].Checks[1]
	if second.ID != "runtime.state_dir" || second.Status != StatusFail || !second.Critical {
		t.Errorf("second check = %+v", second)
	}
	if got.Summary.OK != 1 || got.Summary.Fail != 1 || got.Summary.CriticalFailures != 1 {
		t.Errorf("summary counts = %+v", got.Summary)
	}
	if got.Summary.Status != StatusFail || got.Summary.ExitCode != 1 {
		t.Errorf("summary status/exit = %q/%d", got.Summary.Status, got.Summary.ExitCode)
	}
}

func TestWriteText(t *testing.T) {
	r := NewReport([]Group{
		{Name: "Runtime", Checks: []Check{Pass("a", "version ok")}},
		{Name: "Guard", Checks: []Check{Warning("b", "no firewall"), Failure("c", "probe failed")}},
	})

	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Caddy Analyzer Doctor",
		"Runtime",
		"  [OK] version ok",
		"Guard",
		"  [WARN] no firewall",
		"  [FAIL] probe failed",
		"Summary: 1 OK, 1 WARN, 1 FAIL",
		"Result: PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteTextCriticalFailure(t *testing.T) {
	r := NewReport([]Group{{Name: "Guard", Checks: []Check{CriticalFailure("a", "no backend")}}})

	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "Result: FAIL (1 critical)") {
		t.Fatalf("output = %s", buf.String())
	}
}
