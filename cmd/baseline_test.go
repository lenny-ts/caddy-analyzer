package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/output"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

var baseTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestLoadBaselineRejectsWrongVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":99}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(path); err == nil || !strings.Contains(err.Error(), "unsupported baseline schema_version") {
		t.Fatalf("loadBaseline error = %v", err)
	}
}

func TestValidateBaselinePathRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "link.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := validateBaselinePath(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestComparisonThresholdAndJSON(t *testing.T) {
	base := types.NewStats()
	base.TotalRequests = 100
	base.Errors = 1
	base.DurationSum = 10
	base.StartTime = baseTime
	base.EndTime = baseTime.Add(10 * time.Second)
	current := types.NewStats()
	current.TotalRequests = 100
	current.Errors = 2
	current.DurationSum = 20
	current.StartTime = baseTime
	current.EndTime = baseTime.Add(10 * time.Second)
	oldThreshold := flagThreshold
	flagThreshold = 5
	defer func() { flagThreshold = oldThreshold }()
	baseOps := types.NewOperationalStats()
	currentOps := analysis.NewOperationalEngine(types.Filters{})
	result := compareBaseline(baselineFile{Stats: base, OperationalStats: baseOps}, types.Filters{}, analysis.NewFromStats(types.Filters{}, current), currentOps)
	if !result.Regression {
		t.Fatal("expected regression above threshold")
	}
	var out bytes.Buffer
	if err := printComparison(&out, result, output.FormatJSON); err != nil {
		t.Fatal(err)
	}
	var decoded comparisonResult
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Threshold != 5 || !decoded.Regression {
		t.Fatalf("decoded comparison = %+v", decoded)
	}
}
