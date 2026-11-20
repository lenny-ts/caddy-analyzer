package analysis

import (
	"reflect"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestExplainPreservesDetections(t *testing.T) {
	entry := &types.LogEntry{URI: "/?q=review%20me", UserAgent: "sqlmap"}
	rules := []DetectionPattern{
		{Type: "example", Pattern: "review", Source: "uri", Confidence: 5},
		{Type: "example", Pattern: "review me", Source: "uri", Confidence: 8},
		{Type: "example", Pattern: "me", Source: "uri", Confidence: 8},
	}
	want := NewDetectorWithPatterns(rules).DetectAll(entry)
	d := NewDetectorWithPatterns(rules)
	var explanations []Explanation
	d.SetExplain(func(x Explanation) { explanations = append(explanations, x) })
	if got := d.DetectAll(entry); !reflect.DeepEqual(got, want) {
		t.Fatalf("explain changed detections: got %+v, want %+v", got, want)
	}
	if len(explanations) != len(want) {
		t.Fatalf("got %d explanations for %d detections", len(explanations), len(want))
	}
	for i, x := range explanations {
		if !reflect.DeepEqual(x.Detection, want[i]) || x.RuleID == "" {
			t.Errorf("bad explanation: %+v", x)
		}
		if x.Detection.Type == "example" && (x.Source != "query string" || x.Matched != "review me") {
			t.Errorf("explanation lost the winning signature: %+v", x)
		}
	}
}
