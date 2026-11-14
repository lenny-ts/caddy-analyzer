// Package doctor implements read-only installation and runtime diagnostics
// for the caddy-analyze CLI. Check collection is kept separate from report
// rendering so severity, exit codes, and JSON output can be tested without a
// live firewall or a writable system state directory.
package doctor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrCritical is returned by command wiring when at least one critical check
// failed. It carries no additional text: the report itself is the diagnosis.
var ErrCritical = errors.New("critical checks failed")

// Status is the severity of one diagnostic check.
type Status string

const (
	StatusOK   Status = "OK"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Check is a single diagnostic result.
type Check struct {
	ID       string `json:"id"`
	Status   Status `json:"status"`
	Message  string `json:"message"`
	Critical bool   `json:"critical"`
}

// Group is a subsystem section in the report.
type Group struct {
	Name   string  `json:"name"`
	Checks []Check `json:"checks"`
}

// Summary aggregates every check in the report.
type Summary struct {
	OK               int    `json:"ok"`
	Warn             int    `json:"warn"`
	Fail             int    `json:"fail"`
	CriticalFailures int    `json:"critical_failures"`
	Status           Status `json:"status"`
	ExitCode         int    `json:"exit_code"`
}

// Report is the complete doctor result.
type Report struct {
	Groups  []Group `json:"groups"`
	Summary Summary `json:"summary"`
}

// Pass returns an OK check.
func Pass(id, message string) Check {
	return Check{ID: id, Status: StatusOK, Message: message}
}

// Warning returns a non-critical WARN check.
func Warning(id, message string) Check {
	return Check{ID: id, Status: StatusWarn, Message: message}
}

// Failure returns a non-critical FAIL check.
func Failure(id, message string) Check {
	return Check{ID: id, Status: StatusFail, Message: message}
}

// CriticalFailure returns a FAIL check that makes the process exit non-zero.
func CriticalFailure(id, message string) Check {
	return Check{ID: id, Status: StatusFail, Message: message, Critical: true}
}

// NewReport builds a report and computes its summary and exit code.
func NewReport(groups []Group) Report {
	return Report{Groups: groups, Summary: summarize(groups)}
}

func summarize(groups []Group) Summary {
	var s Summary
	for _, g := range groups {
		for _, c := range g.Checks {
			switch c.Status {
			case StatusOK:
				s.OK++
			case StatusWarn:
				s.Warn++
			case StatusFail:
				s.Fail++
				if c.Critical {
					s.CriticalFailures++
				}
			}
		}
	}

	switch {
	case s.Fail > 0:
		s.Status = StatusFail
	case s.Warn > 0:
		s.Status = StatusWarn
	default:
		s.Status = StatusOK
	}
	if s.CriticalFailures > 0 {
		s.ExitCode = 1
	}
	return s
}

// WriteText renders the human-readable report.
func (r Report) WriteText(w io.Writer) error {
	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintln(bw, "Caddy Analyzer Doctor"); err != nil {
		return err
	}
	for _, g := range r.Groups {
		if _, err := fmt.Fprintln(bw, g.Name); err != nil {
			return err
		}
		for _, c := range g.Checks {
			if _, err := fmt.Fprintf(bw, "  [%s] %s\n", c.Status, c.Message); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(bw, "\nSummary: %d OK, %d WARN, %d FAIL\n",
		r.Summary.OK, r.Summary.Warn, r.Summary.Fail); err != nil {
		return err
	}
	result := "PASS"
	if r.Summary.CriticalFailures > 0 {
		result = fmt.Sprintf("FAIL (%d critical)", r.Summary.CriticalFailures)
	}
	if _, err := fmt.Fprintf(bw, "Result: %s\n", result); err != nil {
		return err
	}
	return bw.Flush()
}

// WriteJSON renders the machine-readable report.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
