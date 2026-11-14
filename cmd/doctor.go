package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/config"
	"github.com/lenny-ts/caddy-analyzer/pkg/doctor"
	"github.com/lenny-ts/caddy-analyzer/pkg/reader"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

const defaultDoctorStateFile = "/var/lib/caddy-analyzer/blocked.json"

var (
	doctorJSON      bool
	doctorLog       string
	doctorStateFile string
	doctorCacheDir  string
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose installation and runtime problems without changing the system",
	Long: `Run read-only installation and runtime diagnostics.

Checks are grouped by subsystem (Runtime, Caddy, Guard, Optional Dependencies)
and reported as [OK], [WARN], or [FAIL]. No firewall rules are created, no
state file is written, and no configuration is changed.

The exit code is non-zero only when a critical check fails.

Examples:
  caddy-analyze doctor
  caddy-analyze doctor --json
  caddy-analyze doctor --log /var/log/caddy/access.log
`,
	Args:          cobra.NoArgs,
	RunE:          runDoctor,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorJSON, "json", false, "Emit machine-readable JSON")
	doctorCmd.Flags().StringVar(&doctorLog, "log", "", "Caddy access log to inspect (auto-detected if empty)")
	doctorCmd.Flags().StringVar(&doctorStateFile, "state-file", defaultDoctorStateFile, "Guard state file to check")
	doctorCmd.Flags().StringVar(&doctorCacheDir, "cache-dir", defaultBlocklistCacheDir(), "Blocklist cache directory to inspect")
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	env := doctor.Env{
		Version:             Version,
		GOOS:                runtime.GOOS,
		GOARCH:              runtime.GOARCH,
		Euid:                os.Geteuid(),
		StateFile:           doctorStateFile,
		AccessLog:           doctorLog,
		AccessLogCandidates: doctorAccessLogCandidates(),
		GeoIPDB:             flagGeoIPDB,
		BlocklistCacheDir:   filepath.Clean(doctorCacheDir),
		Now:                 time.Now(),
	}

	report := doctor.NewReport(doctor.Collect(env))
	out := cmd.OutOrStdout()
	if doctorJSON {
		if err := report.WriteJSON(out); err != nil {
			return err
		}
	} else if err := report.WriteText(out); err != nil {
		return err
	}

	if report.Summary.ExitCode != 0 {
		return doctor.ErrCritical
	}
	return nil
}

// doctorAccessLogCandidates mirrors the sources the analyzer auto-detects,
// with an explicitly configured source checked first.
func doctorAccessLogCandidates() []string {
	var candidates []string
	if cfg, _, err := config.Load(); err == nil && cfg != nil && cfg.Source != "" {
		src := reader.ParseSource(cfg.Source)
		if src.Type == types.SourceFile && src.Path != "" {
			candidates = append(candidates, src.Path)
		}
	}
	return append(candidates,
		"access.log",
		"caddy.log",
		"caddy-access.log",
		"/var/log/caddy/access.log",
		"/var/log/caddy/caddy.log",
	)
}
