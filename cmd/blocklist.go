package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/blocklist"
	"github.com/lenny-ts/caddy-analyzer/pkg/config"
)

var blocklistCmd = &cobra.Command{
	Use:   "blocklist <action>",
	Short: "Manage blocklist feeds",
	Long: `Manage blocklist feeds used by the guard for immediate IP blocking.

Actions:
  refresh   Download all configured feeds and update the local cache.
  list       Show the status of every configured feed (entries, age, errors).
  config     Print the current feed configuration as JSON.
  init       Save current blocklist settings (from flags) to the config file.

Default feeds (disabled with --no-default-blocklists):
  • Spamhaus DROP    https://www.spamhaus.org/drop/drop.txt
  • FireHOL level1   https://iplists.firehol.org/files/firehol_level1.netset
  • CINS Army        http://cinsscore.com/list/ci-badguys.txt
  • Tor exit nodes   https://check.torproject.org/torbulkexitlist

Custom feeds are added with --blocklist-config and removed with
--blocklist-remove. The cache lives in --cache-dir (default
~/.cache/caddy-analyzer/blocklists).

'blocklist init' persists the current flag settings to caddy-analyzer.json
so the guard and blocklist subcommands pick them up automatically.

Examples:
  caddy-analyze blocklist refresh
  caddy-analyze blocklist list
  caddy-analyze blocklist config
  caddy-analyze blocklist init --no-default-blocklists --blocklist-config mylist.txt
  caddy-analyze blocklist refresh --blocklist-config mylist.txt
  caddy-analyze blocklist list --no-default-blocklists
`,
	Args: cobra.ExactArgs(1),
	RunE: runBlocklist,
}

var (
	blocklistCacheDir      string
	blocklistNoDefaults    bool
	blocklistConfigFiles   []string
	blocklistRemoveSources []string
	blocklistConfigFormat  string
)

func init() {
	blocklistCmd.Flags().StringVarP(&blocklistCacheDir, "cache-dir", "", defaultBlocklistCacheDir(), "Directory for cached blocklist files")
	blocklistCmd.Flags().BoolVarP(&blocklistNoDefaults, "no-default-blocklists", "", false, "Disable default feeds (Spamhaus, FireHOL, CINS, Tor)")
	blocklistCmd.Flags().StringSliceVarP(&blocklistConfigFiles, "blocklist-config", "", nil, "Path(s) to JSON file(s) with extra sources: [{\"name\":\"x\",\"url\":\"y\"}]")
	blocklistCmd.Flags().StringSliceVarP(&blocklistRemoveSources, "blocklist-remove", "", nil, "Remove named sources from the configuration")
	blocklistCmd.Flags().StringVarP(&blocklistConfigFormat, "format", "f", "table", "Output format for list/config: table, json")
	rootCmd.AddCommand(blocklistCmd)
}

func defaultBlocklistCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return dir + "/caddy-analyzer/blocklists"
	}
	return "/var/lib/caddy-analyzer/blocklists"
}

func runBlocklist(cmd *cobra.Command, args []string) error {
	action := strings.ToLower(args[0])
	switch action {
	case "refresh":
		return blocklistRefresh()
	case "list":
		return blocklistList()
	case "config":
		return blocklistConfig()
	case "init":
		return blocklistInit()
	default:
		return fmt.Errorf("unknown action %q: use refresh, list, config, or init", action)
	}
}

// loadBlocklistConfig builds a BlocklistConfig from the config file (if
// any) and the CLI flags. CLI flags override config file values.
func loadBlocklistConfig() (*config.BlocklistConfig, error) {
	// Start from the config file.
	var bc config.BlocklistConfig
	cfg, _, _ := config.Load()
	if cfg != nil && cfg.Blocklist != nil {
		bc = *cfg.Blocklist
	}

	// CLI flags override.
	if blocklistNoDefaults {
		bc.NoDefaults = true
	}
	for _, path := range blocklistConfigFiles {
		fileBC, err := config.LoadBlocklistFile(path)
		if err != nil {
			return nil, fmt.Errorf("--blocklist-config %s: %w", path, err)
		}
		bc.CustomSources = append(bc.CustomSources, fileBC.CustomSources...)
	}
	if len(blocklistRemoveSources) > 0 {
		bc.RemoveSources = append(bc.RemoveSources, blocklistRemoveSources...)
	}
	return &bc, nil
}

// buildSources assembles the source list from the config file and CLI
// flags, honouring --no-default-blocklists, --blocklist-config, and
// --blocklist-remove.
func buildSources() ([]blocklist.Source, error) {
	bc, err := loadBlocklistConfig()
	if err != nil {
		return nil, err
	}
	return bc.ResolveSources()
}

func blocklistRefresh() error {
	sources, err := buildSources()
	if err != nil {
		return err
	}
	mgr, err := blocklist.NewManager(sources, blocklistCacheDir)
	if err != nil {
		return fmt.Errorf("blocklist manager: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Refreshing %d blocklist feed(s)...\n", len(sources))
	statuses := mgr.Refresh()
	totalEntries := 0
	active := 0
	hadErr := false
	for _, st := range statuses {
		if st.Error != "" {
			fmt.Fprintf(os.Stderr, "  ✗ %-18s %s\n", st.Name, st.Error)
			hadErr = true
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %-18s %d entries\n", st.Name, st.Entries)
			totalEntries += st.Entries
			active++
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d feed(s) active, %d total entries cached in %s\n", active, totalEntries, blocklistCacheDir)
	if hadErr {
		return fmt.Errorf("one or more feeds failed to refresh")
	}
	return nil
}

func blocklistList() error {
	sources, err := buildSources()
	if err != nil {
		return err
	}
	mgr, err := blocklist.NewManager(sources, blocklistCacheDir)
	if err != nil {
		return fmt.Errorf("blocklist manager: %w", err)
	}
	mgr.LoadAll()
	statuses := mgr.ListSources()

	if blocklistConfigFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(statuses)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tENTRIES\tAGE\tSTATUS\tURL")
	for _, st := range statuses {
		age := "never"
		if !st.FetchedAt.IsZero() {
			age = humanAge(time.Since(st.FetchedAt))
		}
		status := "ok"
		if st.Error != "" {
			status = st.Error
		} else if st.Stale {
			status = "stale"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", st.Name, st.Entries, age, status, st.URL)
	}
	return w.Flush()
}

func blocklistConfig() error {
	sources, err := buildSources()
	if err != nil {
		return err
	}
	if blocklistConfigFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sources)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tURL")
	for _, s := range sources {
		fmt.Fprintf(w, "%s\t%s\n", s.Name, s.URL)
	}
	return w.Flush()
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// blocklistInit writes the current blocklist configuration (from CLI
// flags) to the config file so it is picked up automatically by the
// guard and blocklist subcommands on future invocations.
func blocklistInit() error {
	bc, err := loadBlocklistConfig()
	if err != nil {
		return err
	}
	// Load the existing config so we don't clobber Source/Namespace.
	cfg, _, err := config.Load()
	if err != nil {
		cfg = &config.Config{}
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.Blocklist = bc

	path := config.LocalConfigPath()
	if flagConfigGlobal {
		path, err = config.DefaultConfigPath()
		if err != nil {
			return fmt.Errorf("global config path: %w", err)
		}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	srcs, _ := bc.ResolveSources()
	fmt.Printf("Blocklist config saved: %s\n", path)
	fmt.Printf("  No defaults: %t\n", bc.NoDefaults)
	fmt.Printf("  Custom sources: %d\n", len(bc.CustomSources))
	fmt.Printf("  Remove sources: %d\n", len(bc.RemoveSources))
	fmt.Printf("  Resolved feeds: %d\n", len(srcs))
	return nil
}
