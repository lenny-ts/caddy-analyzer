package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/L9Lenny/caddy-analyzer/pkg/blocklist"
)

var blocklistCmd = &cobra.Command{
	Use:   "blocklist <action>",
	Short: "Manage blocklist feeds",
	Long: `Manage blocklist feeds used by the guard for immediate IP blocking.

Actions:
  refresh   Download all configured feeds and update the local cache.
  list       Show the status of every configured feed (entries, age, errors).
  config     Print the current feed configuration as JSON.

Default feeds (disabled with --no-default-blocklists):
  • Spamhaus DROP    https://www.spamhaus.org/drop/drop.txt
  • Spamhaus EDROP   https://www.spamhaus.org/drop/edrop.txt
  • FireHOL level1   https://iplists.firehol.org/files/firehol_level1.netset
  • CINS Army        https://cinsscore.com/list/ci_badguys
  • Tor exit nodes   https://check.torproject.org/torbulkexitlist

Custom feeds are added with --blocklist-config and removed with
--blocklist-remove. The cache lives in --cache-dir (default
~/.cache/caddy-analyzer/blocklists).

Examples:
  caddy-analyze blocklist refresh
  caddy-analyze blocklist list
  caddy-analyze blocklist config
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
	default:
		return fmt.Errorf("unknown action %q: use refresh, list, or config", action)
	}
}

// buildSources assembles the source list from defaults and config files,
// honouring --no-default-blocklists and --blocklist-remove.
func buildSources() ([]blocklist.Source, error) {
	var sources []blocklist.Source
	if !blocklistNoDefaults {
		sources = append(sources, blocklist.DefaultSources...)
	}
	for _, path := range blocklistConfigFiles {
		fileSrcs, err := loadSourcesFile(path)
		if err != nil {
			return nil, fmt.Errorf("--blocklist-config %s: %w", path, err)
		}
		sources = append(sources, fileSrcs...)
	}
	if len(blocklistRemoveSources) > 0 {
		remove := make(map[string]bool, len(blocklistRemoveSources))
		for _, name := range blocklistRemoveSources {
			remove[strings.TrimSpace(name)] = true
		}
		filtered := sources[:0]
		for _, s := range sources {
			if !remove[s.Name] {
				filtered = append(filtered, s)
			}
		}
		sources = filtered
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no sources configured: enable defaults or add --blocklist-config")
	}
	return sources, nil
}

func loadSourcesFile(path string) ([]blocklist.Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var srcs []blocklist.Source
	if err := json.Unmarshal(data, &srcs); err != nil {
		return nil, err
	}
	return srcs, nil
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
