package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/config"
)

var flagConfigGlobal bool

var configCmd = &cobra.Command{
	Use:   "config [show|set|reset|source]",
	Short: "Manage default log source and persistent configuration",
	Long: `Manage default log source and configuration settings.

When configured, caddy-analyze automatically reads from your default log source
whenever you run 'caddy-analyze' without positional source arguments.

Config Locations:
  Local:  ./caddy-analyzer.json (project-specific)
  Global: ~/.config/caddy-analyzer/config.json (--global flag)

Commands:
  caddy-analyze config                           Show active configuration and source
  caddy-analyze config /var/log/caddy/access.log Set default log source (local)
  caddy-analyze config docker://my-caddy -g       Set default log source (global)
  caddy-analyze config set <source>              Set default log source explicitly
  caddy-analyze config reset                     Remove configuration file

Examples:
  caddy-analyze config docker://caddy
  caddy-analyze config k8s://my-pod -n production
  caddy-analyze config reset
`,
	Args: cobra.ArbitraryArgs,
	RunE: runConfigCmd,
}

func init() {
	configCmd.Flags().BoolVarP(&flagConfigGlobal, "global", "g", false, "Operate on global config (~/.config/caddy-analyzer/config.json)")
	rootCmd.AddCommand(configCmd)
}

func runConfigCmd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 || (len(args) == 1 && strings.ToLower(args[0]) == "show") {
		return showConfig()
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "reset", "clear", "rm":
		return resetConfig()
	case "set":
		if len(args) < 2 {
			return fmt.Errorf("usage: caddy-analyze config set <source>")
		}
		return setConfig(args[1])
	default:
		return setConfig(args[0])
	}
}

func showConfig() error {
	cfg, path, err := config.Load()
	if err != nil || cfg == nil || path == "" {
		fmt.Println("No active config file found.")
		fmt.Println("Set a default log source with: caddy-analyze config <source>")
		return nil
	}

	fmt.Printf("Active Config File: %s\n", path)
	fmt.Printf("Default Log Source: %s\n", cfg.Source)
	if cfg.Namespace != "" {
		fmt.Printf("Kubernetes Namespace: %s\n", cfg.Namespace)
	}
	return nil
}

func setConfig(source string) error {
	var path string
	if flagConfigGlobal {
		defPath, err := config.DefaultConfigPath()
		if err != nil {
			return fmt.Errorf("global config path: %w", err)
		}
		path = defPath
	} else {
		path = config.LocalConfigPath()
	}

	cfg := config.Config{Source: source, Namespace: flagK8sNS}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	fmt.Printf("Config saved: %s\n", path)
	fmt.Printf("  Default log source set to: %s\n", source)
	if flagK8sNS != "" {
		fmt.Printf("  Kubernetes namespace: %s\n", flagK8sNS)
	}
	return nil
}

func resetConfig() error {
	var path string
	if flagConfigGlobal {
		defPath, err := config.DefaultConfigPath()
		if err != nil {
			return fmt.Errorf("global config path: %w", err)
		}
		path = defPath
	} else {
		path = config.LocalConfigPath()
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("Config file %s does not exist.\n", path)
		return nil
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove config file: %w", err)
	}

	fmt.Printf("Removed config file: %s\n", path)
	return nil
}
