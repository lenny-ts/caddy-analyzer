package cmd

import (
	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/selfupdate"
)

var (
	updateCheck      bool
	updateVersion    string
	updateForce      bool
	updateInstallDir string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Self-update: download, verify, and install the latest release in-place",
	Long: `Download the latest caddy-analyze release from GitHub, verify it, and
replace the running binary in place.

Verification is fail closed: the release manifest (checksums.txt) must pass
cosign keyless signature verification (certificate minted by this repo's
release workflow) AND the archive SHA256 must match the signed manifest.
If cosign is missing or any check fails, nothing is installed.

The replacement is atomic: the new binary is staged next to the target and
swapped with a single rename. On Windows the running .exe is moved aside
(.exe.old) and rolled back if installation fails.

Examples:
  caddy-analyze update                     # install latest verified release
  caddy-analyze update --check             # report availability only
  caddy-analyze update --version v0.5.0    # pin an exact release
  caddy-analyze update --force             # reinstall / allow downgrade
  caddy-analyze update --install-dir ~/.local/bin
`,
	Args: cobra.NoArgs,
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().BoolVar(&updateCheck, "check", false, "Report whether an update is available without downloading")
	updateCmd.Flags().StringVar(&updateVersion, "version", "", "Install a specific release tag instead of the latest (e.g. v0.5.0)")
	updateCmd.Flags().BoolVar(&updateForce, "force", false, "Reinstall even when up to date; also allows downgrades")
	updateCmd.Flags().StringVar(&updateInstallDir, "install-dir", "", "Replace the binary inside this directory instead of the running executable")
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, _ []string) error {
	return selfupdate.Run(cmd.Context(), &selfupdate.Options{
		Repo:       selfupdate.DefaultRepo,
		CurrentVer: Version,
		TargetVer:  updateVersion,
		CheckOnly:  updateCheck,
		Force:      updateForce,
		InstallDir: updateInstallDir,
	})
}
