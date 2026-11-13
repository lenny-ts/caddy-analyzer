package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
)

func init() {
	list := &cobra.Command{
		Use: "offenders", Short: "List unexpired repeat-offender history as JSON",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _ := cmd.Flags().GetString("state-file")
			offenders, err := guard.ListOffenders(path)
			if err != nil {
				return err
			}
			if offenders == nil {
				offenders = []guard.Offender{}
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(offenders)
		},
	}
	show := &cobra.Command{
		Use: "show <ip>", Short: "Show unexpired history for an IP or CIDR as JSON",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("state-file")
			offender, err := guard.GetOffender(path, args[0])
			if err != nil {
				return err
			}
			if offender == nil {
				return fmt.Errorf("no unexpired offender history for %s", args[0])
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(offender)
		},
	}
	reset := &cobra.Command{
		Use: "reset <ip>", Short: "Forget offender history without removing an active ban",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("state-file")
			return guard.ResetOffender(path, args[0])
		},
	}
	for _, cmd := range []*cobra.Command{list, show, reset} {
		cmd.Flags().String("state-file", guardStateFile, "Guard state file whose .offenders directory contains the history")
	}
	offender := &cobra.Command{Use: "offender", Short: "Inspect or reset repeat-offender history"}
	offender.AddCommand(show, reset)
	guardCmd.AddCommand(list, offender)
}
