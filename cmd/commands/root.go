// cmd/commands/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/security"
)

// RootCmd defines the base command for the CLI
var RootCmd = &cobra.Command{
	Use:           "owatch",
	Version:       Version,
	Short:         "orkowatch is a lightweight scanner for host OS vulnerabilities",
	Long:          `orkowatch helps engineers and architects scan for vulnerabilities in OS, software, and security protocols`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("displaying help: %w", err)
		}
		return fmt.Errorf("owatch requires a subcommand (e.g., all, osinfo, audit, software)")
	},
}

func init() {
	RootCmd.AddCommand(security.SecurityCmd)
	RootCmd.Flags().BoolP("version", "V", false, "version for owatch")
}

// Execute runs the root command and exits with a non-zero status on error.
// SilenceErrors is set on RootCmd, so this is the single error-reporting
// point for the binary; errors go to stderr, never stdout, so they cannot
// interleave with report output or escape 2> redirection.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
