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
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("owatch requires a subcommand (e.g., all, osinfo, security_audit, software).")
		if err := cmd.Help(); err != nil {
			fmt.Fprintf(os.Stderr, "error displaying help: %v\n", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(security.SecurityCmd)
	RootCmd.Flags().BoolP("version", "V", false, "version for owatch")
}

// Execute runs the root command and exits with a non-zero status on error
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
