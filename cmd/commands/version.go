// cmd/commands/version.go

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

/*
Version is the current application version.
It defaults to the active development stage and is overridden
at build time via -ldflags "-X github.com/papa0four/orkowatch/cmd/commands.Version=..."
*/
var Version = "dev"

// versionCmd prints the application version, matching the --version output
var versionCmd = &cobra.Command{
	Use:   "version",
	Args:  cobra.NoArgs,
	Short: "Print the orkowatch version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("owatch version %s\n", Version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
