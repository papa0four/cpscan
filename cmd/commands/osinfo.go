// cmd/commands/osinfo.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/papa0four/cpscan/internal/osfingerprint"
)

var osinfoVerbose bool

// osinfoCmd represents the command for gathering OS information
var osinfoCmd = &cobra.Command{
	Use:   "osinfo",
	Short: "Gather OS Fingerprint information",
	Long:  `osinfo will scan the host machine and retrieve basic OS fingerprint information such as platform, version, and kernel details.`,
	Run: func(cmd *cobra.Command, args []string) {
		if osinfoVerbose {
			fmt.Println("[*] Verbose mode enabled. Gathering additional information...")
		}
		osfingerprint.PrintOSInfo()
	},
}

func init() {
	RootCmd.AddCommand(osinfoCmd)
	osinfoCmd.Flags().BoolVarP(&osinfoVerbose, "verbose", "v", false, "Enable verbose output")
}
