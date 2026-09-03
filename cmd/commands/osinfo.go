// cmd/commands/osinfo.go

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// osinfoCmd represents the command for gathering OS information
var osinfoCmd = &cobra.Command{
	Use:   "osinfo",
	Args:  cobra.NoArgs,
	Short: "Gather OS Fingerprint information",
	Long:  `osinfo will scan the host machine and retrieve basic OS fingerprint information such as platform, version, and kernel details.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := osfingerprint.GetOSFingerprint()
		if err != nil {
			return fmt.Errorf("osinfo: %w", err)
		}
		return osfingerprint.WriteText(cmd.OutOrStdout(), info)
	},
}

func init() {
	RootCmd.AddCommand(osinfoCmd)
}
