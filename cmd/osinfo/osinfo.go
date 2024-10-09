// cmd/osinfo/osinfo.go
package osinfo

import (
    "fmt"
    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/cmd/root"
    "github.com/papa0four/cpscan/internal/osfingerprint"
)

var verbose bool

// osinfoCmd represents the command for gathering OS information
var osinfoCmd = &cobra.Command{
    Use: "osinfo",
    Short: "Gather OS Fingerprint information",
    Long: `osinfo will scan the host machine and retrieve basic OS fingerprint information such as platform, version, and kernel details.`,
    Run: func(cmd *cobra.Command, args []string) {
        if verbose {
            fmt.Println("Verbose mode enabled. Gathering additional information...")
        }
        osfingerprint.PrintOSInfo()
    },
}

func init() {
    // Add the osinfo command to the root command
    RootCmd.AddCommand(osinfoCmd)

    // Define a --verbose flag for osinfo command
    osinfoCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
