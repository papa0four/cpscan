// cmd/commands/all.go
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/papa0four/cpscan/internal/osfingerprint"
	"github.com/papa0four/cpscan/internal/softwarelist"
)

// allCmd represents the all command that combines all host scanning commands
var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all available scans including OS information, software listing, and security audit",
	Long: `The all command gathers OS fingerprint information, lists installed software and services,
and performs a comprehensive security audit of the host system.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Running all available scans...")

		// Run OS fingerprint scan
		fmt.Println("\n======================================")
		fmt.Println("== OS Fingerprint Information")
		fmt.Println("======================================")
		osInfo, err := osfingerprint.GetOSFingerprint()
		if err != nil {
			fmt.Println("Error retrieving OS information:", err)
		} else {
			fmt.Printf("OS: %s\nPlatform: %s\nVersion: %s\nKernel Version: %s\n\n",
				osInfo.OS, osInfo.Platform, osInfo.PlatformVersion, osInfo.KernelVersion)
		}

		// Run software listing scan
		fmt.Println("\n======================================")
		fmt.Println("== Installed Software")
		fmt.Println("======================================")
		software, err := softwarelist.GetInstalledSoftware()
		if err != nil {
			fmt.Println("Error fetching installed software:", err)
		} else {
			fmt.Println("Installed Software:\n", software)
		}

		// Run security audit with verbose flag
		fmt.Println("\n======================================")
		fmt.Println("== Security Audit")
		fmt.Println("======================================")
		securityAuditCmd.Flags().Set("verbose", "true") // Enable verbose mode
		securityAuditCmd.Run(securityAuditCmd, []string{}) // Trigger security audit
		fmt.Println("======================================")
	},
}

func init() {
	// Register the all command under the root command
	RootCmd.AddCommand(allCmd)
}
