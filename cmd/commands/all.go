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
    Use: "all",
    Short: "Run both OS information and software listing scans",
    Long: `The all command gathers OS fingerprint information, available software, and services hosts`,
    Run: func(cmd *cobra.Command, args []string) {
        // Run OS fingerprint scan
        osInfo, err := osfingerprint.GetOSFingerprint()
        if err != nil {
            fmt.Println("Error retrieving OS information:", err)
            return
        }
        fmt.Printf("OS: %s\nPlatform: %s\nVersion: %s\nKernel Version: %s\n\n",
            osInfo.OS, osInfo.Platform, osInfo.PlatformVersion, osInfo.KernelVersion)

        // Run software listing scan
        software, err := softwarelist.GetInstalledSoftware()
        if err != nil {
            fmt.Println("Error fetching installed software:", err)
            return
        }
        fmt.Println("Installed Software:\n", software)
    },
}

func init() {
    //Register the all command under the root command
    RootCmd.AddCommand(allCmd)
}
