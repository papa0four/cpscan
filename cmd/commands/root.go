// cmd/root.go
package cmd

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/cmd/commands/security"
)

// RootCmd defines the base command for the CLI
var RootCmd = &cobra.Command{
    Use: "cpscan",
    Short: "CPScan is a lightweight scanner for host OS vulnerabilities",
    Long: `CPScan helps engineers and architects scan for vulnerabilities in OS, software, and security protocols`,
    Run: func(cmd *cobra.Command, args []string) {
        // Default action when no subcommands are provided
        fmt.Println("CPScan requires a subcommand (e.g., osinfo, security_audit, software).")
        cmd.Help()
    },
}

func init() {
    // Register the security audit command
    RootCmd.AddCommand(security.SecurityCmd)
}

func Execute() {
    if err := RootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
