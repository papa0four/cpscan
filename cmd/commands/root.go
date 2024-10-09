// cmd/root.go
package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
    "os"
)

// RootCmd defines the base command for the CLI
var RootCmd = &cobra.Command{
    Use: "cpscan",
    Short: "CPScan is a lightweight scanner for OS and network vulnerabilities",
    Long: `CPScan helps engineers and architects scan for vulnerabilities in OS, software, and network protocols`,
    Run: func(cmd *cobra.Command, args []string) {
        // Default action when no subcommands are provided
        fmt.Println("CPScan requires a subcommand (e.g., osinfo).")
    },
}

func Execute() {
    if err := RootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
