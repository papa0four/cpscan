package cmd

import (
    "fmt"
    "runtime"

    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/internal/security"
)

// securityAuditCmd represents the security audit command
var securityAuditCmd = &cobra.Command{
    Use:   "security_audit",
    Short: "Perform a security audit",
    Long:  "This command performs a security audit based on the operating system.",
    Run: func(cmd *cobra.Command, args []string) {
        os := runtime.GOOS
        fmt.Println(os)
        fmt.Printf("Running security audit for OS: %s\n", os)

        // Detect the OS and call the appropriate audit function
        if os == "windows" {
            security.RunWindowsAudit()
        if os == "linux" || os == "darwin" || os == "freebsd" || os == "openbsd" {
            security.RunUnixAudit()
        } else {
            fmt.Println("Unsupported OS for security audit.")
        }
    },
}

func init() {
    RootCmd.AddCommand(securityAuditCmd)
}

