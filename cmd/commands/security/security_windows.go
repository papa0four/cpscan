// cmd/commands/security/security_windows.go
//go:build windows
// +build windows

package security

import (
    "fmt"
    "runtime"
    
    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/internal/security/audit"
)

func init() {
    SecurityCmd.RunE = runWindowsAudit
}

func runWindowsAudit(cmd *cobra.Command, args []string) error {
    if verbose {
        fmt.Printf("Running security audit for OS: %s\n", runtime.GOOS)
    }

    // Convert command flags to audit options
    opts := audit.AuditOptions{
        Verbose:     verbose,
        CustomPaths: customPaths,
        SkipChecks:  skipChecks,
        MinSeverity: minSeverity,
        Timeout:     timeout,
    }

    // Create and run auditor
    auditor := audit.NewSecurityAuditor(opts)
    result, err := auditor.RunAudit()
    if err != nil {
        return fmt.Errorf("audit failed: %w", err)
    }

    return outputResults(result)
}