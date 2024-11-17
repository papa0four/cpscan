// cmd/commands/security/security_unix.go
//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package security

import (
    "fmt"
    "runtime"
    "strings"
    
    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/internal/security/audit"
)

func init() {
    SecurityCmd.RunE = runUnixAudit
}

func runUnixAudit(cmd *cobra.Command, args []string) error {
    // Determine which checks to run
    var checks []string
    if checkSSH {
        checks = append(checks, "ssh")
    }
    if checkFirewall {
        checks = append(checks, "firewall")
    }
    if checkUsers {
        checks = append(checks, "users")
    }
    if checkFilePerms != "" {
        checks = append(checks, "file-permissions")
    }

    if verbose {
        fmt.Printf("Running security audit for OS: %s\n", runtime.GOOS)
        if len(checks) > 0 {
            fmt.Printf("Running checks: %s\n", strings.Join(checks, ", "))
        }
    }

    // Convert command flags to audit options
    opts := audit.AuditOptions{
        Verbose:        verbose,
        CustomPaths:    customPaths,
        SkipChecks:     skipChecks,
        MinSeverity:    minSeverity,
        Timeout:        timeout,
        SpecificChecks: checks,
    }

    // Create and run auditor
    auditor := audit.NewSecurityAuditor(opts)
    result, err := auditor.RunAudit()
    if err != nil {
        return fmt.Errorf("audit failed: %w", err)
    }

    return outputResults(result)
}