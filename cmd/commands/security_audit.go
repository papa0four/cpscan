package cmd

import (
    "fmt"
    "runtime"

    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/internal/security"
)

// Flags for security audit command
var (
    securityVerbose    bool
    checkSSH           bool
    checkFirewall      bool
    checkUsers         bool
    checkFilePerms     string // Path for file permissions check
)

// securityAuditCmd represents the security audit command
var securityAuditCmd = &cobra.Command{
    Use:   "security_audit",
    Short: "Perform a security audit",
    Long:  `Perform a security audit based on the operating system. Options include:
    --check-ssh                Check SSH configuration
    --check-firewall           Check firewall rules
    --check-users              List user accounts
    --file-permissions FILE    Check permission of a specified file
    -v, --verbose              Run all checks with detailed output`,
    Run: func(cmd *cobra.Command, args []string) {
        os := runtime.GOOS
        fmt.Printf("Running security audit for OS: %s\n", os)

        // Supported *nix-based OS's
        supportedOS := map[string]bool{
            "linux":    true,
            "darwin":   true,
            "freebsd":  true,
            "openbsd":  true,
        }

        // Detect the OS and call the appropriate audit function
        if os == "windows" {
            fmt.Println("The security audit feature is currently not available for Windows.")
            return
        }
        if !supportedOS[os] {
            fmt.Println("Unsupported OS for security audit.")
            return
        }

        // Determine which audits to run based on flags
        checks := []string{}
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

        // Display help message if no specific checks or verbose flag provided
        if verbose && len(checks) == 0 {
            fmt.Println("Verbose flag set. Running all checks with detailed output...")
            checks = []string{"ssh", "firewall", "users", "file-permissions"}
        }

        // Display help message if no checks are specified and verbose mode is not enabled
        if len(checks) == 0 {
            fmt.Println("No specific checks provided. Showing help:")
            cmd.Help()
            return
        }

        // Execute the audit with secific flags
        security.RunUnixAudit(verbose, checks...)
    },
}

func init() {
    RootCmd.AddCommand(securityAuditCmd)

    // Define flags for specific checks
    securityAuditCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Run all checks with detailed output")
    securityAuditCmd.Flags().BoolVar(&checkSSH, "check-ssh", false, "Check SSH configuration")
    securityAuditCmd.Flags().BoolVar(&checkFirewall, "check-firewall", false, "Check firewall rules")
    securityAuditCmd.Flags().BoolVar(&checkUsers, "check-users", false, "List user accounts")
    securityAuditCmd.Flags().StringVar(&checkFilePerms, "file-permissions", "", "Check permissions of specified file")
}

