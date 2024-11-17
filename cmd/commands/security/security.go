// cmd/commands/security/security.go
package security

import (
	"encoding/json"
    "fmt"
    "os"
    "strings"
    "time"

	"gopkg.in/yaml.v3"
    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/internal/security/audit"
    "github.com/papa0four/cpscan/internal/security/types"
)

var (
    // Command flags
    verbose         bool
    outputFormat    string
    reportFile     string
    customPaths    []string
    skipChecks     []string
    minSeverity    string
    timeout        time.Duration

    // Individual check flags
    checkSSH        bool
    checkFirewall   bool
    checkUsers      bool
    checkFilePerms  string
)

// SecurityCmd represents the security audit command
var SecurityCmd = &cobra.Command{
    Use:   "security_audit [flags] [check...]",
    Short: "Perform a security audit of the system",
    Long: `Perform a comprehensive security audit of the system.
This command checks various security aspects including:
- SSH configuration
- Firewall rules
- User accounts
- File permissions

You can run all checks or specify individual checks to run.`,
    Example: `  # Run all security checks with verbose output
  cpscan security_audit -v

  # Run specific checks
  cpscan security_audit --check-ssh
  cpscan security_audit --check-firewall
  cpscan security_audit --check-users
  cpscan security_audit --file-permissions /path/to/file

  # Run checks with verbose output
  cpscan security_audit --check-ssh -v

  # Set minimum severity level
  cpscan security_audit --min-severity HIGH

  # Run checks and save report to file
  cpscan security_audit -v -o json --report-file audit.json`,
    RunE: runSecurityAudit,
}

// Formatter types
type (
    formattedResult struct {
        Timestamp   string                `json:"timestamp" yaml:"timestamp"`
        Duration    string                `json:"duration" yaml:"duration"`
        SystemInfo  formattedSystemInfo   `json:"system_info" yaml:"system_info"`
        Results     []formattedCheck      `json:"results" yaml:"results"`
        Summary     formattedSummary      `json:"summary" yaml:"summary"`
    }

    formattedSystemInfo struct {
        OS            string `json:"os" yaml:"os"`
        Architecture  string `json:"architecture" yaml:"architecture"`
        Hostname      string `json:"hostname" yaml:"hostname"`
        KernelVersion string `json:"kernel_version" yaml:"kernel_version"`
        SoftwareInfo  string `json:"software_info,omitempty"`
        SoftwareCount int    `json:"software_count"`
    }

    formattedCheck struct {
        Name        string           `json:"name" yaml:"name"`
        Status      string           `json:"status" yaml:"status"`
        Description string           `json:"description" yaml:"description"`
        Duration    string           `json:"duration" yaml:"duration"`
        Findings    []formattedFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
        Details     []string         `json:"details,omitempty" yaml:"details,omitempty"`
    }

    formattedFinding struct {
        Title       string            `json:"title" yaml:"title"`
        Severity    string            `json:"severity" yaml:"severity"`
        Description string            `json:"description,omitempty" yaml:"description,omitempty"`
        Impact      string            `json:"impact,omitempty" yaml:"impact,omitempty"`
        Resolution  string            `json:"resolution,omitempty" yaml:"resolution,omitempty"`
        References  []types.Reference `json:"references,omitempty" yaml:"references,omitempty"`
    }

    formattedSummary struct {
        TotalChecks   int    `json:"total_checks" yaml:"total_checks"`
        PassedChecks  int    `json:"passed_checks" yaml:"passed_checks"`
        WarningChecks int    `json:"warning_checks" yaml:"warning_checks"`
        FailedChecks  int    `json:"failed_checks" yaml:"failed_checks"`
        SkippedChecks int    `json:"skipped_checks" yaml:"skipped_checks"`
    }
)

func init() {
    // Define flags
    SecurityCmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
        "Enable verbose output")
    SecurityCmd.Flags().StringVarP(&outputFormat, "output", "o", "text",
        "Output format (text, json, yaml)")
    SecurityCmd.Flags().StringVar(&reportFile, "report-file", "",
        "Save audit report to file")
    SecurityCmd.Flags().StringSliceVar(&customPaths, "paths", []string{},
        "Custom paths to check (comma-separated)")
    SecurityCmd.Flags().StringSliceVar(&skipChecks, "skip-checks", []string{},
        "Checks to skip (comma-separated)")
    SecurityCmd.Flags().StringVar(&minSeverity, "min-severity", "LOW",
        "Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)")
    SecurityCmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute,
        "Maximum time to run the audit")

    // Individual check flags
    SecurityCmd.Flags().BoolVar(&checkSSH, "check-ssh", false,
        "Run SSH configuration check")
    SecurityCmd.Flags().BoolVar(&checkFirewall, "check-firewall", false,
        "Run firewall configuration check")
    SecurityCmd.Flags().BoolVar(&checkUsers, "check-users", false,
        "Run user accounts check")
    SecurityCmd.Flags().StringVar(&checkFilePerms, "file-permissions", "",
        "Check permissions of specified file path")
}

func runSecurityAudit(cmd *cobra.Command, args []string) error {
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

    // Validate flags
    if err := validateFlags(); err != nil {
        return err
    }

    // Create audit options
    opts := audit.AuditOptions{
        Verbose:       verbose,
        CustomPaths:   customPaths,
        SkipChecks:    skipChecks,
        MinSeverity:   minSeverity,
        Timeout:       timeout,
    }

    // Create security auditor
    auditor := audit.NewSecurityAuditor(opts)

    // Show progress if verbose
    if verbose {
        fmt.Println("Starting security audit...")
        if len(checks) > 0 {
            fmt.Printf("Running checks: %s\n", strings.Join(checks, ", "))
        } else {
            fmt.Println("Running comprehensive security audit")
        }

        fmt.Printf("Configuration:\n")
        fmt.Printf("- Output format: %s\n", outputFormat)
        if len(customPaths) > 0 {
            fmt.Printf("- Custom paths: %s\n", strings.Join(customPaths, ", "))
        }
        if len(skipChecks) > 0 {
            fmt.Printf("- Skipped checks: %s\n", strings.Join(skipChecks, ", "))
        }
        fmt.Printf("- Minimum severity: %s\n", minSeverity)
        fmt.Printf("- Timeout: %s\n", timeout)
        fmt.Println()
    }

    // Run the audit with timeout
    resultChan := make(chan *audit.AuditResult, 1)
    errorChan := make(chan error, 1)

    go func() {
        result, err := auditor.RunAudit(args...)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- result
    }()

    // Wait for result or timeout
    select {
    case result := <-resultChan:
        return outputResults(result)
    case err := <-errorChan:
        return fmt.Errorf("audit failed: %w", err)
    case <-time.After(timeout):
        return fmt.Errorf("audit timed out after %v", timeout)
    }
}

func validateFlags() error {
    // Validate output format
    validFormats := map[string]bool{
        "text": true,
        "json": true,
        "yaml": true,
    }
    if !validFormats[outputFormat] {
        return fmt.Errorf("invalid output format: %s", outputFormat)
    }

    // Validate severity level
    validSeverities := map[string]bool{
        "LOW":      true,
        "MEDIUM":   true,
        "HIGH":     true,
        "CRITICAL": true,
    }
    if !validSeverities[strings.ToUpper(minSeverity)] {
        return fmt.Errorf("invalid severity level: %s", minSeverity)
    }

    // Validate custom paths
    for _, path := range customPaths {
        if _, err := os.Stat(path); os.IsNotExist(err) {
            return fmt.Errorf("path does not exist: %s", path)
        }
    }

    // Validate skip checks
    validChecks := map[string]bool{
        "ssh":         true,
        "firewall":    true,
        "users":       true,
        "permissions": true,
    }
    for _, check := range skipChecks {
        if !validChecks[check] {
            return fmt.Errorf("invalid check to skip: %s", check)
        }
    }

    return nil
}

func outputResults(result *audit.AuditResult) error {
    if result == nil || len(result.Results) == 0 {
        fmt.Println("No results to display.")
        return nil
    }

    // Format results based on output format
    var output string
    var err error

    switch outputFormat {
    case "json":
        output, err = formatJSON(result)
    case "yaml":
        output, err = formatYAML(result)
    default:
        output, err = formatText(result)
    }

    if err != nil {
        return fmt.Errorf("failed to format results: %w", err)
    }

    // Save to file if specified
    if reportFile != "" {
        if err := os.WriteFile(reportFile, []byte(output), 0644); err != nil {
            return fmt.Errorf("failed to write report file: %w", err)
        }
        if verbose {
            fmt.Printf("Report saved to: %s\n", reportFile)
        }
    }

    // Print to stdout if no file specified or verbose
    if reportFile == "" || verbose {
        fmt.Println(output)
    }

    if !verbose {
        // Print summary of critical findings
        printCriticalFindings(result)
    }

    return nil
}

func printCriticalFindings(result *audit.AuditResult) {
    var criticalCount int
    var highCount int

    for _, checkResult := range result.Results {
        for _, finding := range checkResult.Findings {
            switch finding.Severity {
            case types.SeverityCritical:
                criticalCount++
            case types.SeverityHigh:
                highCount++
            }
        }
    }

    if criticalCount > 0 || highCount > 0 {
        fmt.Printf("\n%s Security Issues Found:\n", types.SymbolWarning)
        if criticalCount > 0 {
            fmt.Printf("- %d Critical severity findings\n", criticalCount)
        }
        if highCount > 0 {
            fmt.Printf("- %d High severity findings\n", highCount)
        }
        fmt.Println("\nPlease review the detailed report and take appropriate action.")
    }
}

func formatJSON(result *audit.AuditResult) (string, error) {
    formatted := convertToFormattedResult(result)
    
    jsonBytes, err := json.MarshalIndent(formatted, "", "  ")
    if err != nil {
        return "", fmt.Errorf("failed to marshal JSON: %w", err)
    }
    
    return string(jsonBytes), nil
}

func formatYAML(result *audit.AuditResult) (string, error) {
    formatted := convertToFormattedResult(result)
    
    yamlBytes, err := yaml.Marshal(formatted)
    if err != nil {
        return "", fmt.Errorf("failed to marshal YAML: %w", err)
    }
    
    return string(yamlBytes), nil
}

func convertToFormattedResult(result *audit.AuditResult) formattedResult {
    formatted := formattedResult{
        Timestamp: result.StartTime.Format(time.RFC3339),
        Duration:  result.Duration.String(),
        SystemInfo: formattedSystemInfo{
            OS:            result.SystemInfo.OS,
            Architecture:  result.SystemInfo.Architecture,
            Hostname:      result.SystemInfo.Hostname,
            KernelVersion: result.SystemInfo.KernelVersion,
            SoftwareInfo:  result.SystemInfo.SoftwareInfo,
            SoftwareCount: result.SystemInfo.SoftwareCount,
        },
        Summary: formattedSummary{
            TotalChecks:   result.Summary.TotalChecks,
            PassedChecks:  result.Summary.PassedChecks,
            WarningChecks: result.Summary.WarningChecks,
            FailedChecks:  result.Summary.FailedChecks,
            SkippedChecks: result.Summary.SkippedChecks,
        },
    }

    for _, check := range result.Results {
        formattedCheck := formattedCheck{
            Name:        check.Name,
            Status:      check.Status,
            Description: check.Description,
            Duration:    check.Duration.String(),
            Details:     check.Details,
        }

        for _, finding := range check.Findings {
            formattedFinding := formattedFinding{
                Title:       finding.Title,
                Severity:    finding.Severity,
                Description: finding.Description,
                Impact:      finding.Impact,
                Resolution:  finding.Resolution,
                References:  finding.References,
            }
            formattedCheck.Findings = append(formattedCheck.Findings, formattedFinding)
        }

        formatted.Results = append(formatted.Results, formattedCheck)
    }

    return formatted
}

func formatText(result *audit.AuditResult) (string, error) {
    var builder strings.Builder
    isComprehensive := len(result.Results) > 1

    // Header
    if isComprehensive {
        builder.WriteString("Security Audit Report\n")
        builder.WriteString("====================\n\n")

        // System Information
        builder.WriteString(fmt.Sprintf("System: %s %s\n", result.SystemInfo.OS, result.SystemInfo.Architecture))
        builder.WriteString(fmt.Sprintf("Hostname: %s\n", result.SystemInfo.Hostname))
        builder.WriteString(fmt.Sprintf("Kernel: %s\n\n", result.SystemInfo.KernelVersion))
    }

    // Results
    for _, checkResult := range result.Results {
        builder.WriteString(fmt.Sprintf("Check: %s\n", checkResult.Name))
        builder.WriteString(fmt.Sprintf("Status: %s\n", checkResult.Status))
        if verbose {
            builder.WriteString(fmt.Sprintf("Duration: %v\n", checkResult.Duration))

            // Details are only shown in verbose mode
            if len(checkResult.Details) > 0 {
                builder.WriteString("\nDetails:\n")
                for _, detail := range checkResult.Details {
                    builder.WriteString(fmt.Sprintf(" %s\n", detail))
                }
            }
        }
        
        
        if len(checkResult.Findings) > 0 {
            builder.WriteString("\nFindings:\n")
            for _, finding := range checkResult.Findings {
                builder.WriteString(fmt.Sprintf("- [%s] %s\n", finding.Severity, finding.Title))
                if verbose {
                    if finding.Description != "" {
                        builder.WriteString(fmt.Sprintf("  Description: %s\n", finding.Description))
                    }
                    if finding.Impact != "" {
                        builder.WriteString(fmt.Sprintf("  Impact: %s\n", finding.Impact))
                    }
                    if finding.Resolution != "" {
                        builder.WriteString(fmt.Sprintf("  Resolution: %s\n", finding.Resolution))
                    }
                }
            }
        }
        
        builder.WriteString("\n")
    }

    // Summary
    builder.WriteString("\nSummary:\n")
    builder.WriteString(fmt.Sprintf("Checks Run: %d\n", len(result.Results)))
    builder.WriteString(fmt.Sprintf("Passed: %d\n", result.Summary.PassedChecks))
    builder.WriteString(fmt.Sprintf("Warnings: %d\n", result.Summary.WarningChecks))
    builder.WriteString(fmt.Sprintf("Failed: %d\n", result.Summary.FailedChecks))

    if verbose {
        builder.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
    }
    
    return builder.String(), nil
}

// formatJSON and formatYAML functions would be implemented similarly
// They would use encoding/json and gopkg.in/yaml.v2 packages respectively

func init() {
    // This function would be called by the main command to register this subcommand
}