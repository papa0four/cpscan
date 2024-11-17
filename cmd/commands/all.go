// cmd/commands/all.go
package cmd

import (
    "fmt"
	"io"
    "os"
    // "runtime"
    "strings"
    "time"

    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/internal/osfingerprint"
    "github.com/papa0four/cpscan/internal/security/audit"
    "github.com/papa0four/cpscan/internal/security/formatter"
    "github.com/papa0four/cpscan/internal/security/types"
    "github.com/papa0four/cpscan/internal/softwarelist"
)

var (
    // Command flags for 'all' command
    allVerbose     bool
    outputFormat   string
    reportFile     string
    skipModules    []string
    timeout        time.Duration
)

// allCmd represents the all command that combines all scanning modules
var allCmd = &cobra.Command{
    Use:   "all",
    Short: "Run all available scans",
    Long: `The all command performs a comprehensive system scan including:
- OS fingerprinting
- Software inventory
- Security audit
- System configuration analysis

Results can be output in various formats and saved to a file.`,
    Example: `  # Run all scans with default settings
  cpscan all

  # Run all scans with verbose output
  cpscan all -v

  # Skip specific modules
  cpscan all --skip-modules security,software

  # Save report to file in JSON format
  cpscan all -o json --report-file system-scan.json`,
    RunE: runAllScans,
}

func init() {
    // Add command flags
    allCmd.Flags().BoolVarP(&allVerbose, "verbose", "v", false,
        "Enable verbose output for all scans")
    allCmd.Flags().StringVarP(&outputFormat, "output", "o", "text",
        "Output format (text, json, yaml)")
    allCmd.Flags().StringVar(&reportFile, "report-file", "",
        "Save complete report to file")
    allCmd.Flags().StringSliceVar(&skipModules, "skip-modules", []string{},
        "Modules to skip (comma-separated: os,software,security)")
    allCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Minute,
        "Maximum time to run all scans")

    RootCmd.AddCommand(allCmd)
}

// ScanResult represents the combined results of all scans
type ScanResult struct {
    Timestamp     time.Time                 `json:"timestamp"`
    Duration      time.Duration             `json:"duration"`
    OSInfo        *osfingerprint.OSInfo     `json:"os_info,omitempty"`
    SoftwareInfo  string                    `json:"software_info,omitempty"`
    SecurityAudit *audit.AuditResult        `json:"security_audit,omitempty"`
    Errors        []string                  `json:"errors,omitempty"`
}

func runAllScans(cmd *cobra.Command, args []string) error {
    startTime := time.Now()

    if isModuleSkipped("os") && isModuleSkipped("software") && isModuleSkipped("security") {
        return fmt.Errorf("all modules have been skipped, at least one module must be run")
    }
    
    // Create channels for results and errors
    results := make(chan *ScanResult, 1)
    errorChan := make(chan error, 1)

    // Run scans with timeout
    go func() {
        result := &ScanResult{
            Timestamp: startTime,
            Errors:    make([]string, 0),
        }

        // Run each scan if not skipped
        if !isModuleSkipped("os") {
            if osInfo, err := runOSFingerprint(); err != nil {
                result.Errors = append(result.Errors, 
                    fmt.Sprintf("OS fingerprint error: %v", err))
            } else {
                result.OSInfo = osInfo
            }
        }

        if !isModuleSkipped("software") {
            softwareInfo, err := runSoftwareInventory()
                if err != nil {
                result.Errors = append(result.Errors, 
                    fmt.Sprintf("Software inventory error: %v", err))
            } else {
                result.SoftwareInfo = softwareInfo
            }
        }

        if !isModuleSkipped("security") {
            if securityResult, err := runSecurityAudit(); err != nil {
                result.Errors = append(result.Errors, 
                    fmt.Sprintf("Security audit error: %v", err))
            } else {
                result.SecurityAudit = securityResult
            }
        }

        result.Duration = time.Since(startTime)
        results <- result
    }()

    // Wait for completion or timeout
    select {
    case result := <-results:
        return outputResults(result)
    case err := <-errorChan:
        return fmt.Errorf("scan failed: %w", err)
    case <-time.After(timeout):
        return fmt.Errorf("scan timed out after %v", timeout)
    }
}

func runOSFingerprint() (*osfingerprint.OSInfo, error) {
    if allVerbose {
        fmt.Println("\n=== OS Fingerprint Scan ===")
    }
    
    info, err := osfingerprint.GetOSFingerprint()
    if err != nil {
        return nil, err
    }

    if allVerbose {
        fmt.Printf("OS: %s\nPlatform: %s\nVersion: %s\nKernel: %s\n",
            info.OS, info.Platform, info.PlatformVersion, info.KernelVersion)
    }

    return info, nil
}

func runSoftwareInventory() (string, error) {
    if allVerbose {
        fmt.Println("\n=== Software Inventory Scan ===")
    }

    software, err := softwarelist.GetInstalledSoftware()
    if err != nil {
        return "", err
    }

    if allVerbose {
        fmt.Printf("Found %d installed packages\n", 
            strings.Count(software, "\n")+1)
        fmt.Println("For a comprehensive list of software, run 'cpscan software'.")
    }

    return software, nil
}

func runSecurityAudit() (*audit.AuditResult, error) {
    if allVerbose {
        fmt.Println("\n=== Security Audit Scan ===")
    }

    // Create audit options
    opts := audit.AuditOptions{
        Verbose:     allVerbose,
        CustomPaths: nil,
        SkipChecks:  nil,
        MinSeverity: "LOW",
        Timeout:     timeout / 3, // Allocate one-third of total timeout
    }

    // Create and run auditor
    auditor := audit.NewSecurityAuditor(opts)
    return auditor.RunAudit()
}

// conversion helper function to convert scan result to audit result
func convertToAuditResult(scan *ScanResult) *audit.AuditResult {
    if scan.SecurityAudit == nil {
        return nil
    }
    
    return &audit.AuditResult{
        StartTime:   scan.Timestamp,
        EndTime:     scan.Timestamp.Add(scan.Duration),
        Duration:    scan.Duration,
        Results:     scan.SecurityAudit.Results,
        SystemInfo:  audit.SystemInfo{
            OS:            scan.OSInfo.OS,
            Architecture: scan.OSInfo.Platform,
            Hostname:     scan.OSInfo.PlatformVersion,
            KernelVersion: scan.OSInfo.KernelVersion,
        },
        Summary:    scan.SecurityAudit.Summary,
    }
}

func outputResults(result *ScanResult) error {
    // Create formatter options
    opts := formatter.FormatOptions{
        Format:        formatter.OutputFormat(outputFormat),
        Verbose:       allVerbose,
        ColorOutput:   isTerminal(),
        IncludeSystem: true,
        Compact:       false,
    }

    // Create output formatter
    var output io.Writer = os.Stdout
    if reportFile != "" {
        file, err := os.Create(reportFile)
        if err != nil {
            return fmt.Errorf("failed to create report file: %w", err)
        }
        defer file.Close()
        output = file
    }

	// // Convert ScanResult to AuditResult
	// auditResult := convertToAuditResult(result)
	// if auditResult == nil {
	// 	return fmt.Errorf("no security audit results available")
	// }

    // f := formatter.NewFormatter(output, opts)
    // if err := f.Format(auditResult); err != nil {
    //     return fmt.Errorf("failed to format results: %w", err)
    // }

    // // Print summary of critical findings if any
    // if result.SecurityAudit != nil {
    //     printCriticalFindings(result.SecurityAudit)
    // }

    // return nil

    f := formatter.NewFormatter(output, opts)

    // Output OS information
    if result.OSInfo != nil {
        fmt.Fprintf(output, "OS: %s\nPlatform: %s\nVersion: %s\nKernel: %s\n\n",
            result.OSInfo.OS, result.OSInfo.Platform, 
            result.OSInfo.PlatformVersion, result.OSInfo.KernelVersion)
    }

    // Output software information
    if result.SoftwareInfo != "" {
        fmt.Fprintln(output, "Installed Software:")
        fmt.Fprintln(output, result.SoftwareInfo)
        fmt.Fprintln(output)
    }

    // Output security audit results
    if result.SecurityAudit != nil {
        if err := f.Format(result.SecurityAudit); err != nil {
            return fmt.Errorf("failed to format security audit results: %w", err)
        }
    }

    // Print summary of critical findings if any
    if result.SecurityAudit != nil {
        printCriticalFindings(result.SecurityAudit)
    }

    return nil
}

func isModuleSkipped(module string) bool {
    if len(skipModules) == 0 {
        return false
    }

    for _, skip := range skipModules {
        if strings.EqualFold(skip, module) {
            return true
        }
    }
    return false
}

func printCriticalFindings(auditResult *audit.AuditResult) {
    var criticalCount, highCount int

    for _, result := range auditResult.Results {
        for _, finding := range result.Findings {
            switch finding.Severity {
            case types.SeverityCritical:
                criticalCount++
            case types.SeverityHigh:
                highCount++
            }
        }
    }

    if criticalCount > 0 || highCount > 0 {
        fmt.Printf("\n%s Critical Security Findings:\n", types.SymbolWarning)
        if criticalCount > 0 {
            fmt.Printf("- %d Critical severity issues found\n", criticalCount)
        }
        if highCount > 0 {
            fmt.Printf("- %d High severity issues found\n", highCount)
        }
        fmt.Printf("\nPlease review the detailed security audit section of the report.\n")
    }
}

// isTerminal checks if the output is going to a terminal
func isTerminal() bool {
    fileInfo, _ := os.Stdout.Stat()
    return (fileInfo.Mode() & os.ModeCharDevice) != 0
}