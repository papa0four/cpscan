// cmd/commands/all.go
package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/papa0four/cpscan/internal/osfingerprint"
	"github.com/papa0four/cpscan/internal/security/audit"
	"github.com/papa0four/cpscan/internal/security/formatter"
	"github.com/papa0four/cpscan/internal/security/types"
	"github.com/papa0four/cpscan/internal/softwarelist"
	"github.com/spf13/cobra"
)

var (
	allVerbose      bool
	allOutputFormat string
	allReportFile   string
	skipModules     []string
	allTimeout      time.Duration
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
	allCmd.Flags().BoolVarP(&allVerbose, "verbose", "v", false,
		"Enable verbose output for all scans")
	allCmd.Flags().StringVarP(&allOutputFormat, "output", "o", "text",
		"Output format (text, json, yaml)")
	allCmd.Flags().StringVar(&allReportFile, "report-file", "",
		"Save complete report to file")
	allCmd.Flags().StringSliceVar(&skipModules, "skip-modules", []string{},
		"Modules to skip (comma-separated: os,software,security)")
	allCmd.Flags().DurationVar(&allTimeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")

	RootCmd.AddCommand(allCmd)
}

// ScanResult represents the combined results of all scans
type ScanResult struct {
	Timestamp     time.Time             `json:"timestamp"`
	Duration      time.Duration         `json:"duration"`
	OSInfo        *osfingerprint.OSInfo `json:"os_info,omitempty"`
	SoftwareInfo  string                `json:"software_info,omitempty"`
	SoftwareCount int                   `json:"software_count"`
	SecurityAudit *audit.AuditResult    `json:"security_audit,omitempty"`
	Errors        []string              `json:"errors,omitempty"`
}

func runAllScans(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	if isModuleSkipped("os") && isModuleSkipped("software") && isModuleSkipped("security") {
		return fmt.Errorf("all modules have been skipped, at least one module must be run")
	}

	results := make(chan *ScanResult, 1)

	go func() {
		result := &ScanResult{
			Timestamp: startTime,
			Errors:    make([]string, 0),
		}

		if !isModuleSkipped("os") {
			if osInfo, err := runOSFingerprint(); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("OS fingerprint error: %v", err))
			} else {
				result.OSInfo = osInfo
			}
		}

		if !isModuleSkipped("software") {
			softwareInfo, softwareCount, err := runSoftwareInventory()
			if err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("Software inventory error: %v", err))
			} else {
				result.SoftwareInfo = softwareInfo
				result.SoftwareCount = softwareCount
			}
		}

		if !isModuleSkipped("security") {
			if securityResult, err := runSecurityAuditModule(); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("Security audit error: %v", err))
			} else {
				result.SecurityAudit = securityResult
			}
		}

		result.Duration = time.Since(startTime)
		results <- result
	}()

	select {
	case result := <-results:
		return outputResults(result)
	case <-time.After(allTimeout):
		return fmt.Errorf("scan timed out after %v", allTimeout)
	}
}

func runOSFingerprint() (*osfingerprint.OSInfo, error) {
	if allVerbose {
		fmt.Println("[*] OS Fingerprint Scan")
	}

	info, err := osfingerprint.GetOSFingerprint()
	if err != nil {
		return nil, err
	}

	if allVerbose {
		fmt.Printf("[*] OS: %s | Platform: %s | Version: %s | Kernel: %s\n",
			info.OS, info.Platform, info.PlatformVersion, info.KernelVersion)
	}

	return info, nil
}

func runSoftwareInventory() (string, int, error) {
	if allVerbose {
		fmt.Println("[*] Software Inventory Scan")
	}

	software, err := softwarelist.GetInstalledSoftware()
	if err != nil {
		return "", 0, err
	}

	softwareCount := strings.Count(software, "\n") + 1

	if allVerbose {
		fmt.Printf("[*] Found %d installed packages\n", softwareCount)
		fmt.Println(software)
	}

	return software, softwareCount, nil
}

func runSecurityAuditModule() (*audit.AuditResult, error) {
	if allVerbose {
		fmt.Println("[*] Security Audit Scan")
	}

	opts := audit.AuditOptions{
		Verbose:     allVerbose,
		MinSeverity: "LOW",
		Timeout:     allTimeout / 3,
	}

	auditor := audit.NewSecurityAuditor(opts)
	return auditor.RunAudit()
}

func convertToAuditResult(scan *ScanResult) *audit.AuditResult {
	if scan.SecurityAudit == nil {
		return nil
	}

	sysInfo := audit.SystemInfo{
		SoftwareInfo:  scan.SoftwareInfo,
		SoftwareCount: scan.SoftwareCount,
	}

	if scan.OSInfo != nil {
		sysInfo.OS = scan.OSInfo.OS
		sysInfo.Architecture = scan.OSInfo.Platform
		sysInfo.Hostname = scan.OSInfo.PlatformVersion
		sysInfo.KernelVersion = scan.OSInfo.KernelVersion
	}

	return &audit.AuditResult{
		StartTime:  scan.Timestamp,
		EndTime:    scan.Timestamp.Add(scan.Duration),
		Duration:   scan.Duration,
		Results:    scan.SecurityAudit.Results,
		SystemInfo: sysInfo,
		Summary:    scan.SecurityAudit.Summary,
	}
}

func outputResults(result *ScanResult) error {
	opts := formatter.FormatOptions{
		Format:        formatter.OutputFormat(allOutputFormat),
		Verbose:       allVerbose,
		ColorOutput:   isTerminal(),
		IncludeSystem: true,
		Compact:       false,
	}

	var output io.Writer = os.Stdout
	if allReportFile != "" {
		file, err := os.Create(allReportFile)
		if err != nil {
			return fmt.Errorf("failed to create report file: %w", err)
		}
		defer file.Close()
		output = file
	}

	auditResult := convertToAuditResult(result)
	if auditResult == nil {
		return fmt.Errorf("no security audit results available")
	}

	f := formatter.NewFormatter(output, opts)
	if err := f.Format(auditResult); err != nil {
		return fmt.Errorf("failed to format results: %w", err)
	}

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
		fmt.Printf("\n%s Critical Security Findings:\n", types.SymbolCritical)
		if criticalCount > 0 {
			fmt.Printf("  %d Critical severity issues found\n", criticalCount)
		}
		if highCount > 0 {
			fmt.Printf("  %d High severity issues found\n", highCount)
		}
		fmt.Println("\nPlease review the detailed security audit section of the report.")
	}
}

// isTerminal checks if the output is going to a terminal
func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
