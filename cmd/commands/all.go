// cmd/commands/all.go
package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/formatter"
	"github.com/papa0four/orkowatch/internal/softwarelist"
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
  owatch all

  # Run all scans with verbose output
  owatch all -v || owatch all --verbose

  # Skip specific modules
  owatch all --skip-modules security,software

  # Save report to file in JSON format
  owatch all -o json --report-file system-scan.json`,
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
	SecurityAudit *audit.Result         `json:"security_audit,omitempty"`
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
		line := fmt.Sprintf("[*] OS: %s | Platform: %s | OS Version: %s",
			info.OS, info.Platform, info.PlatformVersion)
		if info.KernelVersion != "" && info.KernelVersion != info.PlatformVersion {
			line += fmt.Sprintf(" | Kernel: %s", info.KernelVersion)
		}
		fmt.Println(line)
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
		fmt.Printf("[*] Found %d installed packages\n\n", softwareCount)
		fmt.Println(software)
	}

	return software, softwareCount, nil
}

func runSecurityAuditModule() (*audit.Result, error) {
	if allVerbose {
		fmt.Println("[*] Security Audit Scan")
	}

	opts := audit.Options{
		Verbose:     allVerbose,
		MinSeverity: "LOW",
		Timeout:     allTimeout / 3,
	}

	auditor := audit.NewSecurityAuditor(opts)
	return auditor.RunAudit()
}

func convertToAuditResult(scan *ScanResult) *audit.Result {
	if scan.SecurityAudit == nil {
		return nil
	}

	sysInfo := scan.SecurityAudit.SystemInfo
	if scan.OSInfo != nil {
		if scan.OSInfo.Platform != "" {
			sysInfo.OS = scan.OSInfo.Platform
		}
		if scan.OSInfo.KernelVersion != "" {
			sysInfo.KernelVersion = scan.OSInfo.KernelVersion
		}
	}
	if scan.SoftwareInfo != "" {
		sysInfo.SoftwareInfo = scan.SoftwareInfo
		sysInfo.SoftwareCount = scan.SoftwareCount
	}

	return &audit.Result{
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
		if err := isSafeReportPath(allReportFile); err != nil {
			return fmt.Errorf("invalid report file path: %w", err)
		}
		file, err := os.Create(allReportFile) // #nosec G304 -- path validated by isSafeReportPath before use
		if err != nil {
			return fmt.Errorf("failed to create report file: %w", err)
		}
		defer file.Close() //nolint:errcheck // report file written successfully before close; close error does not affect output
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

// isTerminal checks if the output is going to a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// isSafeReportPath validates the report file path to prevent
// path traversal attacks (CWE-22) when creating output files.
func isSafeReportPath(path string) error {
	if strings.Contains(path, "..") {
		return fmt.Errorf("report file path must not contain traversal sequences: %s", path)
	}
	if path == "" {
		return fmt.Errorf("report file path must not be empty")
	}
	return nil
}
