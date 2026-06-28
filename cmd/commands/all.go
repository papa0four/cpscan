// cmd/commands/all.go
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/scan"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/formatter"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

var (
	allVerbose            bool
	allEnrich             bool
	allAllowElevatedWrite bool
	allOutputFormat       string
	allReportFile         string
	skipModules           []string
	allTimeout            time.Duration
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
  owatch all -v

  # Skip specific modules
  owatch all --skip-modules security,software

  # Save report to directory in JSON format
  owatch all -o json --report-file /path/to/reports`,
	RunE: runAllScans,
}

func init() {
	allCmd.Flags().BoolVarP(&allVerbose, "verbose", "v", false,
		"Enable verbose output for all scans")
	allCmd.Flags().StringVarP(&allOutputFormat, "output", "o", "text",
		"Output format (json, yaml, text, csv)")
	allCmd.Flags().StringVar(&allReportFile, "report-file", "",
		"Save complete report to the specified directory; filename is generated automatically")
	allCmd.Flags().StringSliceVar(&skipModules, "skip-modules", []string{},
		"Modules to skip (comma-separated: os,software,security)")
	allCmd.Flags().DurationVar(&allTimeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")
	allCmd.Flags().BoolVarP(&allEnrich, "enrich", "e", false,
		"Query external sources to annotate findings with CVEs mapped to referenced CWEs")
	allCmd.Flags().BoolVar(&allAllowElevatedWrite, "allow-elevated-write", false,
		"Permit an elevated write outside the allowlisted directories")

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

// allScanLabel is the scan segment used in generated report filenames for the all command
const allScanLabel = "all"

// buildAllMask composes a CheckMask from the active module and security check flags
func buildAllMask() scan.CheckMask {
	var mask scan.CheckMask
	if !isModuleSkipped("os") {
		mask |= scan.ModuleOS
	}
	if !isModuleSkipped("software") {
		mask |= scan.ModuleSoftware
	}
	if !isModuleSkipped("security") {
		mask |= scan.CheckSSH | scan.CheckFirewall | scan.CheckUsers | scan.CheckPerms
	}
	return mask
}

// validateSkipModules rejects any --skip-modules value that is not recognized
func validateSkipModules() error {
	valid := map[string]bool{
		"os":       true,
		"software": true,
		"security": true,
	}
	for _, module := range skipModules {
		if !valid[strings.ToLower(module)] {
			return fmt.Errorf("invalid module to skip: %s (valid: os, software, security)", module)
		}
	}
	return nil
}

// validateAllFlags rejects invalid flag combinations for the all command.
func validateAllFlags(cmd *cobra.Command) error {
	switch allOutputFormat {
	case "json", "yaml", "text", "csv":
		// accepted
	default:
		return fmt.Errorf("invalid output format: %s (valid: json, yaml, text, csv)", allOutputFormat)
	}

	if cmd.Flags().Changed("report-file") {
		if err := validateAllReportDir(allReportFile); err != nil {
			return err
		}
	}

	return nil
}

// validateAllReportDir confirms that the value passed to --report-file is an
// existing directory. The program generates the filename inside it; the caller
// supplies only the destination directory.
func validateAllReportDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("--report-file: directory is not accessible: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--report-file: %s is not a directory", path)
	}
	return nil
}

func runAllScans(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	if err := validateSkipModules(); err != nil {
		return err
	}

	if err := validateAllFlags(cmd); err != nil {
		return err
	}

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

	mask := buildAllMask()
	select {
	case result := <-results:
		return outputResults(cmd, result, mask)
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
		Enrich:      allEnrich,
	}

	auditor := audit.NewSecurityAuditor(opts)
	return auditor.RunAudit()
}

func convertToAuditResult(scan *ScanResult) *audit.Result {
	var sysInfo audit.SystemInfo
	if scan.SecurityAudit != nil {
		sysInfo = scan.SecurityAudit.SystemInfo
	} else {
		sysInfo = audit.SystemInfo{
			OS:           runtime.GOOS,
			Architecture: runtime.GOARCH,
		}
		if hostname, err := os.Hostname(); err == nil {
			sysInfo.Hostname = hostname
		}
	}

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

	result := &audit.Result{
		StartTime:  scan.Timestamp,
		EndTime:    scan.Timestamp.Add(scan.Duration),
		Duration:   scan.Duration,
		SystemInfo: sysInfo,
	}

	if scan.SecurityAudit != nil {
		result.Results = scan.SecurityAudit.Results
		result.Summary = scan.SecurityAudit.Summary
		result.EnrichmentRequested = scan.SecurityAudit.EnrichmentRequested
		result.EnrichmentError = scan.SecurityAudit.EnrichmentError
		result.Enrichment = scan.SecurityAudit.Enrichment
		result.References = scan.SecurityAudit.References
	}

	return result
}

func outputResults(cmd *cobra.Command, result *ScanResult, mask scan.CheckMask) error {
	format := "text"
	if cmd.Flags().Changed("output") {
		format = allOutputFormat
	} else if allReportFile != "" {
		format = "json"
	}

	opts := formatter.FormatOptions{
		Format:        formatter.OutputFormat(format),
		Verbose:       allVerbose,
		ColorOutput:   isTerminal() && allReportFile == "",
		IncludeSystem: true,
		Compact:       false,
	}

	auditResult := convertToAuditResult(result)

	var buf bytes.Buffer
	f := formatter.NewFormatter(&buf, opts)
	if err := f.Format(auditResult); err != nil {
		return fmt.Errorf("failed to format results: %w", err)
	}

	if allReportFile != "" {
		hostname := report.ResolveHostname()
		codes := scan.Codes(mask)
		path := report.DefaultPath(allReportFile, allScanLabel, hostname, codes, format)
		wOpts := report.Options{AllowElevatedWrite: allAllowElevatedWrite}
		if err := report.Write(path, buf.Bytes(), wOpts); err != nil {
			if errors.Is(err, report.ErrElevatedWriteDenied) {
				return fmt.Errorf("%w; pass --allow-elevated-write to permit it", err)
			}
			return fmt.Errorf("failed to write report file: %w", err)
		}
		if allVerbose {
			fmt.Printf("[+] Report saved to: %s\n", path)
		}
		return nil
	}

	fmt.Print(buf.String())
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
