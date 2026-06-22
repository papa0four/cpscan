// cmd/commands/security/security.go
package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/types"
)

var (
	// Command flags
	verbose      bool
	outputFormat string
	reportFile   string
	skipChecks   []string
	minSeverity  string
	timeout      time.Duration

	// Individual check flags
	checkSSH       bool
	checkFirewall  bool
	checkUsers     bool
	checkFilePerms string

	// enrichment flag
	enrich bool

	// allow escalated dir write
	allowElevatedWrite bool
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
  owatch security_audit -v

  # Run specific checks
  owatch security_audit --ssh
  owatch security_audit --fwall
  owatch security_audit --users
  owatch security_audit --fperms /path/to/file

  # Run checks with verbose output
  owatch security_audit --ssh -v

  # Set minimum severity level
  owatch security_audit --min-severity HIGH

  # Run checks and save report to file
  owatch security_audit -v -o json --report-file audit.json`,
}

// Formatter types
type (
	formattedResult struct {
		Timestamp  string              `json:"timestamp" yaml:"timestamp"`
		Duration   string              `json:"duration" yaml:"duration"`
		SystemInfo formattedSystemInfo `json:"system_info" yaml:"system_info"`
		Results    []formattedCheck    `json:"results" yaml:"results"`
		Summary    formattedSummary    `json:"summary" yaml:"summary"`
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
		Name        string             `json:"name" yaml:"name"`
		Status      string             `json:"status" yaml:"status"`
		Description string             `json:"description" yaml:"description"`
		Duration    string             `json:"duration" yaml:"duration"`
		Findings    []formattedFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
		Details     []string           `json:"details,omitempty" yaml:"details,omitempty"`
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
		TotalChecks   int `json:"total_checks" yaml:"total_checks"`
		PassedChecks  int `json:"passed_checks" yaml:"passed_checks"`
		WarningChecks int `json:"warning_checks" yaml:"warning_checks"`
		FailedChecks  int `json:"failed_checks" yaml:"failed_checks"`
		SkippedChecks int `json:"skipped_checks" yaml:"skipped_checks"`
	}
)

func init() {
	SecurityCmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output")
	SecurityCmd.Flags().StringVarP(&outputFormat, "output", "o", "text",
		"Output format (text, json, yaml)")
	SecurityCmd.Flags().StringVar(&reportFile, "report-file", "",
		"Save audit report to file")
	SecurityCmd.Flags().StringSliceVar(&skipChecks, "skip-checks", []string{},
		"Checks to skip (comma-separated)")
	SecurityCmd.Flags().StringVar(&minSeverity, "min-severity", "LOW",
		"Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)")
	SecurityCmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute,
		"Maximum time to run the audit")
	SecurityCmd.Flags().BoolVar(&checkSSH, "ssh", false,
		"Run SSH configuration check")
	SecurityCmd.Flags().BoolVar(&checkFirewall, "fwall", false,
		"Run firewall configuration check")
	SecurityCmd.Flags().BoolVar(&checkUsers, "users", false,
		"Run user accounts check")
	SecurityCmd.Flags().StringVar(&checkFilePerms, "fperms", "",
		"Check permissions of specified file path")
	SecurityCmd.Flags().BoolVarP(&enrich, "enrich", "e", false,
		"Query external sources to annotate findings with CVEs mapped to referenced CWEs")
	SecurityCmd.Flags().BoolVar(&allowElevatedWrite, "allow-elevated-write", false,
		"Permit an elevated write outside the allowlisted directories")
}

func buildChecks() []string {
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
		checks = append(checks, "permissions")
	}
	return checks
}

func validateFlags(cmd *cobra.Command) error {
	validFormats := map[string]bool{
		"text": true,
		"json": true,
		"yaml": true,
	}
	if !validFormats[outputFormat] {
		return fmt.Errorf("invalid output format: %s", outputFormat)
	}

	validSeverities := map[string]bool{
		"LOW":      true,
		"MEDIUM":   true,
		"HIGH":     true,
		"CRITICAL": true,
	}
	if !validSeverities[strings.ToUpper(minSeverity)] {
		return fmt.Errorf("invalid severity level: %s", minSeverity)
	}

	if err := validateFilePermsPath(cmd); err != nil {
		return err
	}

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

// validateFilePermsPath enforces existing path and file rejecting explicit empty value
func validateFilePermsPath(cmd *cobra.Command) error {
	if !cmd.Flags().Changed("fperms") {
		return nil
	}
	if checkFilePerms == "" {
		return fmt.Errorf("--fperms: requires a path")
	}
	if _, err := os.Stat(checkFilePerms); err != nil {
		return fmt.Errorf("--fperms: path is not accessible: %w", err)
	}
	return nil
}

func logVerboseConfig(checks []string) {
	if !verbose {
		return
	}
	if len(checks) > 0 {
		fmt.Printf("[*] Running checks: %s\n", strings.Join(checks, ", "))
	} else {
		fmt.Println("[*] Running comprehensive security audit")
	}
	fmt.Printf("[*] Output format: %s\n", outputFormat)
	if len(skipChecks) > 0 {
		fmt.Printf("[*] Skipped checks: %s\n", strings.Join(skipChecks, ", "))
	}
	fmt.Printf("[*] Minimum severity: %s\n", minSeverity)
	fmt.Printf("[*] Timeout: %s\n", timeout)
	fmt.Println()
}

func runAuditWithTimeout(checks []string) error {
	opts := audit.Options{
		Verbose:        verbose,
		SkipChecks:     skipChecks,
		FilePermsPath:  checkFilePerms,
		MinSeverity:    minSeverity,
		Timeout:        timeout,
		SpecificChecks: checks,
		Enrich:         enrich,
	}

	auditor := audit.NewSecurityAuditor(opts)

	resultChan := make(chan *audit.Result, 1)
	errorChan := make(chan error, 1)

	go func() {
		result, err := auditor.RunAudit()
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- result
	}()

	select {
	case result := <-resultChan:
		return outputResults(result)
	case err := <-errorChan:
		return fmt.Errorf("audit failed: %w", err)
	case <-time.After(timeout):
		return fmt.Errorf("audit timeout after %v", timeout)
	}
}

func outputResults(result *audit.Result) error {
	if result == nil || len(result.Results) == 0 {
		fmt.Println("No results to display.")
		return nil
	}

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

	if reportFile != "" {
		opts := report.Options{AllowElevatedWrite: allowElevatedWrite}
		if err := report.Write(reportFile, []byte(output), opts); err != nil {
			if errors.Is(err, report.ErrElevatedWriteDenied) {
				return fmt.Errorf("%w; pass --allow-elevated-write to permit it", err)
			}
			return fmt.Errorf("failed to write report file: %w", err)
		}
		if verbose {
			fmt.Printf("[+] Report saved to: %s\n", reportFile)
		}
	}

	if reportFile == "" || verbose {
		fmt.Println(output)
	}

	return nil
}

func formatJSON(result *audit.Result) (string, error) {
	formatted := convertToFormattedResult(result)
	jsonBytes, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(jsonBytes), nil
}

func formatYAML(result *audit.Result) (string, error) {
	formatted := convertToFormattedResult(result)
	yamlBytes, err := yaml.Marshal(formatted)
	if err != nil {
		return "", fmt.Errorf("failed to marshal YAML: %w", err)
	}
	return string(yamlBytes), nil
}

func convertToFormattedResult(result *audit.Result) formattedResult {
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
		fc := formattedCheck{
			Name:        check.Name,
			Status:      check.Status,
			Description: check.Description,
			Duration:    check.Duration.String(),
			Details:     check.Details,
		}

		for _, finding := range check.Findings {
			fc.Findings = append(fc.Findings, formattedFinding{
				Title:       finding.Title,
				Severity:    finding.Severity,
				Description: finding.Description,
				Impact:      finding.Impact,
				Resolution:  finding.Resolution,
				References:  finding.References,
			})
		}

		formatted.Results = append(formatted.Results, fc)
	}

	return formatted
}
func renderEnrichmentBlock(builder *strings.Builder, result *audit.Result) {
	if !result.EnrichmentRequested {
		return
	}

	builder.WriteString("Enrichment:\n")

	if result.EnrichmentError != nil {
		fmt.Fprintf(builder, "  Unavailable: %v\n\n", result.EnrichmentError)
		renderReferenceErrors(builder, result.References)
		return
	}

	if len(result.References.CWEs) == 0 {
		builder.WriteString("  No CWE references found in current findings.\n\n")
		renderReferenceErrors(builder, result.References)
		return
	}

	if result.Enrichment == nil {
		builder.WriteString("  No enrichment data returned.\n\n")
		renderReferenceErrors(builder, result.References)
		return
	}

	rendered := 0
	for _, cwe := range result.References.CWEs {
		entry, ok := result.Enrichment.Successes[cwe]
		if !ok {
			continue
		}
		rendered++
		fmt.Fprintf(builder, "  %s", cwe)
		if entry.WeaknessName != "" {
			fmt.Fprintf(builder, " - %s", entry.WeaknessName)
		}
		fmt.Fprintln(builder)

		if entry.Status == "NO_MATCHES" || len(entry.MatchedCVEs) == 0 {
			builder.WriteString("    No CVE matches in queried sources.\n")
			continue
		}

		for _, match := range entry.MatchedCVEs {
			symbol, label := types.SeverityFormat(match.CVSSSeverity)
			fmt.Fprintf(builder, "    %s %s  %s (%.1f) [%s]\n",
				symbol, label, match.CVEID, match.CVSSBaseScore, match.Source)
			if verbose {
				if match.Description != "" {
					fmt.Fprintf(builder, "      Description: %s\n", match.Description)
				}
				if match.KnownExploited {
					builder.WriteString("      Known Exploited: yes\n")
				}
				if match.PatchAvailable {
					builder.WriteString("      Patch Available: yes\n")
				}
			}
		}
	}

	if rendered == 0 {
		builder.WriteString("  No enrichment data returned.\n")
	}

	if len(result.Enrichment.Failures) > 0 {
		builder.WriteString("\n  Failed enrichments:\n")
		for cwe, failure := range result.Enrichment.Failures {
			fmt.Fprintf(builder, "    %s [%s]: %s",
				cwe, failure.Source, failure.Reason)
			if failure.Retryable {
				builder.WriteString(" (retryable)")
			}
			fmt.Fprintln(builder)
		}
	}

	builder.WriteString("\n")
	renderReferenceErrors(builder, result.References)
}

func renderReferenceErrors(builder *strings.Builder, refs types.ReferenceExtraction) {
	if len(refs.Errors) == 0 {
		return
	}
	builder.WriteString("  Reference parsing errors:\n")
	for _, err := range refs.Errors {
		fmt.Fprintf(builder, "    %v\n", err)
	}
	builder.WriteString("\n")
}

func formatText(result *audit.Result) (string, error) {
	var builder strings.Builder
	isComprehensive := len(result.Results) > 1

	if isComprehensive {
		builder.WriteString("Security Audit Report\n")
		builder.WriteString("====================\n\n")
		fmt.Fprintf(&builder, "System: %s %s\n", result.SystemInfo.OS, result.SystemInfo.Architecture)
		fmt.Fprintf(&builder, "Hostname: %s\n", result.SystemInfo.Hostname)
		fmt.Fprintf(&builder, "Kernel: %s\n\n", result.SystemInfo.KernelVersion)
	}

	hasFindings := false

	for _, checkResult := range result.Results {
		fmt.Fprintf(&builder, "Check: %s\n", checkResult.Name)
		fmt.Fprintf(&builder, "Status: %s\n", checkResult.Status)
		fmt.Fprintf(&builder, "Duration: %v\n", checkResult.Duration)

		if len(checkResult.Findings) > 0 {
			hasFindings = true
			builder.WriteString("Findings:\n")
			for _, finding := range checkResult.Findings {
				symbol, label := types.SeverityFormat(finding.Severity)
				fmt.Fprintf(&builder, "%s %s  %s\n", symbol, label, finding.Title)
				if verbose {
					if finding.Description != "" {
						fmt.Fprintf(&builder, "  Description: %s\n", finding.Description)
					}
					if finding.Impact != "" {
						fmt.Fprintf(&builder, "  Impact: %s\n", finding.Impact)
					}
					if finding.Resolution != "" {
						fmt.Fprintf(&builder, "  Resolution: %s\n", finding.Resolution)
					}
				}
			}
		}

		if verbose && len(checkResult.Details) > 0 {
			builder.WriteString("Raw Diagnostic Output:\n")
			for _, detail := range checkResult.Details {
				fmt.Fprintf(&builder, "  %s\n", detail)
			}
		}

		builder.WriteString("\n")
	}

	renderEnrichmentBlock(&builder, result)
	builder.WriteString("Summary:\n")
	fmt.Fprintf(&builder, "Checks Run: %d\n", len(result.Results))
	fmt.Fprintf(&builder, "Passed:     %d\n", result.Summary.PassedChecks)
	fmt.Fprintf(&builder, "Warnings:   %d\n", result.Summary.WarningChecks)
	fmt.Fprintf(&builder, "Failed:     %d\n", result.Summary.FailedChecks)
	fmt.Fprintf(&builder, "Duration:   %v\n", result.Duration)

	if !verbose && hasFindings {
		builder.WriteString("\nRun with -v for full finding details, impact analysis, and remediation guidance.\n")
	}

	return builder.String(), nil
}
