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

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/scan"
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
	Use:     "audit [flags] [check...]",
	Aliases: []string{"security_audit"},
	Short:   "Perform a security audit of the system",
	Long: `Perform a comprehensive security audit of the system.
This command checks various security aspects including:
- SSH configuration
- Firewall rules
- User accounts
- File permissions

You can run all checks or specify individual checks to run.`,
	Example: `  # Run all security checks with verbose output
  owatch audit -v

  # Run specific checks
  owatch audit --ssh
  owatch audit --fwall
  owatch audit --users
  owatch audit --fperms /path/to/file

  # Run checks with verbose output
  owatch audit --ssh -v

  # Set minimum severity level
  owatch audit --min-severity HIGH

  # Run checks and save report to file
  owatch audit -v -o json --report-file /path/to/reports`,
}

// Formatter types
type (
	formattedResult struct {
		Timestamp           string                     `json:"timestamp" yaml:"timestamp"`
		Duration            string                     `json:"duration" yaml:"duration"`
		SystemInfo          formattedSystemInfo        `json:"system_info" yaml:"system_info"`
		Results             []formattedCheck           `json:"results" yaml:"results"`
		Summary             formattedSummary           `json:"summary" yaml:"summary"`
		FindingsSuppressed  int                        `json:"findings_suppressed,omitempty" yaml:"findings_suppressed,omitempty"`
		MinSeverityApplied  string                     `json:"min_severity_applied,omitempty" yaml:"min_severity_applied,omitempty"`
		EnrichmentRequested bool                       `json:"enrichment_requested" yaml:"enrichment_requested"`
		EnrichmentError     string                     `json:"enrichment_error,omitempty" yaml:"enrichment_error,omitempty"`
		ReferenceCWEs       []string                   `json:"reference_cwes,omitempty" yaml:"reference_cwes,omitempty"`
		ReferenceErrors     []string                   `json:"reference_errors,omitempty" yaml:"reference_errors,omitempty"`
		EnrichmentEntries   []render.EnrichmentEntry   `json:"enrichment_entries,omitempty" yaml:"enrichment_entries,omitempty"`
		EnrichmentFailures  []render.EnrichmentFailure `json:"enrichment_failures,omitempty" yaml:"enrichment_failures,omitempty"`
	}

	formattedSystemInfo struct {
		OS            string `json:"os" yaml:"os"`
		Architecture  string `json:"architecture" yaml:"architecture"`
		Hostname      string `json:"hostname" yaml:"hostname"`
		KernelVersion string `json:"kernel_version" yaml:"kernel_version"`
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

	// formattedSummary carries per-severity finding counts and check-level
	// pass/skip totals for structured output formats. WarningChecks and
	// FailedChecks are removed -- findings are the canonical signal; check
	// status is reflected in PassedChecks and SkippedChecks only.
	formattedSummary struct {
		TotalChecks      int `json:"total_checks" yaml:"total_checks"`
		PassedChecks     int `json:"passed_checks" yaml:"passed_checks"`
		SkippedChecks    int `json:"skipped_checks" yaml:"skipped_checks"`
		TotalFindings    int `json:"total_findings" yaml:"total_findings"`
		CriticalFindings int `json:"critical_findings" yaml:"critical_findings"`
		HighFindings     int `json:"high_findings" yaml:"high_findings"`
		MediumFindings   int `json:"medium_findings" yaml:"medium_findings"`
		LowFindings      int `json:"low_findings" yaml:"low_findings"`
	}
)

func init() {
	SecurityCmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output")
	SecurityCmd.Flags().StringVarP(&outputFormat, "output", "o", "text",
		"Output format (text, json, yaml)")
	SecurityCmd.Flags().StringVar(&reportFile, "report-file", "",
		"Save audit report to the specified directory; filename is generated automatically")
	SecurityCmd.Flags().StringSliceVar(&skipChecks, "skip-checks", []string{},
		"Checks to skip (comma-separated: ssh, firewall, users, permissions)")
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

// buildMask composes a CheckMask from the active flag values
func buildMask() (scan.CheckMask, error) {
	mask := scan.CheckSSH | scan.CheckFirewall | scan.CheckUsers | scan.CheckPerms

	if checkSSH || checkFirewall || checkUsers || checkFilePerms != "" {
		mask = 0
		if checkSSH {
			mask |= scan.CheckSSH
		}
		if checkFirewall {
			mask |= scan.CheckFirewall
		}
		if checkUsers {
			mask |= scan.CheckUsers
		}
		if checkFilePerms != "" {
			mask |= scan.CheckPerms
		}
	}

	if len(skipChecks) > 0 {
		skipMask, err := scan.MaskFromNames(skipChecks, scan.CategoryCheck)
		if err != nil {
			return 0, err
		}
		mask &^= skipMask
	}

	return mask, nil
}

func validateFlags(cmd *cobra.Command) error {
	switch outputFormat {
	case "json", "yaml", "text", "csv":
		// accepted
	default:
		return fmt.Errorf("invalid output format: %s (valid: json, yaml, text)", outputFormat)
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

	if cmd.Flags().Changed("report-file") {
		if err := validateReportDir(reportFile); err != nil {
			return err
		}
	}

	if _, err := scan.MaskFromNames(skipChecks, scan.CategoryCheck); err != nil {
		return err
	}

	return nil
}

// validateReportDir confirms that the value passed to --report-file is an existing directory.
// The program generates the filename inside it; the caller supplies only the destination directory.
func validateReportDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("--report-file: directory is not accessible: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--report-file: %s is not a directory", path)
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

func logVerboseConfig(mask scan.CheckMask) {
	if !verbose || reportFile != "" {
		return
	}
	checks := scan.EnabledChecks(mask)
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

func runAuditWithTimeout(cmd *cobra.Command, mask scan.CheckMask) error {
	opts := audit.Options{
		Verbose:        verbose && reportFile == "",
		SkipChecks:     skipChecks,
		FilePermsPath:  checkFilePerms,
		MinSeverity:    minSeverity,
		Timeout:        timeout,
		SpecificChecks: scan.EnabledChecks(mask),
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
		return outputResults(cmd, result, mask)
	case err := <-errorChan:
		return fmt.Errorf("audit failed: %w", err)
	case <-time.After(timeout):
		return fmt.Errorf("audit timeout after %v", timeout)
	}
}

func outputResults(cmd *cobra.Command, result *audit.Result, mask scan.CheckMask) error {
	if result == nil || len(result.Results) == 0 {
		fmt.Println("No results to display.")
		return nil
	}

	format := "text"
	if cmd.Flags().Changed("output") {
		format = outputFormat
	} else if reportFile != "" {
		format = "json"
	}

	var output string
	var err error

	switch format {
	case "json":
		output, err = formatJSON(result)
	case "yaml":
		output, err = formatYAML(result)
	case "csv":
		return fmt.Errorf("csv output format is not yet implemented")
	default:
		output, err = formatText(result)
	}

	if err != nil {
		return fmt.Errorf("failed to format results: %w", err)
	}

	if reportFile != "" {
		hostname := report.ResolveHostname()
		codes := scan.Codes(mask)
		path := report.DefaultPath(reportFile, hostname, codes, format)
		opts := report.Options{AllowElevatedWrite: allowElevatedWrite}
		if err := report.Write(path, []byte(output), opts); err != nil {
			if errors.Is(err, report.ErrElevatedWriteDenied) {
				return fmt.Errorf("%w; pass --allow-elevated-write to permit it", err)
			}
			return fmt.Errorf("failed to write report file: %w", err)
		}
		// Always confirm the written path; this is the only stdout output
		// when --report-file is set.
		fmt.Printf("[+] Report saved to: %s\n", path)
		return nil
	}

	fmt.Println(output)
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
		},
		Summary: formattedSummary{
			TotalChecks:      result.Summary.TotalChecks,
			PassedChecks:     result.Summary.PassedChecks,
			SkippedChecks:    result.Summary.SkippedChecks,
			TotalFindings:    result.Summary.TotalFindings,
			CriticalFindings: result.Summary.CriticalFindings,
			HighFindings:     result.Summary.HighFindings,
			MediumFindings:   result.Summary.MediumFindings,
			LowFindings:      result.Summary.LowFindings,
		},
		EnrichmentRequested: result.EnrichmentRequested,
	}

	if result.EnrichmentError != nil {
		formatted.EnrichmentError = result.EnrichmentError.Error()
	}
	if len(result.References.CWEs) > 0 {
		formatted.ReferenceCWEs = result.References.CWEs
	}
	formatted.ReferenceErrors = render.ReferenceErrorStrings(result.References.Errors)
	formatted.EnrichmentEntries = render.EnrichmentEntries(result.References, result.Enrichment)
	formatted.EnrichmentFailures = render.EnrichmentFailures(result.Enrichment)

	var shownFindings int
	for _, check := range result.Results {
		fc := formattedCheck{
			Name:        check.Name,
			Status:      check.Status,
			Description: check.Description,
			Duration:    check.Duration.String(),
			Details:     check.Details,
		}

		for _, finding := range check.Findings {
			sev := types.EffectiveSeverity(finding)
			if !types.MeetsMinSeverity(sev, minSeverity) {
				continue
			}
			shownFindings++
			fc.Findings = append(fc.Findings, formattedFinding{
				Title:       finding.Title,
				Severity:    sev,
				Description: finding.Description,
				Impact:      finding.Impact,
				Resolution:  finding.Resolution,
				References:  finding.References,
			})
		}

		formatted.Results = append(formatted.Results, fc)
	}

	if suppressed := formatted.Summary.TotalFindings - shownFindings; suppressed > 0 {
		formatted.FindingsSuppressed = suppressed
		formatted.MinSeverityApplied = strings.ToUpper(minSeverity)
	}

	return formatted
}

// formatText renders result as human-readable text, applying the active
// minSeverity filter to findings before output. Each check block includes
// a clean-pass confirmation when no findings meet the threshold, ensuring
// an empty findings block is never visually ambiguous. Verbose mode appends
// finding details, impact, resolution, and raw diagnostic output. Shared
// blocks (finding lines, the enrichment six-state block, suppression
// disclosure, summary) come from internal/render.
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
	var shownFindings int

	for _, checkResult := range result.Results {
		fmt.Fprintf(&builder, "Check: %s\n", checkResult.Name)
		fmt.Fprintf(&builder, "Status: %s\n", checkResult.Status)
		fmt.Fprintf(&builder, "Duration: %v\n", checkResult.Duration)

		var filteredFindings []types.Finding
		for _, finding := range checkResult.Findings {
			if types.MeetsMinSeverity(types.EffectiveSeverity(finding), minSeverity) {
				filteredFindings = append(filteredFindings, finding)
			}
		}
		shownFindings += len(filteredFindings)
		if len(filteredFindings) > 0 {
			hasFindings = true
			builder.WriteString("Findings:\n")
			for _, finding := range filteredFindings {
				if err := render.FindingLine(&builder, "", types.EffectiveSeverity(finding), finding.Title); err != nil {
					return "", err
				}
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
		} else {
			// Explicit clean pass confirmation so an empty findings block is
			// never mistaken for a silent checker failure.
			fmt.Fprintf(&builder, "Findings:\n%s No findings at or above %s severity\n",
				types.SymbolOK, strings.ToUpper(minSeverity))
		}

		if verbose && len(checkResult.Details) > 0 {
			builder.WriteString("Raw Diagnostic Output:\n")
			for _, detail := range checkResult.Details {
				fmt.Fprintf(&builder, "  %s\n", detail)
			}
		}

		builder.WriteString("\n")
	}

	if err := render.EnrichmentBlock(&builder, render.EnrichmentData{
		Requested:  result.EnrichmentRequested,
		Err:        result.EnrichmentError,
		References: result.References,
		Result:     result.Enrichment,
		Verbose:    verbose,
	}); err != nil {
		return "", err
	}

	if err := render.SuppressionNotice(&builder, result.Summary.TotalFindings-shownFindings,
		result.Summary.TotalFindings, minSeverity); err != nil {
		return "", err
	}
	if err := render.DetailedSummary(&builder, render.SummaryData{
		TotalChecks:   result.Summary.TotalChecks,
		PassedChecks:  result.Summary.PassedChecks,
		SkippedChecks: result.Summary.SkippedChecks,
		TotalFindings: result.Summary.TotalFindings,
		Shown:         shownFindings,
		Critical:      result.Summary.CriticalFindings,
		High:          result.Summary.HighFindings,
		Medium:        result.Summary.MediumFindings,
		Low:           result.Summary.LowFindings,
		Duration:      result.Duration,
	}); err != nil {
		return "", err
	}

	if !verbose && hasFindings {
		builder.WriteString("\nRun with -v for full finding details, impact analysis, and remediation guidance.\n")
	}

	return builder.String(), nil
}
