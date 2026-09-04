// cmd/commands/security/security.go

// Package security implements the owatch audit command, which runs the
// configuration security checks and renders their results as text, JSON, or
// YAML, optionally writing them to a generated report file.
package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
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

	// auditFormat is the effective output encoding, resolved once in
	// validateFlags from outputFormat and reportFile
	auditFormat report.Format
)

// SecurityCmd represents the security audit command. RunE is assigned at the
// declaration site from platformRunE, a symbol provided by exactly one
// build-tagged platform file per compiled target. A target missing its
// platform file fails to compile rather than shipping a nil RunE.
var SecurityCmd = &cobra.Command{
	Use:     "audit",
	Args:    cobra.NoArgs,
	Aliases: []string{"security_audit"},
	Short:   "Perform a security audit of the system",
	RunE:    platformRunE,
	Long: `Perform a comprehensive security audit of the system.
This command checks various security aspects including:
- SSH configuration
- Firewall rules
- User accounts
- File permissions

You can run all checks or specify individual checks to run.`,
	Example: `  # Run all security checks
  owatch audit

  # Show progress while checks run
  owatch audit -v

  # Run specific checks
  owatch audit --ssh
  owatch audit --fwall
  owatch audit --users
  owatch audit --fperms /path/to/file

  # Skip checks; skipped checks are still reported as SKIPPED
  owatch audit --skip-checks ssh,firewall

  # Set minimum severity level
  owatch audit --min-severity HIGH

  # Run checks and save report to file
  owatch audit -o json --report-file /path/to/reports`,
}

func init() {
	SecurityCmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output")
	SecurityCmd.Flags().StringVarP(&outputFormat, "output", "o", string(report.FormatText),
		fmt.Sprintf("Output format (%s)", report.FormatNames()))
	SecurityCmd.Flags().StringVar(&reportFile, "report-file", "",
		"Save audit report to the specified directory; filename is generated automatically")
	SecurityCmd.Flags().StringSliceVar(&skipChecks, "skip-checks", []string{},
		"Checks to skip (comma-separated: ssh, firewall, users, permissions)")
	SecurityCmd.Flags().StringVar(&minSeverity, "min-severity", types.SeverityLow,
		fmt.Sprintf("Minimum severity level to report (%s)", types.SeverityNames()))
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

	if mask == 0 {
		return 0, fmt.Errorf("all available checks were skipped; at least one must run")
	}

	return mask, nil
}

func validateFlags(cmd *cobra.Command) error {
	format, ok := report.ParseFormat(outputFormat)
	if !ok {
		return fmt.Errorf("invalid output format: %s (valid: %s)", outputFormat, report.FormatNames())
	}

	// Resolve the effective encoding at the boundary: an explicit -o wins,
	// otherwise a report file implies JSON and a bare run is text.
	switch {
	case cmd.Flags().Changed("output"):
		auditFormat = format
	case reportFile != "":
		auditFormat = report.FormatJSON
	default:
		auditFormat = report.FormatText
	}

	// Normalize once at the boundary so every downstream consumer sees the
	// canonical form; validation and storage happen in the same step.
	normalized, ok := types.NormalizeSeverity(minSeverity)
	if !ok {
		return fmt.Errorf("invalid min-severity: %s (valid: %s)", minSeverity, types.SeverityNames())
	}
	minSeverity = normalized

	if err := validateFilePermsPath(cmd); err != nil {
		return err
	}

	if cmd.Flags().Changed("report-file") {
		if err := report.ValidateDir(reportFile); err != nil {
			return fmt.Errorf("--report-file: %w", err)
		}
	}

	if _, err := scan.MaskFromNames(skipChecks, scan.CategoryCheck); err != nil {
		return err
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

// runAuditWithTimeout executes the audit synchronously under a deadline.
// Cancellation propagates through RunAudit into checker exec and filesystem
// work, so on timeout nothing owatch started is left running -- the prior
// goroutine-and-select pattern reported the timeout but abandoned the scan
// to keep executing against the host.
func runAuditWithTimeout(cmd *cobra.Command, mask scan.CheckMask) error {
	opts := audit.Options{
		Verbose:       verbose && reportFile == "",
		FilePermsPath: checkFilePerms,
		MinSeverity:   minSeverity,
		Checks:        scan.EnabledChecks(mask),
		Enrich:        enrich,
	}

	auditor := audit.NewSecurityAuditor(opts)

	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	result, err := auditor.RunAudit(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	if err := outputResults(result, mask); err != nil {
		return err
	}

	if ctx.Err() == context.DeadlineExceeded {
		if hint := scan.SkipHint(scan.CategoryCheck, result.IncompleteChecks); hint != "" {
			return fmt.Errorf("audit timeout after %v; results above are incomplete; rerun with a longer --timeout or %s",
				timeout, hint)
		}
		return fmt.Errorf("audit timeout after %v; results above are incomplete", timeout)
	}
	return nil
}

func outputResults(result *audit.Result, mask scan.CheckMask) error {
	if result == nil || len(result.Results) == 0 {
		return fmt.Errorf("audit produced no results")
	}

	var output string
	var err error

	switch auditFormat {
	case report.FormatJSON:
		output, err = formatJSON(result)
	case report.FormatYAML:
		output, err = formatYAML(result)
	default:
		output, err = formatText(result)
	}

	if err != nil {
		return fmt.Errorf("failed to format results: %w", err)
	}

	if reportFile != "" {
		hostname := report.ResolveHostname()
		codes := scan.Codes(mask)
		path := report.DefaultPath(reportFile, hostname, codes, auditFormat)
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
	formatted := result.View(minSeverity)
	jsonBytes, err := json.MarshalIndent(formatted, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(jsonBytes), nil
}

func formatYAML(result *audit.Result) (string, error) {
	formatted := result.View(minSeverity)
	yamlBytes, err := yaml.Marshal(formatted)
	if err != nil {
		return "", fmt.Errorf("failed to marshal YAML: %w", err)
	}
	return string(yamlBytes), nil
}

// formatText renders result as human-readable text: the system block via
// osfingerprint.WriteText, then the security section via audit.WriteText.
func formatText(result *audit.Result) (string, error) {
	var builder strings.Builder

	builder.WriteString("\nSecurity Audit Report\n")
	builder.WriteString("====================\n\n")
	if result.HostInfo != nil {
		if err := osfingerprint.WriteText(&builder, result.HostInfo); err != nil {
			return "", err
		}
		builder.WriteString("\n")
	}

	if err := audit.WriteText(&builder, result, minSeverity); err != nil {
		return "", err
	}

	return builder.String(), nil
}
