// cmd/commands/all.go
package cmd

import (
	"bytes"
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
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/scan"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/types"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

var (
	allVerbose            bool
	allEnrich             bool
	allAllowElevatedWrite bool
	allOutputFormat       string
	allReportFile         string
	allSkipModules        []string
	allSkipChecks         []string
	allTimeout            time.Duration
	allMinSeverity        string
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
  owatch all --skip-modules audit,software

  # Save report to directory in JSON format
  owatch all -o json --report-file /path/to/reports`,
	RunE: runAllScans,
}

func init() {
	allCmd.Flags().BoolVarP(&allVerbose, "verbose", "v", false,
		"Enable verbose output for all scans")
	allCmd.Flags().StringVarP(&allOutputFormat, "output", "o", "text",
		"Output format (json, yaml, text)")
	allCmd.Flags().StringVar(&allReportFile, "report-file", "",
		"Save complete report to the specified directory; filename is generated automatically")
	allCmd.Flags().StringSliceVar(&allSkipModules, "skip-modules", []string{},
		"Modules to skip (comma-separated: osinfo,software,audit)")
	allCmd.Flags().StringSliceVar(&allSkipChecks, "skip-checks", []string{},
		"Audit checks to skip (comma-separated: firewall, permissions, ssh, users)")
	allCmd.Flags().DurationVar(&allTimeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")
	allCmd.Flags().StringVar(&allMinSeverity, "min-severity", "LOW",
		"Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)")
	allCmd.Flags().BoolVarP(&allEnrich, "enrich", "e", false,
		"Query external sources to annotate findings with CVEs mapped to referenced CWEs")
	allCmd.Flags().BoolVar(&allAllowElevatedWrite, "allow-elevated-write", false,
		"Permit an elevated write outside the allowlisted directories")

	RootCmd.AddCommand(allCmd)
}

type (
	// ScanResult represents the combined results of all scans. It is the
	// authoritative result type for the all command and is not shared with
	// the audit subsystem.
	ScanResult struct {
		Timestamp     time.Time                    `json:"timestamp"`
		Duration      time.Duration                `json:"duration"`
		OSInfo        *osfingerprint.OSInfo        `json:"os_info,omitempty"`
		Software      []softwarelist.SoftwareEntry `json:"software,omitempty"`
		SecurityAudit *audit.Result                `json:"security_audit,omitempty"`
		Errors        []string                     `json:"errors,omitempty"`
	}

	// allResult is the typed serialization structure for all command JSON and
	// YAML output. It defines clean section boundaries between system, software,
	// and security data.
	allResult struct {
		Timestamp string                    `json:"timestamp" yaml:"timestamp"`
		Duration  string                    `json:"duration" yaml:"duration"`
		System    *osfingerprint.SystemView `json:"system,omitempty" yaml:"system,omitempty"`
		Software  *allSoftware              `json:"software,omitempty" yaml:"software,omitempty"`
		Security  *allSecurity              `json:"security,omitempty" yaml:"security,omitempty"`
		Errors    []string                  `json:"errors,omitempty" yaml:"errors,omitempty"`
	}

	// allSoftware carries the structured software inventory for all command output.
	allSoftware struct {
		Count    int                          `json:"count" yaml:"count"`
		Packages []softwarelist.SoftwareEntry `json:"packages" yaml:"packages"`
	}

	// allSecurity carries the security audit results for all command output.
	// FindingsSuppressed and MinSeverityApplied are populated only when
	// --min-severity filtered out at least one finding, so a consumer can tell
	// Findings is a partial view of Summary.TotalFindings without guessing.
	allSecurity struct {
		Summary             allSecuritySummary       `json:"summary" yaml:"summary"`
		FindingsSuppressed  int                      `json:"findings_suppressed,omitempty" yaml:"findings_suppressed,omitempty"`
		MinSeverityApplied  string                   `json:"min_severity_applied,omitempty" yaml:"min_severity_applied,omitempty"`
		EnrichmentRequested bool                     `json:"enrichment_requested,omitempty" yaml:"enrichment_requested,omitempty"`
		EnrichmentError     string                   `json:"enrichment_error,omitempty" yaml:"enrichment_error,omitempty"`
		ReferenceCWEs       []string                 `json:"reference_cwes,omitempty" yaml:"reference_cwes,omitempty"`
		ReferenceErrors     []string                 `json:"reference_errors,omitempty" yaml:"reference_errors,omitempty"`
		Entries             []enrichment.EntryView   `json:"enrichment_entries,omitempty" yaml:"enrichment_entries,omitempty"`
		FailureViews        []enrichment.FailureView `json:"enrichment_failures,omitempty" yaml:"enrichment_failures,omitempty"`
		Findings            []allFinding             `json:"findings,omitempty" yaml:"findings,omitempty"`
	}

	// allSecuritySummary carries per-severity finding counts for all command output.
	allSecuritySummary struct {
		TotalChecks   int `json:"total_checks" yaml:"total_checks"`
		PassedChecks  int `json:"passed_checks" yaml:"passed_checks"`
		TotalFindings int `json:"total_findings" yaml:"total_findings"`
		Critical      int `json:"critical" yaml:"critical"`
		High          int `json:"high" yaml:"high"`
		Medium        int `json:"medium" yaml:"medium"`
		Low           int `json:"low" yaml:"low"`
	}

	// allFinding carries a single security finding for all command output.
	allFinding struct {
		Check       string   `json:"check" yaml:"check"`
		Title       string   `json:"title" yaml:"title"`
		Severity    string   `json:"severity" yaml:"severity"`
		Categories  []string `json:"categories,omitempty" yaml:"categories,omitempty"`
		CWE         string   `json:"cwe,omitempty" yaml:"cwe,omitempty"`
		Description string   `json:"description,omitempty" yaml:"description,omitempty"`
		Impact      string   `json:"impact,omitempty" yaml:"impact,omitempty"`
		Resolution  string   `json:"resolution,omitempty" yaml:"resolution,omitempty"`
	}
)

// buildAllMask composes a CheckMask from the active module and security check flags
func buildAllMask() (scan.CheckMask, error) {
	var mask scan.CheckMask
	if !isModuleSkipped("osinfo") {
		mask |= scan.ModuleOS
	}
	if !isModuleSkipped("software") {
		mask |= scan.ModuleSoftware
	}
	if !isModuleSkipped("audit") {
		allChecks := scan.CheckSSH | scan.CheckFirewall | scan.CheckUsers | scan.CheckPerms
		if len(allSkipChecks) > 0 {
			skipMask, err := scan.MaskFromNames(allSkipChecks, scan.CategoryCheck)
			if err != nil {
				return 0, err
			}
			allChecks &^= skipMask
		}
		mask |= allChecks
	}
	return mask, nil
}

// toAllResult converts a ScanResult into the typed serialization structure
// for all command output.
func toAllResult(scan *ScanResult) allResult {
	out := allResult{
		Timestamp: scan.Timestamp.UTC().Format(time.RFC3339),
		Duration:  scan.Duration.String(),
		Errors:    scan.Errors,
	}

	// system info
	if scan.OSInfo != nil {
		view := scan.OSInfo.View()
		out.System = &view
	}

	// software inventory
	if len(scan.Software) > 0 {
		out.Software = &allSoftware{
			Count:    len(scan.Software),
			Packages: scan.Software,
		}
	}

	// security audit
	if scan.SecurityAudit != nil {
		sec := &allSecurity{
			Summary: allSecuritySummary{
				TotalChecks:   scan.SecurityAudit.Summary.TotalChecks,
				PassedChecks:  scan.SecurityAudit.Summary.PassedChecks,
				TotalFindings: scan.SecurityAudit.Summary.TotalFindings,
				Critical:      scan.SecurityAudit.Summary.CriticalFindings,
				High:          scan.SecurityAudit.Summary.HighFindings,
				Medium:        scan.SecurityAudit.Summary.MediumFindings,
				Low:           scan.SecurityAudit.Summary.LowFindings,
			},
		}
		for _, check := range scan.SecurityAudit.Results {
			for _, finding := range check.Findings {
				sev := types.EffectiveSeverity(finding)
				if !types.MeetsMinSeverity(sev, allMinSeverity) {
					continue
				}
				f := allFinding{
					Check:       check.Name,
					Title:       finding.Title,
					Severity:    sev,
					Categories:  finding.Categories,
					Description: finding.Description,
					Impact:      finding.Impact,
					Resolution:  finding.Resolution,
				}
				// extract first CWE reference if present
				for _, ref := range finding.References {
					if ref.Type == "CWE" {
						f.CWE = ref.Title
						break
					}
				}
				sec.Findings = append(sec.Findings, f)
			}
		}
		if suppressed := sec.Summary.TotalFindings - len(sec.Findings); suppressed > 0 {
			sec.FindingsSuppressed = suppressed
			sec.MinSeverityApplied = allMinSeverity
		}
		if scan.SecurityAudit.EnrichmentRequested {
			sec.EnrichmentRequested = true
			if scan.SecurityAudit.EnrichmentError != nil {
				sec.EnrichmentError = scan.SecurityAudit.EnrichmentError.Error()
			}
			if len(scan.SecurityAudit.References.CWEs) > 0 {
				sec.ReferenceCWEs = scan.SecurityAudit.References.CWEs
			}
			sec.ReferenceErrors = enrichment.ReferenceErrorStrings(scan.SecurityAudit.References.Errors)
			sec.Entries = enrichment.Entries(scan.SecurityAudit.References.CWEs, scan.SecurityAudit.Enrichment)
			sec.FailureViews = enrichment.Failures(scan.SecurityAudit.Enrichment)
		}
		out.Security = sec
	}

	return out
}

// validateSkipModules rejects any --skip-modules value that is not recognized
func validateSkipModules() error {
	if _, err := scan.MaskFromNames(allSkipModules, scan.CategoryModule); err != nil {
		return err
	}
	return nil
}

// validateAllFlags rejects invalid flag combinations for the all command.
func validateAllFlags(cmd *cobra.Command) error {
	switch allOutputFormat {
	case "json", "yaml", "text":
		// accepted
	default:
		return fmt.Errorf("invalid output format: %s (valid: json, yaml, or text)", allOutputFormat)
	}

	if cmd.Flags().Changed("report-file") {
		if err := validateAllReportDir(allReportFile); err != nil {
			return err
		}
	}

	if err := validateSkipModules(); err != nil {
		return err
	}

	if len(allSkipChecks) > 0 {
		if _, err := scan.MaskFromNames(allSkipChecks, scan.CategoryCheck); err != nil {
			return err
		}
	}

	// Normalize once at the boundary so every downstream consumer sees the
	// canonical form; validation and storage happen in the same step.
	allMinSeverity = strings.ToUpper(allMinSeverity)
	switch allMinSeverity {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		// accepted
	default:
		return fmt.Errorf("invalid min-severity: %s (valid: LOW, MEDIUM, HIGH, CRITICAL)", allMinSeverity)
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

	if err := validateAllFlags(cmd); err != nil {
		return err
	}

	if isModuleSkipped("osinfo") && isModuleSkipped("software") && isModuleSkipped("audit") {
		return fmt.Errorf("all modules have been skipped, at least one module must be run")
	}

	mask, err := buildAllMask()
	if err != nil {
		return err
	}

	// Verbose module headers print only when writing to an interactive
	// terminal without --report-file, preventing duplication when piping
	// or redirecting output. Computed once here as the single suppression
	// point for the whole run.
	verboseHeaders := allVerbose && render.StdoutIsTerminal() && allReportFile == ""

	// The whole scan runs synchronously under one deadline. Cancellation
	// reaches the audit's checkers and the software module's package-manager
	// invocations, so a timed-out scan leaves nothing running -- the prior
	// goroutine-and-select pattern reported the timeout but abandoned the
	// scan to keep executing against the host.
	ctx, cancel := context.WithTimeout(cmd.Context(), allTimeout)
	defer cancel()

	result := &ScanResult{
		Timestamp: startTime,
		Errors:    make([]string, 0),
	}

	if !isModuleSkipped("osinfo") {
		if osInfo, err := runOSFingerprint(verboseHeaders); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("OS fingerprint error: %v", err))
		} else {
			result.OSInfo = osInfo
		}
	}

	if !isModuleSkipped("software") {
		software, err := runSoftwareInventory(ctx, verboseHeaders)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Software inventory error: %v", err))
		} else {
			result.Software = software
		}
	}

	if !isModuleSkipped("audit") {
		if securityResult, err := runSecurityAuditModule(ctx, mask, result.OSInfo, verboseHeaders); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Security audit error: %v", err))
		} else {
			result.SecurityAudit = securityResult
		}
	}

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("scan timed out after %v", allTimeout)
	}

	result.Duration = time.Since(startTime)
	return outputResults(cmd, result, mask)
}

func runOSFingerprint(verboseHeaders bool) (*osfingerprint.OSInfo, error) {
	if verboseHeaders {
		fmt.Println("[*] OS Fingerprint Scan")
	}

	info, err := osfingerprint.GetOSFingerprint()
	if err != nil {
		return nil, err
	}

	if verboseHeaders {
		line := fmt.Sprintf("[*] OS: %s | Platform: %s | OS Version: %s",
			info.OS, info.Platform, info.PlatformVersion)
		if info.KernelVersion != "" && info.KernelVersion != info.PlatformVersion {
			line += fmt.Sprintf(" | Kernel: %s", info.KernelVersion)
		}
		fmt.Println(line)
	}

	return info, nil
}

// runSoftwareInventory enumerates installed software packages. Verbose module
// headers are gated behind verboseHeaders to prevent duplication when piping
// or redirecting output.
func runSoftwareInventory(ctx context.Context, verboseHeaders bool) ([]softwarelist.SoftwareEntry, error) {
	if verboseHeaders {
		fmt.Println("[*] Software Inventory Scan")
	}

	entries, err := softwarelist.GetInstalledSoftwareList(ctx)
	if err != nil {
		return nil, err
	}

	if verboseHeaders {
		fmt.Printf("[*] Found %d installed packages\n\n", len(entries))
		// Courtesy verbose listing only; a stdout write failure must not
		// discard the already-collected inventory.
		if err := softwarelist.WriteTable(os.Stdout, entries, false); err != nil {
			fmt.Fprintf(os.Stderr, "[!] WARNING: software listing write failed: %v\n", err)
		}
	}

	return entries, nil
}

func runSecurityAuditModule(ctx context.Context, mask scan.CheckMask, hostInfo *osfingerprint.OSInfo, verboseHeaders bool) (*audit.Result, error) {
	if verboseHeaders {
		fmt.Println("[*] Security Audit Scan")
	}

	opts := audit.Options{
		Verbose:        verboseHeaders,
		MinSeverity:    allMinSeverity,
		Enrich:         allEnrich,
		SpecificChecks: scan.EnabledChecks(mask),
		HostInfo:       hostInfo,
	}

	auditor := audit.NewSecurityAuditor(opts)
	return auditor.RunAudit(ctx)
}

func outputResults(cmd *cobra.Command, result *ScanResult, mask scan.CheckMask) error {
	format := "text"
	if cmd.Flags().Changed("output") {
		format = allOutputFormat
	} else if allReportFile != "" {
		format = "json"
	}

	var buf bytes.Buffer

	switch format {
	case "json":
		data := toAllResult(result)
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
	case "yaml":
		data := toAllResult(result)
		if err := yaml.NewEncoder(&buf).Encode(data); err != nil {
			return fmt.Errorf("failed to encode YAML: %w", err)
		}
	default:
		if err := renderAllText(&buf, result); err != nil {
			return fmt.Errorf("failed to render text output: %w", err)
		}
	}

	if allReportFile != "" {
		hostname := report.ResolveHostname()
		codes := scan.Codes(mask)
		path := report.DefaultPath(allReportFile, hostname, codes, format)
		wOpts := report.Options{AllowElevatedWrite: allAllowElevatedWrite}
		if err := report.Write(path, buf.Bytes(), wOpts); err != nil {
			if errors.Is(err, report.ErrElevatedWriteDenied) {
				return fmt.Errorf("%w; pass --allow-elevated-write to permit it", err)
			}
			return fmt.Errorf("failed to write report file: %w", err)
		}
		fmt.Printf("[+] Report saved to: %s\n", path)
		return nil
	}

	fmt.Print(buf.String())
	return nil
}

// renderAllText writes a concise human-readable summary of the scan result
// to w. This is the non-TUI text path; it will be replaced by the Bubbletea
// progress display when #35 lands. Shared blocks (finding lines, the
// enrichment six-state block, suppression disclosure, summary) come from
// internal/render; the first write error from any of them is returned.
func renderAllText(w *bytes.Buffer, result *ScanResult) error {
	fmt.Fprintf(w, "owatch all  --  %s\n\n", result.Timestamp.UTC().Format(time.RFC3339))

	// system
	if result.OSInfo != nil {
		fmt.Fprintf(w, "System\n")
		if err := osfingerprint.WriteText(w, result.OSInfo); err != nil {
			return err
		}
	}

	// software
	if len(result.Software) > 0 {
		fmt.Fprintf(w, "Software: %d packages installed\n", len(result.Software))
	}

	fmt.Fprintln(w)

	// security findings
	if result.SecurityAudit != nil {
		fmt.Fprintf(w, "Security Audit\n")
		s := result.SecurityAudit.Summary
		var shown int
		for _, check := range result.SecurityAudit.Results {
			for _, finding := range check.Findings {
				sev := types.EffectiveSeverity(finding)
				if !types.MeetsMinSeverity(sev, allMinSeverity) {
					continue
				}
				shown++
				if err := render.FindingLine(w, "  ", sev, finding.Title); err != nil {
					return err
				}
			}
		}
		fmt.Fprintln(w)

		if err := enrichment.Block(w, enrichment.Data{
			Requested:  result.SecurityAudit.EnrichmentRequested,
			Err:        result.SecurityAudit.EnrichmentError,
			References: result.SecurityAudit.References,
			Result:     result.SecurityAudit.Enrichment,
			Verbose:    allVerbose,
		}); err != nil {
			return err
		}

		if err := render.SuppressionNotice(w, s.TotalFindings-shown, s.TotalFindings, allMinSeverity); err != nil {
			return err
		}
		if err := render.CompactSummary(w, render.SummaryData{
			TotalChecks:   s.TotalChecks,
			PassedChecks:  s.PassedChecks,
			TotalFindings: s.TotalFindings,
			Shown:         shown,
			Duration:      result.Duration.Round(time.Millisecond),
		}); err != nil {
			return err
		}
	}
	return nil
}

func isModuleSkipped(module string) bool {
	if len(allSkipModules) == 0 {
		return false
	}

	for _, skip := range allSkipModules {
		if strings.EqualFold(skip, module) {
			return true
		}
	}
	return false
}
