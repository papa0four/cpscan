// cmd/commands/all.go
package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/scan"
	"github.com/papa0four/orkowatch/internal/security/audit"
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
		"Output format (json, yaml, text, csv)")
	allCmd.Flags().StringVar(&allReportFile, "report-file", "",
		"Save complete report to the specified directory; filename is generated automatically")
	allCmd.Flags().StringSliceVar(&allSkipModules, "skip-modules", []string{},
		"Modules to skip (comma-separated: osinfo,software,audit)")
	allCmd.Flags().StringSliceVar(&allSkipChecks, "skip-checks", []string{},
		"Audit checks to skip (comma-separated: firewall, permissions, ssh, users)")
	allCmd.Flags().DurationVar(&allTimeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")
	allCmd.Flags().StringVar(&allMinSeverity, "min-severity", "LOW",
		"Minimum severity level to report (LOW< MEDIUM, HIGH, CRITICAL)")
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
		Timestamp string        `json:"timestamp" yaml:"timestamp"`
		Duration  string        `json:"duration" yaml:"duration"`
		System    allSystemInfo `json:"system" yaml:"system"`
		Software  *allSoftware  `json:"software,omitempty" yaml:"software,omitempty"`
		Security  *allSecurity  `json:"security,omitempty" yaml:"security,omitempty"`
		Errors    []string      `json:"errors,omitempty" yaml:"errors,omitempty"`
	}

	// allSystemInfo carries host identity fields for all command output.
	allSystemInfo struct {
		OS            string `json:"os" yaml:"os"`
		Hostname      string `json:"hostname" yaml:"hostname"`
		KernelVersion string `json:"kernel_version" yaml:"kernel_version"`
		Architecture  string `json:"architecture" yaml:"architecture"`
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
		Summary             allSecuritySummary     `json:"summary" yaml:"summary"`
		FindingsSuppressed  int                    `json:"findings_suppressed,omitempty" yaml:"findings_suppressed,omitempty"`
		MinSeverityApplied  string                 `json:"min_severity_applied,omitempty" yaml:"min_severity_applied,omitempty"`
		EnrichmentRequested bool                   `json:"enrichment_requested,omitempty" yaml:"enrichment_requested,omitempty"`
		EnrichmentError     string                 `json:"enrichment_error,omitempty" yaml:"enrichment_error,omitempty"`
		ReferenceCWEs       []string               `json:"reference_cwes,omitempty" yaml:"reference_cwes,omitempty"`
		ReferenceErrors     []string               `json:"reference_errors,omitempty" yaml:"reference_errors,omitempty"`
		EnrichmentEntries   []allEnrichmentEntry   `json:"enrichment_entries,omitempty" yaml:"enrichment_entries,omitempty"`
		EnrichmentFailures  []allEnrichmentFailure `json:"enrichment_failures,omitempty" yaml:"enrichment_failures,omitempty"`
		Findings            []allFinding           `json:"findings,omitempty" yaml:"findings,omitempty"`
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
		Check       string `json:"check" yaml:"check"`
		Title       string `json:"title" yaml:"title"`
		Severity    string `json:"severity" yaml:"severity"`
		CWE         string `json:"cwe,omitempty" yaml:"cwe,omitempty"`
		Description string `json:"description,omitempty" yaml:"description,omitempty"`
		Impact      string `json:"impact,omitempty" yaml:"impact,omitempty"`
		Resolution  string `json:"resolution,omitempty" yaml:"resolution,omitempty"`
	}

	// allEnrichmentMatch is the typed representation of a single CVE match for
	// all command output.
	allEnrichmentMatch struct {
		CVEID          string  `json:"cve_id" yaml:"cve_id"`
		Source         string  `json:"source" yaml:"source"`
		CVSSBaseScore  float64 `json:"cvss_base_score" yaml:"cvss_base_score"`
		CVSSSeverity   string  `json:"cvss_severity" yaml:"cvss_severity"`
		Description    string  `json:"description,omitempty" yaml:"description,omitempty"`
		KnownExploited bool    `json:"known_exploited" yaml:"known_exploited"`
		PatchAvailable bool    `json:"patch_available" yaml:"patch_available"`
	}

	// allEnrichmentEntry is the typed representation of a single CWE's
	// enrichment result for all command output.
	allEnrichmentEntry struct {
		CWEID        string               `json:"cwe_id" yaml:"cwe_id"`
		WeaknessName string               `json:"weakness_name,omitempty" yaml:"weakness_name,omitempty"`
		NoMatches    bool                 `json:"no_matches" yaml:"no_matches"`
		Matches      []allEnrichmentMatch `json:"matches,omitempty" yaml:"matches,omitempty"`
	}

	// allEnrichmentFailure is the typed representation of a failed per-CWE
	// enrichment lookup for all command output.
	allEnrichmentFailure struct {
		CWEID     string `json:"cwe_id" yaml:"cwe_id"`
		Source    string `json:"source" yaml:"source"`
		Reason    string `json:"reason" yaml:"reason"`
		Retryable bool   `json:"retryable" yaml:"retryable"`
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

	// system info -- prefer OS fingerprint data, fall back to runtime
	if scan.OSInfo != nil {
		out.System = allSystemInfo{
			OS:            scan.OSInfo.Platform,
			Hostname:      scan.OSInfo.Hostname,
			KernelVersion: scan.OSInfo.KernelVersion,
			Architecture:  runtime.GOARCH,
		}
	} else {
		hostname, _ := os.Hostname() //nolint:errcheck // fallback to empty string on error
		out.System = allSystemInfo{
			OS:           runtime.GOOS,
			Hostname:     hostname,
			Architecture: runtime.GOARCH,
		}
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
				sev := effectiveSeverity(finding)
				if !allMeetsMinSeverity(finding.Severity, allMinSeverity) {
					continue
				}
				f := allFinding{
					Check:       check.Name,
					Title:       finding.Title,
					Severity:    sev,
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
			sec.MinSeverityApplied = strings.ToUpper(allMinSeverity)
		}
		if scan.SecurityAudit.EnrichmentRequested {
			sec.EnrichmentRequested = true
			if scan.SecurityAudit.EnrichmentError != nil {
				sec.EnrichmentError = scan.SecurityAudit.EnrichmentError.Error()
			}
			if len(scan.SecurityAudit.References.CWEs) > 0 {
				sec.ReferenceCWEs = scan.SecurityAudit.References.CWEs
			}
			sec.ReferenceErrors = allFormatReferenceErrors(scan.SecurityAudit.References.Errors)
			sec.EnrichmentEntries = buildAllEnrichmentEntries(scan.SecurityAudit)
			sec.EnrichmentFailures = buildAllEnrichmentFailures(scan.SecurityAudit)
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

	if err := validateSkipModules(); err != nil {
		return err
	}

	if len(allSkipChecks) > 0 {
		if _, err := scan.MaskFromNames(allSkipChecks, scan.CategoryCheck); err != nil {
			return err
		}
	}

	switch strings.ToUpper(allMinSeverity) {
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

	results := make(chan *ScanResult, 1)

	go func() {
		result := &ScanResult{
			Timestamp: startTime,
			Errors:    make([]string, 0),
		}

		if !isModuleSkipped("osinfo") {
			if osInfo, err := runOSFingerprint(); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("OS fingerprint error: %v", err))
			} else {
				result.OSInfo = osInfo
			}
		}

		if !isModuleSkipped("software") {
			software, err := runSoftwareInventory()
			if err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("Software inventory error: %v", err))
			} else {
				result.Software = software
			}
		}

		if !isModuleSkipped("audit") {
			if securityResult, err := runSecurityAuditModule(mask); err != nil {
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
		return outputResults(cmd, result, mask)
	case <-time.After(allTimeout):
		return fmt.Errorf("scan timed out after %v", allTimeout)
	}
}

func runOSFingerprint() (*osfingerprint.OSInfo, error) {
	if allVerbose && isTerminal() && allReportFile == "" {
		fmt.Println("[*] OS Fingerprint Scan")
	}

	info, err := osfingerprint.GetOSFingerprint()
	if err != nil {
		return nil, err
	}

	if allVerbose && isTerminal() && allReportFile == "" {
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
// headers are gated behind isTerminal() to prevent duplication when piping
// or redirecting output.
func runSoftwareInventory() ([]softwarelist.SoftwareEntry, error) {
	if allVerbose && isTerminal() && allReportFile == "" {
		fmt.Println("[*] Software Inventory Scan")
	}

	entries, err := softwarelist.GetInstalledSoftwareList()
	if err != nil {
		return nil, err
	}

	if allVerbose && isTerminal() && allReportFile == "" {
		fmt.Printf("[*] Found %d installed packages\n\n", len(entries))
		for _, e := range entries {
			fmt.Printf("%-60s %s\n", e.Name, e.Version)
		}
	}

	return entries, nil
}

func runSecurityAuditModule(mask scan.CheckMask) (*audit.Result, error) {
	if allVerbose && isTerminal() && allReportFile == "" {
		fmt.Println("[*] Security Audit Scan")
	}

	opts := audit.Options{
		Verbose:        allVerbose && isTerminal() && allReportFile == "",
		MinSeverity:    allMinSeverity,
		Timeout:        allTimeout,
		Enrich:         allEnrich,
		SpecificChecks: scan.EnabledChecks(mask),
	}

	auditor := audit.NewSecurityAuditor(opts)
	return auditor.RunAudit()
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
	case "csv":
		return fmt.Errorf("csv output format is not yet implemented")
	default:
		renderAllText(&buf, result)
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
// progress display when #35 lands.
func renderAllText(w *bytes.Buffer, result *ScanResult) {
	fmt.Fprintf(w, "owatch all  --  %s\n\n", result.Timestamp.UTC().Format(time.RFC3339))

	// system
	if result.OSInfo != nil {
		fmt.Fprintf(w, "System\n")
		fmt.Fprintf(w, "  OS:       %s\n", result.OSInfo.Platform)
		fmt.Fprintf(w, "  Host:     %s\n", result.OSInfo.Hostname)
		fmt.Fprintf(w, "  Kernel:   %s\n", result.OSInfo.KernelVersion)
	}

	// software
	if len(result.Software) > 0 {
		fmt.Fprintf(w, "  Software: %d packages installed\n", len(result.Software))
	}

	fmt.Fprintln(w)

	// security findings
	if result.SecurityAudit != nil {
		fmt.Fprintf(w, "Security Audit\n")
		s := result.SecurityAudit.Summary
		var shown int
		for _, check := range result.SecurityAudit.Results {
			for _, finding := range check.Findings {
				sev := effectiveSeverity(finding)
				if !allMeetsMinSeverity(sev, allMinSeverity) {
					continue
				}
				shown++
				symbol, _ := types.SeverityFormat(sev)
				fmt.Fprintf(w, "  %s %-8s  %s\n", symbol, sev, finding.Title)
			}
		}
		fmt.Fprintln(w)

		renderAllEnrichmentBlock(w, result.SecurityAudit)

		suppressed := s.TotalFindings - shown
		if suppressed > 0 {
			fmt.Fprintf(w, "%d of %d findings suppressed by --min-severity %s. "+
				"Rerun with a lower threshold or without --min-severity to see all findings.\n\n",
				suppressed, s.TotalFindings, strings.ToUpper(allMinSeverity))
		}
		if suppressed > 0 {
			fmt.Fprintf(w, "Summary: %d checks  %d passed  %d findings total  %d present  %d suppressed  %s\n",
				s.TotalChecks, s.PassedChecks, s.TotalFindings, shown, suppressed, result.Duration.Round(time.Millisecond))
		} else {
			fmt.Fprintf(w, "Summary: %d checks  %d passed  %d findings  %s\n",
				s.TotalChecks, s.PassedChecks, s.TotalFindings, result.Duration.Round(time.Millisecond))
		}
	}
}

// buildAllEnrichmentEntries converts enrichment successes into typed
// structs for all command output, in the same CWE order as
// result.References.CWEs so output order is stable across runs.
func buildAllEnrichmentEntries(result *audit.Result) []allEnrichmentEntry {
	if result.Enrichment == nil {
		return nil
	}
	out := make([]allEnrichmentEntry, 0, len(result.References.CWEs))
	for _, cwe := range result.References.CWEs {
		entry, ok := result.Enrichment.Successes[cwe]
		if !ok {
			continue
		}
		e := allEnrichmentEntry{
			CWEID:        cwe,
			WeaknessName: entry.WeaknessName,
			NoMatches:    string(entry.Status) == "NO_MATCHES" || len(entry.MatchedCVEs) == 0,
		}
		for _, match := range entry.MatchedCVEs {
			e.Matches = append(e.Matches, allEnrichmentMatch{
				CVEID:          match.CVEID,
				Source:         string(match.Source),
				CVSSBaseScore:  match.CVSSBaseScore,
				CVSSSeverity:   match.CVSSSeverity,
				Description:    match.Description,
				KnownExploited: match.KnownExploited,
				PatchAvailable: match.PatchAvailable,
			})
		}
		out = append(out, e)
	}
	return out
}

// buildAllEnrichmentFailures converts enrichment failures into typed
// structs for all command output.
func buildAllEnrichmentFailures(result *audit.Result) []allEnrichmentFailure {
	if result.Enrichment == nil || len(result.Enrichment.Failures) == 0 {
		return nil
	}
	out := make([]allEnrichmentFailure, 0, len(result.Enrichment.Failures))
	for cwe, failure := range result.Enrichment.Failures {
		out = append(out, allEnrichmentFailure{
			CWEID:     cwe,
			Source:    string(failure.Source),
			Reason:    failure.Reason,
			Retryable: failure.Retryable,
		})
	}
	return out
}

// allFormatReferenceErrors converts reference parsing errors into strings
// for all command output.
func allFormatReferenceErrors(errs []error) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}

// renderAllEnrichmentBlock writes the six-state enrichment rendering for
// all command text output, mirroring renderEnrichmentBlock in
// cmd/commands/security/security.go. Kept separate since all.go owns its
// own serialization path independent of the audit formatter.
func renderAllEnrichmentBlock(w *bytes.Buffer, result *audit.Result) {
	if !result.EnrichmentRequested {
		return
	}

	fmt.Fprintf(w, "Enrichment:\n")

	if result.EnrichmentError != nil {
		fmt.Fprintf(w, "  Unavailable: %v\n\n", result.EnrichmentError)
		renderAllReferenceErrors(w, result.References)
		return
	}

	if len(result.References.CWEs) == 0 {
		fmt.Fprintf(w, "  No CWE references found in current findings.\n\n")
		renderAllReferenceErrors(w, result.References)
		return
	}

	if result.Enrichment == nil {
		fmt.Fprintf(w, "  No enrichment data returned.\n\n")
		renderAllReferenceErrors(w, result.References)
		return
	}

	rendered := 0
	for _, cwe := range result.References.CWEs {
		entry, ok := result.Enrichment.Successes[cwe]
		if !ok {
			continue
		}
		rendered++
		fmt.Fprintf(w, "  %s", cwe)
		if entry.WeaknessName != "" {
			fmt.Fprintf(w, " - %s", entry.WeaknessName)
		}
		fmt.Fprintln(w)

		if string(entry.Status) == "NO_MATCHES" || len(entry.MatchedCVEs) == 0 {
			fmt.Fprintf(w, "    No CVE matches in queried sources.\n")
			continue
		}

		for _, match := range entry.MatchedCVEs {
			symbol, label := types.SeverityFormat(match.CVSSSeverity)
			fmt.Fprintf(w, "    %s %s  %s (%.1f) [%s]\n",
				symbol, label, match.CVEID, match.CVSSBaseScore, match.Source)
			if allVerbose {
				if match.Description != "" {
					fmt.Fprintf(w, "      Description: %s\n", match.Description)
				}
				if match.KnownExploited {
					fmt.Fprintf(w, "      Known Exploited: yes\n")
				}
				if match.PatchAvailable {
					fmt.Fprintf(w, "      Patch Available: yes\n")
				}
			}
		}
	}

	if rendered == 0 {
		fmt.Fprintf(w, "  No enrichment data returned.\n")
	}

	if len(result.Enrichment.Failures) > 0 {
		fmt.Fprintf(w, "\n  Failed enrichments:\n")
		for cwe, failure := range result.Enrichment.Failures {
			fmt.Fprintf(w, "    %s [%s]: %s", cwe, failure.Source, failure.Reason)
			if failure.Retryable {
				fmt.Fprintf(w, " (retryable)")
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w)
	renderAllReferenceErrors(w, result.References)
}

// renderAllReferenceErrors writes reference parsing errors for all command
// text output, mirroring renderReferenceErrors in security.go.
func renderAllReferenceErrors(w *bytes.Buffer, refs types.ReferenceExtraction) {
	if len(refs.Errors) == 0 {
		return
	}
	fmt.Fprintf(w, "  Reference parsing errors:\n")
	for _, err := range refs.Errors {
		fmt.Fprintf(w, "    %v\n", err)
	}
	fmt.Fprintln(w)
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

// isTerminal checks if the output is going to a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// allSeverityLevel returns the numeric rank of a severity string for
// threshold comparisons. Unknown values return -1 so they are never
// silently dropped. Mirrors security.severityLevel; kept local since all.go
// owns its own serialization path independent of the audit formatter.
func allSeverityLevel(s string) int {
	switch strings.ToUpper(s) {
	case types.SeverityLow:
		return 0
	case types.SeverityMedium:
		return 1
	case types.SeverityHigh:
		return 2
	case types.SeverityCritical:
		return 3
	default:
		return -1
	}
}

// allMeetsMinSeverity reports whether findingSeverity is at or above the
// min threshold. Unrecognized severity values pass through so findings are
// never silently dropped.
func allMeetsMinSeverity(findingSeverity, min string) bool {
	fl := allSeverityLevel(findingSeverity)
	ml := allSeverityLevel(min)
	if fl < 0 || ml < 0 {
		return true
	}
	return fl >= ml
}

// effectiveSeverity returns the severity value used for filtering and
// display. It currently always returns the finding's static registry-
// assigned severity. Once per-finding CVE/CVSS enrichment lands, this is
// the single point where a live CVSS-derived severity would override the
// static value. Callers should go through this rather than reading
// finding.Severity directly, so severity sourcing only has to change here.
func effectiveSeverity(finding types.Finding) string {
	return finding.Severity
}
