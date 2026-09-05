// cmd/commands/all.go

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/scan"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/types"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

type (
	//allCmd holds one invocation's flag state. Cobra binds flags directly
	// into these fields, so the values a run reads are the values that run
	// parsed.
	allCmd struct {
		verbose            bool
		enrich             bool
		allowElevatedWrite bool
		outputFormat       string
		reportFile         string
		skipModules        []string
		skipChecks         []string
		timeout            time.Duration
		minSeverity        string

		// format is the effective output encoding, resolved once in
		// validateAllFlags from allOutputFormat and allReportFile
		format report.Format
	}

	// ScanResult represents the combined results of all scans. It is the
	// authoritative result type for the all command and is not shared with
	// the audit subsystem.
	ScanResult struct {
		Timestamp     time.Time
		Duration      time.Duration
		Modules       []moduleRun
		OSInfo        *osfingerprint.OSInfo
		Software      []softwarelist.SoftwareEntry
		SecurityAudit *audit.Result
		Errors        []string
	}

	// moduleRun records one module's outcome: COMPLETED, SKIPPED, or ERROR.
	// A skipped or errored module keeps its row rather than vanishing from
	// the run record.
	moduleRun struct {
		Name   string `json:"name" yaml:"name"`
		Status string `json:"status" yaml:"status"`
	}

	// allResult is the typed serialization structure for all command JSON and
	// YAML output. It defines clean section boundaries between system, software,
	// and security data.
	allResult struct {
		Timestamp string                     `json:"timestamp" yaml:"timestamp"`
		Duration  string                     `json:"duration" yaml:"duration"`
		Modules   []moduleRun                `json:"modules" yaml:"modules"`
		System    *osfingerprint.SystemView  `json:"system,omitempty" yaml:"system,omitempty"`
		Software  *softwarelist.SoftwareView `json:"software,omitempty" yaml:"software,omitempty"`
		Security  *audit.View                `json:"security,omitempty" yaml:"security,omitempty"`
		Errors    []string                   `json:"errors,omitempty" yaml:"errors,omitempty"`
	}
)

// newAllCmd returns the command that combines all scanning modules
func newAllCmd() *cobra.Command {
	c := &allCmd{}

	cmd := &cobra.Command{
		Use:   "all",
		Args:  cobra.NoArgs,
		Short: "Run all available scans",
		RunE:  c.runAllScans,
		Long: `The all command performs a comprehensive system scan including:
- OS fingerprinting
- Software inventory
- Security audit
- System configuration analysis

Results can be output in various formats and saved to a file.`,
		Example: `  # Run all scans with default settings
  owatch all

  # Show module and check progress while scanning
  owatch all -v

  # Skip modules; skipped modules are still reported
  owatch all --skip-modules audit,software

  # Skip individual audit checks within the audit module
  owatch all --skip-checks firewall,permissions

  # Save report to directory in JSON format
  owatch all -o json --report-file /path/to/reports`,
	}

	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v", false,
		"Enable verbose output for all scans")
	cmd.Flags().StringVarP(&c.outputFormat, "output", "o", string(report.FormatText),
		fmt.Sprintf("Output format (%s)", report.FormatNames()))
	cmd.Flags().StringVar(&c.reportFile, "report-file", "",
		"Save complete report to the specified directory; filename is generated automatically")
	cmd.Flags().StringSliceVar(&c.skipModules, "skip-modules", []string{},
		"Modules to skip (comma-separated: osinfo,software,audit)")
	cmd.Flags().StringSliceVar(&c.skipChecks, "skip-checks", []string{},
		"Audit checks to skip (comma-separated: firewall, permissions, ssh, users)")
	cmd.Flags().DurationVar(&c.timeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")
	cmd.Flags().StringVar(&c.minSeverity, "min-severity", types.SeverityLow,
		fmt.Sprintf("Minimum severity level to report (%s)", types.SeverityNames()))
	cmd.Flags().BoolVarP(&c.enrich, "enrich", "e", false,
		"Query external sources to annotate findings with CVEs mapped to referenced CWEs")
	cmd.Flags().BoolVar(&c.allowElevatedWrite, "allow-elevated-write", false,
		"Permit an elevated write outside the allowlisted directories")

	return cmd
}

// buildAllMask composes a CheckMask from the active module and security check flags
func (c *allCmd) buildAllMask() (scan.CheckMask, error) {
	var mask scan.CheckMask
	if !c.isModuleSkipped("osinfo") {
		mask |= scan.ModuleOS
	}
	if !c.isModuleSkipped("software") {
		mask |= scan.ModuleSoftware
	}
	if !c.isModuleSkipped("audit") {
		allChecks := scan.CheckSSH | scan.CheckFirewall | scan.CheckUsers | scan.CheckPerms
		if len(c.skipChecks) > 0 {
			skipMask, err := scan.MaskFromNames(c.skipChecks, scan.CategoryCheck)
			if err != nil {
				return 0, err
			}
			allChecks &^= skipMask
		}
		if allChecks == 0 {
			return 0, fmt.Errorf("all audit checks were skipped; use --skip-modules audit to skip the audit module")
		}
		mask |= allChecks
	}
	return mask, nil
}

// toAllResult converts a ScanResult into the typed serialization structure
// for all command output.
func (c *allCmd) toAllResult(scan *ScanResult) allResult {
	out := allResult{
		Timestamp: scan.Timestamp.UTC().Format(time.RFC3339),
		Duration:  scan.Duration.String(),
		Modules:   scan.Modules,
		Errors:    scan.Errors,
	}

	// system info
	if scan.OSInfo != nil {
		view := scan.OSInfo.View()
		out.System = &view
	}

	// software inventory
	if len(scan.Software) > 0 {
		view := softwarelist.View(scan.Software)
		out.Software = &view
	}

	// security audit
	if scan.SecurityAudit != nil {
		view := scan.SecurityAudit.View(c.minSeverity)
		if out.System != nil {
			// avoid duplicating hist identity alread in out.System
			view.SystemInfo = nil
		}
		out.Security = &view
	}

	return out
}

// validateSkipModules rejects any --skip-modules value that is not recognized
func (c *allCmd) validateSkipModules() error {
	if _, err := scan.MaskFromNames(c.skipModules, scan.CategoryModule); err != nil {
		return err
	}
	return nil
}

// validateAllFlags rejects invalid flag combinations for the all command.
func (c *allCmd) validateAllFlags(cmd *cobra.Command) error {
	format, ok := report.ParseFormat(c.outputFormat)
	if !ok {
		return fmt.Errorf("invalid output format: %s (valid: %s)", c.outputFormat, report.FormatNames())
	}

	// Resolve the effective encoding at the boundary: an explicit -o wins,
	// otherwise a report file implies JSON and a bare run is text.
	switch {
	case cmd.Flags().Changed("output"):
		c.format = format
	case c.reportFile != "":
		c.format = report.FormatJSON
	default:
		c.format = report.FormatText
	}

	if cmd.Flags().Changed("report-file") {
		if err := report.ValidateDir(c.reportFile); err != nil {
			return fmt.Errorf("--report-file: %w", err)
		}
	}

	if err := c.validateSkipModules(); err != nil {
		return err
	}

	if len(c.skipChecks) > 0 {
		if _, err := scan.MaskFromNames(c.skipChecks, scan.CategoryCheck); err != nil {
			return err
		}
	}

	// Normalize once at the boundary so every downstream consumer sees the
	// canonical form; validation and storage happen in the same step.
	normalized, ok := types.NormalizeSeverity(c.minSeverity)
	if !ok {
		return fmt.Errorf("invalid min-severity: %s (valid: %s)", c.minSeverity, types.SeverityNames())
	}
	c.minSeverity = normalized

	return nil
}

func (c *allCmd) runAllScans(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	if err := c.validateAllFlags(cmd); err != nil {
		return err
	}

	if c.isModuleSkipped("osinfo") && c.isModuleSkipped("software") && c.isModuleSkipped("audit") {
		return fmt.Errorf("all modules have been skipped, at least one module must be run")
	}

	mask, err := c.buildAllMask()
	if err != nil {
		return err
	}

	// Verbose module headers print only when writing to an interactive
	// terminal without --report-file, preventing duplication when piping
	// or redirecting output. Computed once here as the single suppression
	// point for the whole run.
	verboseHeaders := c.verbose && render.StdoutIsTerminal() && c.reportFile == ""

	// The whole scan runs synchronously under one deadline. Cancellation
	// reaches the audit's checkers and the software module's package-manager
	// invocations, so a timed-out scan leaves nothing running -- the prior
	// goroutine-and-select pattern reported the timeout but abandoned the
	// scan to keep executing against the host.
	ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
	defer cancel()

	result := &ScanResult{
		Timestamp: startTime,
		Errors:    make([]string, 0),
	}

	if c.isModuleSkipped("osinfo") {
		result.Modules = append(result.Modules, moduleRun{Name: "osinfo", Status: types.StatusSkipped})
	} else if osInfo, err := runOSFingerprint(verboseHeaders); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("OS fingerprint error: %v", err))
		result.Modules = append(result.Modules, moduleRun{Name: "osinfo", Status: types.StatusError})
	} else {
		result.OSInfo = osInfo
		result.Modules = append(result.Modules, moduleRun{Name: "osinfo", Status: types.StatusCompleted})
	}

	if c.isModuleSkipped("software") {
		result.Modules = append(result.Modules, moduleRun{Name: "software", Status: types.StatusSkipped})
	} else if software, err := runSoftwareInventory(ctx, verboseHeaders); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Software inventory error: %v", err))
		result.Modules = append(result.Modules, moduleRun{Name: "software", Status: types.StatusError})
	} else {
		result.Software = software
		result.Modules = append(result.Modules, moduleRun{Name: "software", Status: types.StatusCompleted})
	}

	if c.isModuleSkipped("audit") {
		result.Modules = append(result.Modules, moduleRun{Name: "audit", Status: types.StatusSkipped})
	} else if securityResult, err := c.runSecurityAuditModule(ctx, mask, result.OSInfo, verboseHeaders); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Security audit error: %v", err))
		result.Modules = append(result.Modules, moduleRun{Name: "audit", Status: types.StatusError})
	} else {
		result.SecurityAudit = securityResult
		result.Modules = append(result.Modules, moduleRun{Name: "audit", Status: types.StatusCompleted})
	}

	result.Duration = time.Since(startTime)
	if err := c.outputResults(result, mask); err != nil {
		return err
	}

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("scan timed out after %v; %s", c.timeout, incompleteDetail(result))
	}
	return nil
}

func runOSFingerprint(verboseHeaders bool) (*osfingerprint.OSInfo, error) {
	if verboseHeaders {
		fmt.Println("[*] OS Fingerprint Scan")
	}

	return osfingerprint.GetOSFingerprint()
}

// incompleteDetail names the modules and checks that did not finish, so a
// timed-out run tells the operator what to exclude or allow more time for.
func incompleteDetail(result *ScanResult) string {
	var parts []string

	var modules []string
	for _, m := range result.Modules {
		if m.Status == types.StatusError {
			modules = append(modules, m.Name)
		}
	}
	if hint := scan.SkipHint(scan.CategoryModule, modules); hint != "" {
		parts = append(parts, hint)
	}

	if result.SecurityAudit != nil {
		if hint := scan.SkipHint(scan.CategoryCheck, result.SecurityAudit.IncompleteChecks); hint != "" {
			parts = append(parts, hint)
		}
	}

	if len(parts) == 0 {
		return "results above are incomplete"
	}
	return "results above are incomplete; rerun with a longer --timeout or " + strings.Join(parts, " ")
}

// runSoftwareInventory enumerates installed software packages. verboseHeaders
// gates only the progress announcement; the inventory itself always renders
// in renderAllText, matching structured output.
func runSoftwareInventory(ctx context.Context, verboseHeaders bool) ([]softwarelist.SoftwareEntry, error) {
	if verboseHeaders {
		fmt.Println("[*] Software Inventory Scan")
	}

	return softwarelist.GetInstalledSoftwareList(ctx)
}

func (c *allCmd) runSecurityAuditModule(ctx context.Context, mask scan.CheckMask, hostInfo *osfingerprint.OSInfo, verboseHeaders bool) (*audit.Result, error) {
	if verboseHeaders {
		fmt.Println("[*] Security Audit Scan")
	}

	opts := audit.Options{
		Verbose:     verboseHeaders,
		MinSeverity: c.minSeverity,
		Enrich:      c.enrich,
		Checks:      scan.EnabledChecks(mask),
		HostInfo:    hostInfo,
	}

	auditor := audit.NewSecurityAuditor(opts)
	return auditor.RunAudit(ctx)
}

func (c *allCmd) outputResults(result *ScanResult, mask scan.CheckMask) error {
	var buf bytes.Buffer

	switch c.format {
	case report.FormatJSON:
		data := c.toAllResult(result)
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
	case report.FormatYAML:
		data := c.toAllResult(result)
		if err := yaml.NewEncoder(&buf).Encode(data); err != nil {
			return fmt.Errorf("failed to encode YAML: %w", err)
		}
	default:
		if err := c.renderAllText(&buf, result); err != nil {
			return fmt.Errorf("failed to render text output: %w", err)
		}
	}

	if c.reportFile != "" {
		hostname := report.ResolveHostname()
		codes := scan.Codes(mask)
		path := report.DefaultPath(c.reportFile, hostname, codes, c.format)
		wOpts := report.Options{AllowElevatedWrite: c.allowElevatedWrite}
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
func (c *allCmd) renderAllText(w *bytes.Buffer, result *ScanResult) error {
	fmt.Fprintf(w, "owatch all  --  %s\n\n", result.Timestamp.UTC().Format(time.RFC3339))

	// module accounting
	if len(result.Modules) > 0 {
		fmt.Fprintf(w, "Modules:\n")
		for _, m := range result.Modules {
			fmt.Fprintf(w, "  %-10s %s\n", m.Name, m.Status)
		}
		fmt.Fprintln(w)
	}

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
		if err := softwarelist.WriteText(w, softwarelist.View(result.Software)); err != nil {
			return err
		}
	}

	fmt.Fprintln(w)

	// security findings
	if result.SecurityAudit != nil {
		fmt.Fprintf(w, "Security Audit\n")
		if err := audit.WriteText(w, result.SecurityAudit, c.minSeverity); err != nil {
			return err
		}
	}
	return nil
}

func (c *allCmd) isModuleSkipped(module string) bool {
	if len(c.skipModules) == 0 {
		return false
	}

	for _, skip := range c.skipModules {
		if strings.EqualFold(skip, module) {
			return true
		}
	}
	return false
}
