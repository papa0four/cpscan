// cmd/commands/security/security.go

// Package security implements the owatch audit command, which runs the
// configuration security checks and renders their results as text, JSON, or
// YAML, optionally writing them to a generated report file.
package security

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/scan"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// auditCmd holds one invocation's flag state. Cobra binds flags directly into
	// these fields, so the values a run needs are the values that run parsed.
	auditCmd struct {
		// Command flags
		verbose     bool
		skipChecks  []string
		minSeverity string
		timeout     time.Duration

		// Individual check flags
		checkSSH       bool
		checkFirewall  bool
		checkUsers     bool
		checkFilePerms string

		// enrichment flag
		enrich bool

		// out owns the output destination flags and the emission of the
		// finished report.
		out *delivery.Flags
	}

	// auditReport adapts a finished audit result to delivery.Report. It pairs the
	// result with the command whose min-severityu governs its projection.
	auditReport struct {
		c      *auditCmd
		result *audit.Result
	}
)

// NewCmd returns the security audit command. RunE is bound to platformRunE, a
// method provided by exactly one build-tagged file per compiled target, so a
// target missing its platform file fails to compile rather than shipping a nil
// RunE.
func NewCmd() *cobra.Command {
	c := &auditCmd{}

	cmd := &cobra.Command{
		Use:     "audit",
		Args:    cobra.NoArgs,
		Aliases: []string{"security_audit"},
		Short:   "Perform a security audit of the system",
		RunE:    c.platformRunE,
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

	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v", false,
		"Enable verbose output")
	cmd.Flags().StringSliceVar(&c.skipChecks, "skip-checks", []string{},
		"Checks to skip (comma-separated: ssh, firewall, users, permissions)")
	cmd.Flags().StringVar(&c.minSeverity, "min-severity", types.SeverityLow,
		fmt.Sprintf("Minimum severity level to report (%s)", types.SeverityNames()))
	cmd.Flags().DurationVar(&c.timeout, "timeout", 10*time.Minute,
		"Maximum time to run the audit")
	cmd.Flags().BoolVar(&c.checkSSH, "ssh", false,
		"Run SSH configuration check")
	cmd.Flags().BoolVar(&c.checkFirewall, "fwall", false,
		"Run firewall configuration check")
	cmd.Flags().BoolVar(&c.checkUsers, "users", false,
		"Run user accounts check")
	cmd.Flags().StringVar(&c.checkFilePerms, "fperms", "",
		"Check permissions of specified file path")
	cmd.Flags().BoolVarP(&c.enrich, "enrich", "e", false,
		"Query external sources to annotate findings with CVEs mapped to referenced CWEs")

	c.out = delivery.Bind(cmd)

	return cmd
}

// buildMask composes a CheckMask from the active flag values
func (c *auditCmd) buildMask() (scan.CheckMask, error) {
	mask := scan.CheckSSH | scan.CheckFirewall | scan.CheckUsers | scan.CheckPerms

	if c.checkSSH || c.checkFirewall || c.checkUsers || c.checkFilePerms != "" {
		mask = 0
		if c.checkSSH {
			mask |= scan.CheckSSH
		}
		if c.checkFirewall {
			mask |= scan.CheckFirewall
		}
		if c.checkUsers {
			mask |= scan.CheckUsers
		}
		if c.checkFilePerms != "" {
			mask |= scan.CheckPerms
		}
	}

	if len(c.skipChecks) > 0 {
		skipMask, err := scan.MaskFromNames(c.skipChecks, scan.CategoryCheck)
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

func (c *auditCmd) validateFlags(cmd *cobra.Command) error {
	if err := c.out.Resolve(cmd); err != nil {
		return err
	}

	// Normalize once at the boundary so every downstream consumer sees the
	// canonical form; validation and storage happen in the same step.
	normalized, ok := types.NormalizeSeverity(c.minSeverity)
	if !ok {
		return fmt.Errorf("invalid min-severity: %s (valid: %s)", c.minSeverity, types.SeverityNames())
	}
	c.minSeverity = normalized

	if err := c.validateFilePermsPath(cmd); err != nil {
		return err
	}

	if _, err := scan.MaskFromNames(c.skipChecks, scan.CategoryCheck); err != nil {
		return err
	}

	return nil
}

// validateFilePermsPath enforces existing path and file rejecting explicit empty value
func (c *auditCmd) validateFilePermsPath(cmd *cobra.Command) error {
	if !cmd.Flags().Changed("fperms") {
		return nil
	}
	if c.checkFilePerms == "" {
		return fmt.Errorf("--fperms: requires a path")
	}
	if _, err := os.Stat(c.checkFilePerms); err != nil {
		return fmt.Errorf("--fperms: path is not accessible: %w", err)
	}
	return nil
}

func (c *auditCmd) logVerboseConfig(mask scan.CheckMask) {
	if !c.verbose || c.out.ToFile() {
		return
	}
	checks := scan.EnabledChecks(mask)
	if len(checks) > 0 {
		fmt.Printf("[*] Running checks: %s\n", strings.Join(checks, ", "))
	} else {
		fmt.Println("[*] Running comprehensive security audit")
	}
	fmt.Printf("[*] Output format: %s\n", c.out.Format())
	if len(c.skipChecks) > 0 {
		fmt.Printf("[*] Skipped checks: %s\n", strings.Join(c.skipChecks, ", "))
	}
	fmt.Printf("[*] Minimum severity: %s\n", c.minSeverity)
	fmt.Printf("[*] Timeout: %s\n", c.timeout)
	fmt.Println()
}

// runAuditWithTimeout executes the audit synchronously under a deadline.
// Cancellation propagates through RunAudit into checker exec and filesystem
// work, so on timeout nothing owatch started is left running -- the prior
// goroutine-and-select pattern reported the timeout but abandoned the scan
// to keep executing against the host.
func (c *auditCmd) runAuditWithTimeout(cmd *cobra.Command, mask scan.CheckMask) error {
	opts := audit.Options{
		Verbose:       c.verbose && !c.out.ToFile(),
		FilePermsPath: c.checkFilePerms,
		MinSeverity:   c.minSeverity,
		Checks:        scan.EnabledChecks(mask),
		Enrich:        c.enrich,
	}

	auditor := audit.NewSecurityAuditor(opts)

	ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
	defer cancel()

	result, err := auditor.RunAudit(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	if err := c.outputResults(result, mask); err != nil {
		return err
	}

	if ctx.Err() == context.DeadlineExceeded {
		if hint := scan.SkipHint(scan.CategoryCheck, result.IncompleteChecks); hint != "" {
			return fmt.Errorf("audit timeout after %v; results above are incomplete; rerun with a longer --timeout or %s",
				c.timeout, hint)
		}
		return fmt.Errorf("audit timeout after %v; results above are incomplete", c.timeout)
	}
	return nil
}

func (c *auditCmd) outputResults(result *audit.Result, mask scan.CheckMask) error {
	if result == nil || len(result.Results) == 0 {
		return fmt.Errorf("audit produced no results")
	}

	return c.out.Deliver(auditReport{c: c, result: result}, mask)
}

// View returns the severity-filtered audit projection.
func (r auditReport) View() any {
	return r.result.View(r.c.minSeverity)
}

// WriteText renders the audit as human-readable text: the system block via
// osfingerprint.WriteText, then the security section via audit.WriteText.
func (r auditReport) WriteText(w io.Writer) error {
	ew := render.NewErrWriter(w)
	ew.Printf("\nSecurity Audit Report\n")
	ew.Printf("====================\n\n")
	if err := ew.Err(); err != nil {
		return err
	}

	if r.result.HostInfo != nil {
		if err := osfingerprint.WriteText(w, r.result.HostInfo); err != nil {
			return err
		}
		ew.Printf("\n")
		if err := ew.Err(); err != nil {
			return err
		}
	}

	return audit.WriteText(w, r.result, r.c.minSeverity)
}
