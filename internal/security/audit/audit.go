// internal/security/audit/audit.go
package audit

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/checker"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// SecurityAuditor handles the orchestration of security checks
	SecurityAuditor struct {
		sshChecker        checker.SSHChecker
		firewallChecker   checker.FirewallChecker
		userChecker       checker.UserChecker
		permissionChecker checker.PermissionChecker
		verbose           bool
		options           Options
		osContext         registry.OSContext
	}

	// Options configures the audit process. The run's deadline is not part of
	// Options: it arrives as the context passed to RunAudit, owned by the
	// command layer, and bounds checks and enrichment together as one budget.
	Options struct {
		Verbose        bool
		SpecificChecks []string
		SkipChecks     []string
		FilePermsPath  string
		MinSeverity    string
		Enrich         bool
		HostInfo       *osfingerprint.OSInfo
	}

	// Result represents the complete audit results
	Result struct {
		StartTime           time.Time
		EndTime             time.Time
		Duration            time.Duration
		Results             []types.AuditResult
		HostInfo            *osfingerprint.OSInfo
		Summary             Summary
		EnrichmentRequested bool
		EnrichmentError     error
		Enrichment          *enrichment.Result
		References          types.ReferenceExtraction
	}

	// Summary reports the outcome of a completed audit at both check and finding
	// level. PassedChecks counts checks that completed with zero findings.
	// SkippedChecks counts checks excluded via --skip-checks. Finding counts are
	// broken down by severity so the analyst can assess exposure at a glance
	// without reading individual check output. TotalFindings is the sum of all
	// severity buckets.
	Summary struct {
		TotalChecks      int
		PassedChecks     int
		SkippedChecks    int
		TotalFindings    int
		CriticalFindings int
		HighFindings     int
		MediumFindings   int
		LowFindings      int
	}

	// checkRunner pairs a check's canonical name with its execution function
	checkRunner struct {
		name string
		run  func(ctx context.Context) types.AuditResult
	}
)

// NewSecurityAuditor creates a new security auditor based on the OS
func NewSecurityAuditor(opts Options) *SecurityAuditor {
	osCtx := registry.DetectOS()

	auditor := &SecurityAuditor{
		verbose:   opts.Verbose,
		options:   opts,
		osContext: osCtx,
	}

	switch runtime.GOOS {
	case "windows":
		auditor.sshChecker = checker.NewWindowsSSHChecker(osCtx)
		auditor.firewallChecker = checker.NewWindowsFirewallChecker(osCtx)
		auditor.userChecker = checker.NewWindowsUserChecker(osCtx)
		auditor.permissionChecker = checker.NewWindowsPermissionChecker(osCtx, opts.FilePermsPath)
	default:
		auditor.sshChecker = checker.NewUnixSSHChecker(osCtx)
		auditor.firewallChecker = checker.NewUnixFirewallChecker(osCtx)
		auditor.userChecker = checker.NewUnixUserChecker(osCtx)
		auditor.permissionChecker = checker.NewUnixPermissionChecker(osCtx, opts.FilePermsPath)
	}

	return auditor
}

// RunAudit performs the security audit with the specified options. ctx
// bounds the entire run -- checks and enrichment share its deadline -- and
// cancellation propagates into checker exec and filesystem work.
func (sa *SecurityAuditor) RunAudit(ctx context.Context) (*Result, error) {
	fingerprint := sa.options.HostInfo
	if fingerprint == nil {
		var err error
		if fingerprint, err = osfingerprint.GetOSFingerprint(); err != nil && sa.verbose {
			fmt.Printf("[!] OS fingerprint unavailable: %v\n", err)
		}
	}

	result := &Result{
		StartTime:           time.Now(),
		HostInfo:            fingerprint,
		Results:             make([]types.AuditResult, 0),
		EnrichmentRequested: sa.options.Enrich,
	}

	if len(sa.options.SpecificChecks) > 0 {
		for _, check := range sa.options.SpecificChecks {
			if sa.options.Verbose {
				fmt.Printf("\n[*] Running %s check...\n", check)
			}

			var checkResult types.AuditResult
			switch check {
			case "ssh":
				checkResult = timeCheck(ctx, sa.sshChecker.Check)
				result.Results = append(result.Results, checkResult)
			case "firewall":
				checkResult = timeCheck(ctx, sa.firewallChecker.Check)
				result.Results = append(result.Results, checkResult)
			case "users":
				checkResult = timeCheck(ctx, sa.userChecker.Check)
				result.Results = append(result.Results, checkResult)
			case "permissions":
				checkResult = timeCheck(ctx, sa.permissionChecker.Check)
				result.Results = append(result.Results, checkResult)
			}
		}
		sa.finalize(ctx, result)
		return result, nil
	}

	return sa.runAllChecks(ctx, result)
}

func (sa *SecurityAuditor) runAllChecks(ctx context.Context, result *Result) (*Result, error) {
	if sa.verbose {
		fmt.Println("[*] Starting comprehensive security audit...")
	}

	checks := sa.activeChecks()
	if len(checks) == 0 {
		return nil, fmt.Errorf("all available checks were skipped; at least one must run")
	}

	var wg sync.WaitGroup
	resultsChan := make(chan types.AuditResult, len(checks))

	for _, check := range checks {
		wg.Add(1)
		go func(c checkRunner) {
			defer wg.Done()
			if sa.verbose {
				fmt.Printf("[*] Running %s check...\n", c.name)
			}
			resultsChan <- timeCheck(ctx, c.run)
		}(check)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for checkResult := range resultsChan {
		result.Results = append(result.Results, checkResult)
	}

	sa.finalize(ctx, result)
	return result, nil
}

func (sa *SecurityAuditor) activeChecks() []checkRunner {
	all := []checkRunner{
		{name: "ssh", run: sa.sshChecker.Check},
		{name: "firewall", run: sa.firewallChecker.Check},
		{name: "users", run: sa.userChecker.Check},
		{name: "permissions", run: sa.permissionChecker.Check},
	}

	if len(sa.options.SkipChecks) == 0 {
		return all
	}

	skipped := make(map[string]struct{}, len(sa.options.SkipChecks))
	for _, s := range sa.options.SkipChecks {
		skipped[s] = struct{}{}
	}

	active := make([]checkRunner, 0, len(all))
	for _, c := range all {
		if _, skip := skipped[c.name]; skip {
			continue
		}
		active = append(active, c)
	}
	return active
}

// finalize computes duration, summary, and reference aggregation, then runs
// enrichment when requested. Enrichment shares the caller's ctx rather than
// opening a fresh deadline: --timeout is one budget for the whole run, not
// a separate window per phase.
func (sa *SecurityAuditor) finalize(ctx context.Context, result *Result) {
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Summary = sa.calculateSummary(result.Results)
	result.References = aggregateReferences(result.Results)

	if !sa.options.Enrich {
		return
	}

	enricher, err := enrichment.NewEnricher()
	if err != nil {
		result.EnrichmentError = err
		return
	}

	if len(result.References.CWEs) == 0 {
		return
	}

	req := enrichment.EnrichRequest{
		CWEs:        result.References.CWEs,
		MinSeverity: sa.options.MinSeverity,
	}

	enrichResult, err := enricher.Enrich(ctx, req)
	if err != nil {
		result.EnrichmentError = err
		return
	}
	result.Enrichment = &enrichResult
}

func aggregateReferences(results []types.AuditResult) types.ReferenceExtraction {
	var ext types.ReferenceExtraction
	seen := make(map[string]struct{})
	for i := range results {
		sub := results[i].AllCWEReferences()
		for _, id := range sub.CWEs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ext.CWEs = append(ext.CWEs, id)
		}
		ext.Errors = append(ext.Errors, sub.Errors...)
	}
	return ext
}

// calculateSummary iterates all check results and produces a Summary with
// per-severity finding counts. A check is counted as passed only when it
// completes with zero findings. ERROR status checks are not counted as
// passed or skipped -- their findings still contribute to severity totals.
// Severity classification uses the canonical SeverityX constants from the
// types package so the bucketing is consistent with registry and enrichment
// output.
func (sa *SecurityAuditor) calculateSummary(results []types.AuditResult) Summary {
	summary := Summary{
		TotalChecks: len(results),
	}

	for _, result := range results {
		switch {
		case result.Status == "ERROR":
			// ERROR checks are neither passed nor skipped --
			// their findings still count toward severity totals
		case result.Status == "SKIPPED":
			summary.SkippedChecks++
			continue
		case len(result.Findings) == 0:
			summary.PassedChecks++
		}

		for _, finding := range result.Findings {
			summary.TotalFindings++
			switch strings.ToUpper(finding.Severity) {
			case types.SeverityCritical:
				summary.CriticalFindings++
			case types.SeverityHigh:
				summary.HighFindings++
			case types.SeverityMedium:
				summary.MediumFindings++
			case types.SeverityLow:
				summary.LowFindings++
			}
		}
	}
	return summary
}

func timeCheck(ctx context.Context, fn func(context.Context) types.AuditResult) types.AuditResult {
	start := time.Now()
	result := fn(ctx)
	end := time.Now()
	result.StartTime = start
	result.EndTime = end
	result.Duration = end.Sub(start)
	return result
}
