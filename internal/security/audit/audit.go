// internal/security/audit/audit.go
package audit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/papa0four/orkowatch/internal/security/checker"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// SecurityAuditor handles the orchestration of security checks
type SecurityAuditor struct {
	sshChecker        checker.SSHChecker
	firewallChecker   checker.FirewallChecker
	userChecker       checker.UserChecker
	permissionChecker checker.PermissionChecker
	verbose           bool
	options           Options
	osContext         registry.OSContext
}

// Options configures the audit process
type Options struct {
	Verbose        bool
	SpecificChecks []string
	SkipChecks     []string
	FilePermsPath  string
	MinSeverity    string
	Timeout        time.Duration
	Enrich         bool
}

// Result represents the complete audit results
type Result struct {
	StartTime           time.Time
	EndTime             time.Time
	Duration            time.Duration
	Results             []types.AuditResult
	SystemInfo          SystemInfo
	Summary             Summary
	EnrichmentRequested bool
	EnrichmentError     error
	Enrichment          *enrichment.Result
	References          types.ReferenceExtraction
}

// SystemInfo contains basic system information collected at the start of an
// audit. Software inventory is owned by the all command and is not part of
// the audit subsystem -- see cmd/commands/all.go and internal/softwarelist.
type SystemInfo struct {
	OS            string `json:"os" yaml:"os"`
	Architecture  string `json:"architecture" yaml:"architecture"`
	Hostname      string `json:"hostname" yaml:"hostname"`
	KernelVersion string `json:"kernel_version" yaml:"kernel_version"`
}

// Summary reports the outcome of a completed audit at both check and finding
// level. PassedChecks counts checks that completed with zero findings.
// SkippedChecks counts checks excluded via --skip-checks. Finding counts are
// broken down by severity so the analyst can assess exposure at a glance
// without reading individual check output. TotalFindings is the sum of all
// severity buckets.
type Summary struct {
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
type checkRunner struct {
	name string
	run  func() types.AuditResult
}

// NewSecurityAuditor creates a new security auditor based on the OS
func NewSecurityAuditor(opts Options) *SecurityAuditor {
	ctx := registry.DetectOS()

	auditor := &SecurityAuditor{
		verbose:   opts.Verbose,
		options:   opts,
		osContext: ctx,
	}

	switch runtime.GOOS {
	case "windows":
		auditor.sshChecker = checker.NewWindowsSSHChecker(ctx)
		auditor.firewallChecker = checker.NewWindowsFirewallChecker(ctx)
		auditor.userChecker = checker.NewWindowsUserChecker(ctx)
		auditor.permissionChecker = checker.NewWindowsPermissionChecker(ctx, opts.FilePermsPath)
	default:
		auditor.sshChecker = checker.NewUnixSSHChecker(ctx)
		auditor.firewallChecker = checker.NewUnixFirewallChecker(ctx)
		auditor.userChecker = checker.NewUnixUserChecker(ctx)
		auditor.permissionChecker = checker.NewUnixPermissionChecker(ctx, opts.FilePermsPath)
	}

	return auditor
}

// RunAudit performs the security audit with the specified options
func (sa *SecurityAuditor) RunAudit() (*Result, error) {
	result := &Result{
		StartTime:           time.Now(),
		SystemInfo:          getSystemInfo(),
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
				checkResult = timeCheck(sa.sshChecker.Check)
				result.Results = append(result.Results, checkResult)
			case "firewall":
				checkResult = timeCheck(sa.firewallChecker.Check)
				result.Results = append(result.Results, checkResult)
			case "users":
				checkResult = timeCheck(sa.userChecker.Check)
				result.Results = append(result.Results, checkResult)
			case "permissions":
				checkResult = timeCheck(sa.permissionChecker.Check)
				result.Results = append(result.Results, checkResult)
			}
		}
		sa.finalize(result)
		return result, nil
	}

	return sa.runAllChecks(result)
}

func (sa *SecurityAuditor) runAllChecks(result *Result) (*Result, error) {
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
			resultsChan <- timeCheck(c.run)
		}(check)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for checkResult := range resultsChan {
		result.Results = append(result.Results, checkResult)
	}

	sa.finalize(result)
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

func (sa *SecurityAuditor) finalize(result *Result) {
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

	ctx, cancel := context.WithTimeout(context.Background(), sa.options.Timeout)
	defer cancel()

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
		ext.Other = append(ext.Other, sub.Other...)
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

func getSystemInfo() SystemInfo {
	info := SystemInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	if kernel, err := getKernelVersion(); err == nil {
		info.KernelVersion = kernel
	}
	return info
}

func getKernelVersion() (string, error) {
	switch runtime.GOOS {
	case "windows":
		output, err := exec.Command("cmd", "/c", "ver").CombinedOutput()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(output)), nil
	default:
		output, err := exec.Command("uname", "-r").CombinedOutput()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(output)), nil
	}
}

func timeCheck(fn func() types.AuditResult) types.AuditResult {
	start := time.Now()
	result := fn()
	end := time.Now()
	result.StartTime = start
	result.EndTime = end
	result.Duration = end.Sub(start)
	return result
}
