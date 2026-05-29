// internal/security/audit/audit.go
package audit

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/papa0four/orkowatch/internal/security/checker"
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
	CustomPaths    []string
	SkipChecks     []string
	MinSeverity    string
	Timeout        time.Duration
}

// Result represents the complete audit results
type Result struct {
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Results    []types.AuditResult
	SystemInfo SystemInfo
	Summary    Summary
}

// SystemInfo contains basic system information
type SystemInfo struct {
	OS            string
	Architecture  string
	Hostname      string
	KernelVersion string
	SoftwareInfo  string
	SoftwareCount int
}

// Summary provides a summary of the audit results
type Summary struct {
	TotalChecks   int
	PassedChecks  int
	WarningChecks int
	FailedChecks  int
	SkippedChecks int
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
		auditor.permissionChecker = checker.NewWindowsPermissionChecker(ctx)
	default:
		auditor.sshChecker = checker.NewUnixSSHChecker(ctx)
		auditor.firewallChecker = checker.NewUnixFirewallChecker()
		auditor.userChecker = checker.NewUnixUserChecker(ctx)
		auditor.permissionChecker = checker.NewUnixPermissionChecker()
	}

	return auditor
}

// RunAudit performs the security audit with the specified options
func (sa *SecurityAuditor) RunAudit() (*Result, error) {
	result := &Result{
		StartTime:  time.Now(),
		SystemInfo: getSystemInfo(),
		Results:    make([]types.AuditResult, 0),
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
			case "file-permissions":
				checkResult = timeCheck(sa.permissionChecker.Check)
				result.Results = append(result.Results, checkResult)
			}
		}
	} else {
		return sa.runAllChecks(result)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Summary = sa.calculateSummary(result.Results)

	return result, nil
}

func (sa *SecurityAuditor) runAllChecks(result *Result) (*Result, error) {
	if sa.verbose {
		fmt.Println("[*] Starting comprehensive security audit...")
	}

	var wg sync.WaitGroup
	const numSecurityChecks = 4
	resultsChan := make(chan types.AuditResult, numSecurityChecks)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running SSH configuration check...")
		}
		resultsChan <- timeCheck(sa.sshChecker.Check)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running firewall configuration check...")
		}
		resultsChan <- timeCheck(sa.firewallChecker.Check)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running user account security check...")
		}
		resultsChan <- timeCheck(sa.userChecker.Check)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running file permissions check...")
		}
		resultsChan <- timeCheck(sa.permissionChecker.Check)
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for checkResult := range resultsChan {
		result.Results = append(result.Results, checkResult)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Summary = sa.calculateSummary(result.Results)

	return result, nil
}

func (sa *SecurityAuditor) calculateSummary(results []types.AuditResult) Summary {
	summary := Summary{
		TotalChecks: len(results),
	}

	for _, result := range results {
		switch {
		case result.Status == "ERROR":
			summary.FailedChecks++
		case len(result.Findings) > 0:
			summary.WarningChecks++
		case result.Status == "COMPLETED":
			summary.PassedChecks++
		default:
			summary.SkippedChecks++
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
