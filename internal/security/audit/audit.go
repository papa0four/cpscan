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
	auditor := &SecurityAuditor{
		verbose: opts.Verbose,
		options: opts,
	}

	switch runtime.GOOS {
	case "windows":
		auditor.sshChecker = checker.NewWindowsSSHChecker()
		auditor.firewallChecker = checker.NewWindowsFirewallChecker()
		auditor.userChecker = checker.NewWindowsUserChecker()
		auditor.permissionChecker = checker.NewWindowsPermissionChecker()
	default:
		auditor.sshChecker = checker.NewUnixSSHChecker()
		auditor.firewallChecker = checker.NewUnixFirewallChecker()
		auditor.userChecker = checker.NewUnixUserChecker()
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
				checkResult = sa.sshChecker.Check()
				result.Results = append(result.Results, checkResult)
			case "firewall":
				checkResult = sa.firewallChecker.Check()
				result.Results = append(result.Results, checkResult)
			case "users":
				checkResult = sa.userChecker.Check()
				result.Results = append(result.Results, checkResult)
			case "file-permissions":
				checkResult = sa.permissionChecker.Check()
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
	resultsChan := make(chan types.AuditResult, 4)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running SSH configuration check...")
		}
		resultsChan <- sa.sshChecker.Check()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running firewall configuration check...")
		}
		resultsChan <- sa.firewallChecker.Check()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running user account security check...")
		}
		resultsChan <- sa.userChecker.Check()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sa.verbose {
			fmt.Println("[*] Running file permissions check...")
		}
		resultsChan <- sa.permissionChecker.Check()
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
		case result.Status == "COMPLETED" && !containsWarning(result.Details):
			summary.PassedChecks++
		case result.Status == "WARNING" || containsWarning(result.Details):
			summary.WarningChecks++
		case result.Status == "ERROR":
			summary.FailedChecks++
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

	if softwareInfo, softwareCount, err := getSoftwareInfo(); err == nil {
		info.SoftwareInfo = softwareInfo
		info.SoftwareCount = softwareCount
	}

	return info
}

func getKernelVersion() (string, error) {
	switch runtime.GOOS {
	case "windows":
		output, err := exec.Command("ver").CombinedOutput()
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

func getSoftwareInfo() (string, int, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell",
			`Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | `+
				`Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | `+
				`Format-Table -AutoSize`)
	case "darwin":
		cmd = exec.Command("sh", "-c", "system_profiler SPApplicationsDataType | grep 'Name:\\|Version:'")
	default:
		cmd = exec.Command("sh", "-c", "dpkg-query -W -f='${Package} ${Version}\n'")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", 0, err
	}

	softwareInfo := string(output)
	softwareCount := strings.Count(softwareInfo, "\n") + 1

	return softwareInfo, softwareCount, nil
}

func containsWarning(details []string) bool {
	for _, detail := range details {
		if strings.Contains(detail, "WARNING") ||
			strings.Contains(detail, types.SymbolWarning) {
			return true
		}
	}
	return false
}
