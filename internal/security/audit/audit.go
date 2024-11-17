// internal/security/audit/audit.go
package audit

import (
    "fmt"
	"os"
	"os/exec"
    "runtime"
    "sync"
    "time"
	"strings"

    "github.com/papa0four/cpscan/internal/security/checker"
    "github.com/papa0four/cpscan/internal/security/types"
)

// SecurityAuditor handles the orchestration of security checks
type SecurityAuditor struct {
    sshChecker       	checker.SSHChecker
    firewallChecker  	checker.FirewallChecker
    userChecker      	checker.UserChecker
    permissionChecker 	checker.PermissionChecker
    verbose          	bool
	outputFormat		string
	reportFile			string
    options             AuditOptions
}

// AuditOptions configures the audit process
type AuditOptions struct {
    Verbose          bool
    SpecificChecks   []string
    CustomPaths      []string
    SkipChecks       []string
	MinSeverity		 string
	Timeout			 time.Duration
}

// NewSecurityAuditor creates a new security auditor based on the OS
func NewSecurityAuditor(opts AuditOptions) *SecurityAuditor {
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
    default: // Unix-like systems (Linux, macOS, BSD)
        auditor.sshChecker = checker.NewUnixSSHChecker()
        auditor.firewallChecker = checker.NewUnixFirewallChecker()
        auditor.userChecker = checker.NewUnixUserChecker()
        auditor.permissionChecker = checker.NewUnixPermissionChecker()
    }

    return auditor
}

// AuditResult represents the complete audit results
type AuditResult struct {
    StartTime   time.Time
    EndTime     time.Time
    Duration    time.Duration
    Results     []types.AuditResult
    SystemInfo  SystemInfo
    Summary     AuditSummary
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

// AuditSummary provides a summary of the audit results
type AuditSummary struct {
    TotalChecks    int
    PassedChecks   int
    WarningChecks  int
    FailedChecks   int
    SkippedChecks  int
}

// RunAudit performs the security audit with the specified options
func (sa *SecurityAuditor) RunAudit() (*AuditResult, error) {
    result := &AuditResult{
        StartTime:  time.Now(),
        SystemInfo: getSystemInfo(),
        Results:    make([]types.AuditResult, 0),
    }

    // Only run specific checks if specified
    if len(sa.options.SpecificChecks) > 0 {
        for _, check := range sa.options.SpecificChecks {
            if sa.options.Verbose {
                fmt.Printf("\nRunning %s configuration check...\n", check)
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
        // Run all checks only if no specific checks were requested
        return sa.runAllChecks(result)
    }

    result.EndTime = time.Now()
    result.Duration = result.EndTime.Sub(result.StartTime)
    result.Summary = sa.calculateSummary(result.Results)

    return result, nil
}

func (sa *SecurityAuditor) runAllChecks(result *AuditResult) (*AuditResult, error) {
    if sa.verbose {
        fmt.Println("Starting comprehensive security audit...")
    }

    // Use a WaitGroup to run checks concurrently
    var wg sync.WaitGroup
    resultsChan := make(chan types.AuditResult, 4) // Buffer for all checkers

    // Run SSH check
    wg.Add(1)
    go func() {
        defer wg.Done()
        if sa.verbose {
            fmt.Println("\nRunning SSH configuration check...")
        }
        resultsChan <- sa.sshChecker.Check()
    }()

    // Run firewall check
    wg.Add(1)
    go func() {
        defer wg.Done()
        if sa.verbose {
            fmt.Println("\nRunning firewall configuration check...")
        }
        resultsChan <- sa.firewallChecker.Check()
    }()

    // Run user check
    wg.Add(1)
    go func() {
        defer wg.Done()
        if sa.verbose {
            fmt.Println("\nRunning user account security check...")
        }
        resultsChan <- sa.userChecker.Check()
    }()

    // Run permissions check
    wg.Add(1)
    go func() {
        defer wg.Done()
        if sa.verbose {
            fmt.Println("\nRunning file permissions check...")
        }
        resultsChan <- sa.permissionChecker.Check()
    }()

    // Close results channel when all checks are done
    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    // Collect results
    for checkResult := range resultsChan {
        result.Results = append(result.Results, checkResult)
    }

    result.EndTime = time.Now()
    result.Duration = result.EndTime.Sub(result.StartTime)
    result.Summary = sa.calculateSummary(result.Results)

    return result, nil
}

func (sa *SecurityAuditor) runSpecificCheck(check string, result *AuditResult) error {
    if sa.verbose {
        fmt.Printf("\nRunning %s check...\n", check)
    }
    var checkResult types.AuditResult

    switch check {
    case "ssh":
        if sa.verbose {
            fmt.Println("\nRunning SSH configuration check...")
        }
        checkResult = sa.sshChecker.Check()
    case "firewall":
        if sa.verbose {
            fmt.Println("\nRunning firewall configuration check...")
        }
        checkResult = sa.firewallChecker.Check()
    case "users":
        if sa.verbose {
            fmt.Println("\nRunning user account security check...")
        }
        checkResult = sa.userChecker.Check()
    case "permissions":
        if sa.verbose {
            fmt.Println("\nRunning file permissions check...")
        }
        checkResult = sa.permissionChecker.Check()
    default:
        return fmt.Errorf("unknown check: %s", check)
    }

    result.Results = append(result.Results, checkResult)
    return nil
}

func (sa *SecurityAuditor) calculateSummary(results []types.AuditResult) AuditSummary {
    summary := AuditSummary{
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

// PrintResults formats and prints the audit results
func (sa *SecurityAuditor) PrintResults(result *AuditResult) {
    fmt.Printf("\nSecurity Audit Report\n")
    fmt.Printf("===================\n\n")

    // Print system information
    fmt.Printf("System Information:\n")
    fmt.Printf("------------------\n")
    fmt.Printf("OS: %s\n", result.SystemInfo.OS)
    fmt.Printf("Architecture: %s\n", result.SystemInfo.Architecture)
    fmt.Printf("Hostname: %s\n", result.SystemInfo.Hostname)
    fmt.Printf("Kernel Version: %s\n\n", result.SystemInfo.KernelVersion)
    fmt.Printf("Software Count: %d\n", result.SystemInfo.SoftwareCount)

    // Print detailed results
    if sa.verbose {
        // print software information
        fmt.Printf("\nInstalled Software:\n")
        fmt.Println(result.SystemInfo.SoftwareInfo)
        
        for _, checkResult := range result.Results {
            fmt.Printf("\n%s Check Results:\n", checkResult.Name)
            fmt.Printf("%s\n", strings.Repeat("-", len(checkResult.Name)+14))
            fmt.Printf("Status: %s\n", checkResult.Status)
            fmt.Printf("Description: %s\n", checkResult.Description)
            fmt.Printf("Details:\n")
            for _, detail := range checkResult.Details {
                fmt.Printf("  %s\n", detail)
            }
        }
    }

    // Print summary
    fmt.Printf("\nAudit Summary:\n")
    fmt.Printf("-------------\n")
    fmt.Printf("Total Checks: %d\n", result.Summary.TotalChecks)
    fmt.Printf("Passed: %d\n", result.Summary.PassedChecks)
    fmt.Printf("Warnings: %d\n", result.Summary.WarningChecks)
    fmt.Printf("Failed: %d\n", result.Summary.FailedChecks)
    fmt.Printf("Skipped: %d\n", result.Summary.SkippedChecks)
    fmt.Printf("\nAudit Duration: %s\n", result.Duration)
}

// Helper functions

func getSystemInfo() SystemInfo {
    info := SystemInfo{
        OS:           runtime.GOOS,
        Architecture: runtime.GOARCH,
    }

    // Get hostname
    if hostname, err := os.Hostname(); err == nil {
        info.Hostname = hostname
    }

    // Get kernel version
    if kernel, err := getKernelVersion(); err == nil {
        info.KernelVersion = kernel
    }

    if softwareInfo, softwareCount, err := getSoftwareInfo(); err == nil {
        info.SoftwareInfo   = softwareInfo
        info.SoftwareCount  = softwareCount
    }

    return info
}

func getKernelVersion() (string, error) {
    switch runtime.GOOS {
    case "windows":
        cmd := exec.Command("ver")
        output, err := cmd.CombinedOutput()
        if err != nil {
            return "", err
        }
        return strings.TrimSpace(string(output)), nil
    default:
        cmd := exec.Command("uname", "-r")
        output, err := cmd.CombinedOutput()
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
        cmd = exec.Command("powershell", `
        Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Format-Table -AutoSize
        `)
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

// PrintHelpMessage provides help for available security audit options
func PrintHelpMessage() {
    fmt.Println("Security Audit Usage:")
    fmt.Println("  cpscan security_audit [options] [checks...]")
    fmt.Println("\nOptions:")
    fmt.Println("  -v, --verbose        Show detailed output for all checks")
    fmt.Println("\nAvailable Checks:")
    fmt.Println("  ssh                  Check SSH configuration security")
    fmt.Println("  firewall             Check firewall rules and configuration")
    fmt.Println("  users                Check user account security")
    fmt.Println("  permissions          Check file and directory permissions")
    fmt.Println("\nExample:")
    fmt.Println("  cpscan security_audit -v ssh firewall")
    fmt.Println("  cpscan security_audit --check-all")
}