// +build windows

package security

import (
    "fmt"
    "os"
    "os/exec"
    "strings"
)

// RunWindowsAudit runs all checks or individual checks based on flags
func RunWindowsAudit(verbose bool, checks ...string) {
    if len(checks) == 0 {
        if verbose {
            fmt.Println("Running all checks in verbose mode...")
        } else {
            printHelpMessage()
            return
        }
        runCheck("Firewall Status", checkFirewallStatus, verbose)
        runCheck("User Accounts", checkUserAccounts, verbose)
        runCheck("SSH Configuration", checkSSHConfig, verbose)
        runCheck("File Permissions", func() string {
            return checkFilePermissions("C:\\Windows\\System32")
        }, verbose)
    } else {
        for _, check := range checks {
            switch check {
            case "firewall":
                runCheck("Firewall Status", checkFirewallStatus, verbose)
            case "users":
                runCheck("User Accounts", checkUserAccounts, verbose)
            case "ssh":
                runCheck("SSH Configuration", checkSSHConfig, verbose)
            case "file-permissions":
                runCheck("File Permissions", func() string {
                    return checkFilePermissions("C:\\Windows\\System32")
                }, verbose)
            default:
                fmt.Printf("Unknown check: %s\n\n", check)
                printHelpMessage()
                return
            }
        }
    }
}

// runCheck is a helper function to format output for each check
func runCheck(title string, checkFunc func() string, verbose bool) {
    if verbose {
        fmt.Println("\n======================================")
        fmt.Printf("== %s\n", title)
        fmt.Println("======================================")
    }
    result := checkFunc()
    fmt.Println(result)
    if verbose {
        fmt.Println("======================================")
    }
}

// printHelpMessage provides help for available submodule options
func printHelpMessage() {
    fmt.Println("Usage: cpscan security_audit [options]")
    fmt.Println("Perform a security audit for Windows systems. Available options:")
    fmt.Println("  --check-firewall         Check the status of Windows Firewall")
    fmt.Println("  --check-users            List all user accounts on the system")
    fmt.Println("  --check-ssh              Analyze SSH installation and configuration")
    fmt.Println("  --file-permissions FILE  Check permissions for the specified file")
    fmt.Println("  -v, --verbose            Run all checks with detailed output")
}

// checkFirewallStatus inspects the status of Windows firewall
func checkFirewallStatus() string {
    cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles")
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Sprintf("Error checking firewall status: %v", err)
    }
    return parseFirewallOutput(string(output))
}

// parseFirewallOutput extracts key details from firewall output
func parseFirewallOutput(output string) string {
    lines := strings.Split(output, "\n")
    activeProfiles := []string{}
    for _, line := range lines {
        if strings.Contains(line, "State") && strings.Contains(line, "ON") {
            activeProfiles = append(activeProfiles, line)
        }
    }
    if len(activeProfiles) == 0 {
        return "No active firewall profiles found."
    }
    return fmt.Sprintf("Active firewall profiles:\n%s", strings.Join(activeProfiles, "\n"))
}

// checkUserAccounts retrieves and analyzes user accounts on the system
func checkUserAccounts() string {
    cmd := exec.Command("net", "user")
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Sprintf("Error checking user accounts: %v", err)
    }
    return summarizeUserAccounts(string(output))
}

// summarizeUserAccounts provides a concise summary of user accounts
func summarizeUserAccounts(output string) string {
    lines := strings.Split(output, "\n")
    users := []string{}
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line != "" && !strings.HasPrefix(line, "The command completed") && !strings.HasPrefix(line, "User accounts") {
            users = append(users, line)
        }
    }
    if len(users) == 0 {
        return "No user accounts found."
    }
    return fmt.Sprintf("Detected user accounts:\n%s", strings.Join(users, "\n"))
}

// checkSSHConfig inspects SSH installation and configuration on Windows
func checkSSHConfig() string {
    report := ""

    // Check OpenSSH installation
    cmd := exec.Command("powershell", "-Command", "Get-WindowsCapability -Online | Where-Object { $_.Name -like '*OpenSSH.Server*' }")
    output, err := cmd.CombinedOutput()
    if err == nil && strings.Contains(string(output), "Installed") {
        report += "OpenSSH server is installed.\n"
        report += analyzeOpenSSHWindows()
    } else {
        report += "OpenSSH server is not installed.\n"
    }

    // Check for PuTTY
    puttyPath := "C:\\Program Files\\PuTTY\\putty.exe"
    if _, err := os.Stat(puttyPath); !os.IsNotExist(err) {
        report += "PuTTY is installed.\n"
        report += analyzePuTTY()
    } else {
        report += "PuTTY is not installed.\n"
    }

    return report
}

// analyzeOpenSSHWindows examines OpenSSH configuration on Windows
func analyzeOpenSSHWindows() string {
    sshConfigPath := "C:\\ProgramData\\ssh\\sshd_config"
    if _, err := os.Stat(sshConfigPath); os.IsNotExist(err) {
        return "OpenSSH configuration file not found.\n"
    }
    cmd := exec.Command("powershell", "-Command", fmt.Sprintf("Get-Content -Path %s | Out-String", sshConfigPath))
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Sprintf("Error reading OpenSSH configuration: %v\n", err)
    }
    return analyzeSSHConfig(string(output))
}

// analyzePuTTY inspects PuTTY registry settings
func analyzePuTTY() string {
    cmd := exec.Command("reg", "query", "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions")
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Sprintf("Error querying PuTTY configurations: %v", err)
    }

    sessions := strings.Split(string(output), "\n")
    report := "PuTTY Configured Sessions:\n"
    for _, session := range sessions {
        session = strings.TrimSpace(session)
        if session != "" {
            report += fmt.Sprintf("  - %s\n", session)
        }
    }
    return report
}

// checkFilePermissions checks file permissions for the specified path
func checkFilePermissions(path string) string {
    cmd := exec.Command("icacls", path)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Sprintf("Error checking file permissions for %s: %v", path, err)
    }
    return fmt.Sprintf("File permissions for %s:\n%s", path, string(output))
}

