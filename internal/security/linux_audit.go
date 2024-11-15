// +build linux darwin

package security

import (
    "errors"
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "github.com/papa0four/cpscan/internal/softwarelist"
)

// RunUnixAudit runs all checks based on the verbose flag
func RunUnixAudit(verbose bool, check ...string) {
    // If no specific checks are specified
    if len(checks) == 0 {
        if verbose {
            fmt.Println("Running all checks in verbose mode...")
            runCheck("SSH Configuration", checkSSHConfig, verbose)
            runCheck("Firewall Rules", checkFilewallRules, verbose)
            runCheck("User Accounts", checkUserAccounts, verbose)
            runCheck("Installed Services", checkInstalledServices, verbose)
        } else {
            printHelpMessage()
            return            
        }
    } else {
        // Run only specified checks
        for _, check := range checks {
            switch check {
            case "ssh":
                runCheck("SSH Configuration", checkSSHConfig, verbose)
            case "firewall":
                runCheck("Firewall Rules", checkFirewallRules, verbose)
            case "users":
                runCheck("User Accounts", checkUserAccounts, verbose)
            case "file-permissions":
                file := "/etc/passwd" // Default file, can be set dynamically
                runCheck(fmt.Sprintf("File Permissions (%s)", file), func() string {
                    return checkFilePermissions(file)
                }, verbose)
            default:
                fmt.Println("Unknown check: %s\n", check)
                printHelpMessage()
            }
        }
    }
}

func printHelpMessage() {
    // Print the help message if neither verbose nor specific checks are provided 
    fmt.Println(" Usage: cpscan security_audit [ -v, --verbose ] | " + 
        "[ --check-ssh | --check-firewall | --check-users | --file-permissions <file_path> ]")
    fmt.Println("Options:")
    fmt.Println("  -v, --verbose        Run all checks with detailed output")
    fmt.Println("  --check-ssh          Check SSH configuration")
    fmt.Println("  --check-firewall     Check firewall configuration")
    fmt.Println("  --check-users        Check user accounts")
    fmt.Println("  --file-permissions   Check permissions of a specific file or directory")
}

// runCheck is a helper function to format output for each check
func runCheck(title string, checkFunc func() string, verbose bool) {
    if verbose {
        fmt.Println("\n=======================================")
        fmt.Printlnf("== %s\n", title)
        fmt.Println("=======================================")
    }
    result := checkFunc()
    fmt.Println(result)
    if verbose {
        fmt.Println("=======================================")
    }
}

// Individual check functions

func checkSSHConfig() string {
    possiblePaths := []string{
        "/etc/ssh/sshd_config",
        "/private/etc/ssh/sshd_config", // macOS alternative path
    }

    var file *os.File
    var err error
    for _, path := range possiblePaths {
        file, err = os.Open(path)
        if err == nil {
            defer file.Close()
            break
        }
    }

    if file == nil {
        return fmt.Sprintf("SSH configuration file not found: %v", err)
    }

    rootLoginEnabled := false
    passwordAuthEnabled := false

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        if line == "PermitRootLogin no" {
            rootLoginEnabled = true
        }
        if line == "PasswordAuthentication yes" {
            passwordAuthEnabled = true
        }
    }

    if err := scanner.Err(); err != nil {
        return fmt.Sprintf("Error reading SSH configuration: %v", err)
    }

    var result string
    if !rootLoginEnabled {
        result += "SSH root login disabled [OK]\n"
    } else {
        result += "SSH root login enabled [WARNING]\n"
    }

    if passwordAuthEnabled {
        result += "SSH password authentication enabled [WARNING]\n"
    } else {
        result += "SSH password authentication disabled [OK]\n"
    }

    return result
}

func checkFirewallRules() string {
    firewalls := []struct {
        name    string
        command []string
    }{
        {"iptables", []string{"iptables", "-L"}},
        {"ufw", []string{"ufw", "status"}},
        {"firewalld", []string{"firewall-cmd", "--list-all"}},
        {"pfctl", []string{"pfctl", "-sr"}}, // macOS & BSD-based systems
        {"ipfw", []string{"ipfw", "show"}},, // BSD & older UNIX systems
    }
    
    multipleActive := false
    activeFirewallCount := 0

    for _, fw := range firewalls {
        cmd := exec.Command(fw.command[0], fw.command[1:]...)
        output, err := cmd.CombinedOutput()

        if err == nil && len(output) > 0 {
            activeFirewallCount++
            if activeFirewallCount > 1 {
                multipleActive = true
            }
            outputDetails = append(outputDetails, fmt.Sprintf("%s rules:\n%s\n", fw.name, string(output)))
        }
    }

    if len(outputDetails) == 0 {
        return "No active firewall configuration found or support firewall tool installed."
    }

    // Print a summary if multiple firewalls are active
    if multipleActive {
        outputDetails = appen([]string{"Multiple firewall tools are active on this system:"},
            outputDetails...)
    }

    return fmt.Sprintf("\n%s\n", strings.Join(outputDetails, "\n=========================================\n"))
}

func checkFilePermissions(filePath string) string {
    // Check if the specified file exists
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        return fmt.Sprintf("Error: File or directory %s does not exist.", filePath)
    }

    // Use 'stat' for UNIX compatibility (macOS, Linux)
    cmd := exec.Command("stat", "-c", "%A %U %G %n", filePath)
    output, err := cmd.CombinedOutput()

    // if 'stat -c' fails, use alternative formatting for macOS/BSD 'stat'
    if err != nil {
        cmd = exec.Command("stat", "-f", "%Sp %Su %Sg %N", filePath)
        output, err = cmd.CombinedOutput()
        if err != nil {
            return fmt.Sprintf("Error checking file permissions for %s: %v", filePath, err)
        }
    }

    return fmt.Sprintf("File permissions for %s:\n%s", filePath, string(output))
}

// checkUserAccounts lists user accounts and attempts to identify regular users, even if stored externally
func checkUserAccounts() string {
    // Potential user account sources based on typical Unix variations
    sources := []string{
        "/etc/passwd",            // Default Unix
        "/etc/master.passwd"      // BSD systems
        "/etc/security/passwd.db" // Possible security-focused systems
    }

    // Detect NSS configurations if present
    nssConfig, err := os.ReadFile("/etc/nsswitch.conf")
    if err == nil && strings.Contains(string(nssConfig), "ldap") {
        return "Warning: NSS is configured to use LDAP or external directory services " +
            "for user accounts. Please verify external user sources."
    }

    // Check each source file for user accounts
    for _, source := range sources {
        if _, err := os.Stat(source); err == nil {
            // Parse the file if it exists
            userAccounts := parseUserFile(source)
            if len(userAccounts) > 0 {
                return fmt.Sprintf("User accounts from %s:\n%s", source, strings.Join(userAccounts, "\n"))
            }
        }
    }

    return "No local user accounts found, or user data is stored in an unsupported format or external source."
}

// parseUserFile parses user entries from a file (e.g., /etc/passwd or equivalent).
func parseUserFile(filePath string) []string {
    cmd := exec.Command("awk", "-F:", "{print $1\":\"$3\":\"$NF}", filePath)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return []string{fmt.Sprintf("Error parsing user file %s: %v", filePath, err)}
    }

    users := []string{}
    lines := strings.Split(string(output), "\n")
    for _, line := strings.Split(line, ":") {
        if len(fields) >= 2 {
            username := fields[0]
            uid, _ := strconv.Atoi(fields[1])
            shell := fields[2]

            // Identify if it is a regular or suspicious account
            if isRegularAccount(uid, shell) {
                users = append(users, fmt.Sprintf("%s (UID: %d)", username, uid))
            } else if isSuspiciousAccount(uid, shell) {
                users = append(users, fmt.Sprintf("%s (UID: %d) [POTENTIAL SYSTEM ACCOUNT]", username, uid))
            }
        }
    }
    return users
}

// isRegularAccount checks if an account is a likely regular (non-system account)
func isRegularAccount(uid int, shell string) bool {
    return uid >= 1000 && (shell != "/sbin/nologin" && shell != "/usr/sbin/nologin")
}

// isSuspiciousAccount flags potential regular users with system UIDs or accounts without login shells
func isSuspiciousAccount(uid int, shell string) bool {
    return uid < 1000 && (shell == "/bin/bash" || shell == "/bin/sh" || shell == "/bin/zsh")
}
