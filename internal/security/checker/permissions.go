// internal/security/checker/permissions.go
package checker

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    // "syscall"
    "github.com/papa0four/cpscan/internal/security/types"
)

// PermissionChecker defines interface for permission checking
type PermissionChecker interface {
    Check() types.AuditResult
}

// UnixPermissionChecker implements PermissionChecker for Unix-like systems
type UnixPermissionChecker struct {
    Paths []string
    osType string
}

// WindowsPermissionChecker implements PermissionChecker for Windows systems
type WindowsPermissionChecker struct {
    Paths []string
}

// criticalPath represents a path that needs permission checking
type criticalPath struct {
    path        string
    description string
    expected    os.FileMode
    recursive   bool
}

// NewUnixPermissionChecker creates a new Unix permission checker
func NewUnixPermissionChecker() *UnixPermissionChecker {
    checker := &UnixPermissionChecker{
        osType: runtime.GOOS,
    }
    
    // Set default critical paths based on OS
    checker.Paths = getDefaultCriticalPaths(checker.osType)
    return checker
}

// NewWindowsPermissionChecker creates a new Windows permission checker
func NewWindowsPermissionChecker() *WindowsPermissionChecker {
    return &WindowsPermissionChecker{
        Paths: []string{
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\ProgramData",
            "C:\\Users",
        },
    }
}

func getDefaultCriticalPaths(osType string) []string {
    commonPaths := []string{
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh",
        "/var/log",
        "/var/run",
        "/var/tmp",
        "/tmp",
        "/home",
    }

    switch osType {
    case "darwin":
        return append(commonPaths,
            "/System",
            "/Library/Preferences",
            "/private/etc",
            "/private/var",
            "/usr/local/bin",
            "/Applications",
        )
    case "freebsd", "openbsd":
        return append(commonPaths,
            "/boot",
            "/root",
            "/usr/local/etc",
            "/usr/local/sbin",
            "/var/db/pkg",
        )
    default: // Linux
        return append(commonPaths,
            "/boot",
            "/root",
            "/usr/bin",
            "/usr/sbin",
            "/var/spool/cron",
            "/proc",
            "/sys",
            "/dev",
        )
    }
}

// Check implements PermissionChecker interface for Unix systems
func (p *UnixPermissionChecker) Check() types.AuditResult {
    result := types.AuditResult{
        Name:        "File Permissions Security",
        Status:      "CHECKING",
        Description: "Analyzing file and directory permissions",
        Details:     make([]string, 0),
    }

    // Get critical paths with expected permissions
    criticalPaths := p.getCriticalPathConfigs()

    for _, cp := range criticalPaths {
        if err := p.checkPathPermissions(cp, &result); err != nil {
            result.Details = append(result.Details,
                fmt.Sprintf("%s Error checking %s: %v", 
                    types.SymbolError, cp.path, err))
        }
    }

    // Check SUID/SGID files
    p.checkSUIDFiles(&result)

    // Check world-writable files
    p.checkWorldWritableFiles(&result)

    // Check unowned files
    p.checkUnownedFiles(&result)

    result.Status = "COMPLETED"
    return result
}

func (p *UnixPermissionChecker) getCriticalPathConfigs() []criticalPath {
    configs := []criticalPath{
        {"/etc/passwd", "Password file", 0644, false},
        {"/etc/shadow", "Shadow password file", 0400, false},
        {"/etc/group", "Group file", 0644, false},
        {"/etc/sudoers", "Sudo configuration", 0440, false},
        {"/etc/ssh/sshd_config", "SSH daemon configuration", 0600, false},
        {"/var/log", "Log directory", 0755, true},
        {"/home", "User home directories", 0755, true},
    }

    // Add OS-specific paths
    switch p.osType {
    case "darwin":
        configs = append(configs,
            criticalPath{"/private/etc", "System configuration directory", 0755, true},
            criticalPath{"/System", "System directory", 0755, true},
            criticalPath{"/usr/local/bin", "User-installed binaries", 0755, true},
        )
    case "freebsd", "openbsd":
        configs = append(configs,
            criticalPath{"/boot", "Boot directory", 0755, false},
            criticalPath{"/root", "Root user directory", 0700, false},
            criticalPath{"/usr/local/etc", "Local configuration", 0755, true},
        )
    default: // Linux
        configs = append(configs,
            criticalPath{"/boot", "Boot directory", 0755, false},
            criticalPath{"/root", "Root user directory", 0700, false},
            criticalPath{"/proc", "Process information", 0555, false},
            criticalPath{"/sys", "System information", 0555, false},
        )
    }

    return configs
}

func (p *UnixPermissionChecker) checkPathPermissions(cp criticalPath, result *types.AuditResult) error {
    info, err := os.Stat(cp.path)
    if err != nil {
        if os.IsNotExist(err) {
            result.Details = append(result.Details,
                fmt.Sprintf("%s Path does not exist: %s", types.SymbolInfo, cp.path))
            return nil
        }
        return err
    }

    mode := info.Mode()
    if mode.Perm() > cp.expected {
        result.Details = append(result.Details,
            fmt.Sprintf("%s WARNING: %s (%s) has permissions %v, expected %v",
                types.SymbolWarning, cp.path, cp.description, mode.Perm(), cp.expected))
    } else {
        result.Details = append(result.Details,
            fmt.Sprintf("%s %s has correct permissions: %v",
                types.SymbolOK, cp.path, mode.Perm()))
    }

    if cp.recursive && info.IsDir() {
        return filepath.Walk(cp.path, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return nil // Skip files we can't access
            }

            mode := info.Mode()
            if mode&0002 != 0 { // World-writable
                result.Details = append(result.Details,
                    fmt.Sprintf("%s WARNING: %s is world-writable: %v",
                        types.SymbolWarning, path, mode.Perm()))
            }
            return nil
        })
    }

    return nil
}

func (p *UnixPermissionChecker) checkSUIDFiles(result *types.AuditResult) {
    cmd := exec.Command("find", "/",
        "-type", "f",
        "-perm", "-4000", // SUID
        "-o", "-perm", "-2000", // SGID
    )

    output, err := cmd.CombinedOutput()
    if err != nil {
        result.Details = append(result.Details,
            fmt.Sprintf("%s Error checking SUID/SGID files: %v", types.SymbolError, err))
        return
    }

    suidFiles := strings.Split(string(output), "\n")
    if len(suidFiles) > 0 {
        result.Details = append(result.Details, "\nSUID/SGID Files Found:")
        for _, file := range suidFiles {
            if file = strings.TrimSpace(file); file != "" {
                result.Details = append(result.Details,
                    fmt.Sprintf("%s %s", types.SymbolWarning, file))
            }
        }
    }
}

func (p *UnixPermissionChecker) checkWorldWritableFiles(result *types.AuditResult) {
    cmd := exec.Command("find", "/",
        "-type", "f",
        "-perm", "-0002",
        "-not", "-type", "l",
        "-ls")

    output, err := cmd.CombinedOutput()
    if err != nil {
        result.Details = append(result.Details,
            fmt.Sprintf("%s Error checking world-writable files: %v", types.SymbolError, err))
        return
    }

    wwFiles := strings.Split(string(output), "\n")
    if len(wwFiles) > 0 {
        result.Details = append(result.Details, "\nWorld-Writable Files Found:")
        for _, file := range wwFiles {
            if file = strings.TrimSpace(file); file != "" {
                result.Details = append(result.Details,
                    fmt.Sprintf("%s %s", types.SymbolWarning, file))
            }
        }
    }
}

func (p *UnixPermissionChecker) checkUnownedFiles(result *types.AuditResult) {
    cmd := exec.Command("find", "/",
        "-nouser", "-o", "-nogroup",
        "-ls")

    output, err := cmd.CombinedOutput()
    if err != nil {
        result.Details = append(result.Details,
            fmt.Sprintf("%s Error checking unowned files: %v", types.SymbolError, err))
        return
    }

    unownedFiles := strings.Split(string(output), "\n")
    if len(unownedFiles) > 0 {
        result.Details = append(result.Details, "\nUnowned Files Found:")
        for _, file := range unownedFiles {
            if file = strings.TrimSpace(file); file != "" {
                result.Details = append(result.Details,
                    fmt.Sprintf("%s %s", types.SymbolWarning, file))
            }
        }
    }
}

// Check implements PermissionChecker interface for Windows systems
func (p *WindowsPermissionChecker) Check() types.AuditResult {
    result := types.AuditResult{
        Name:        "Windows File Permissions Security",
        Status:      "CHECKING",
        Description: "Analyzing Windows file and directory permissions",
        Details:     make([]string, 0),
    }

    for _, path := range p.Paths {
        if err := p.checkWindowsPermissions(path, &result); err != nil {
            result.Details = append(result.Details,
                fmt.Sprintf("%s Error checking %s: %v",
                    types.SymbolError, path, err))
        }
    }

    // Check for potentially insecure shares
    p.checkNetworkShares(&result)

    result.Status = "COMPLETED"
    return result
}

func (p *WindowsPermissionChecker) checkWindowsPermissions(path string, result *types.AuditResult) error {
    cmd := exec.Command("icacls", path)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("failed to check permissions: %v", err)
    }

    // Analyze permissions
    lines := strings.Split(string(output), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        // Check for potentially dangerous permissions
        if strings.Contains(line, "Everyone:(OI)(CI)(F)") ||
           strings.Contains(line, "Everyone:(F)") {
            result.Details = append(result.Details,
                fmt.Sprintf("%s WARNING: Full control granted to Everyone group on %s",
                    types.SymbolWarning, line))
        } else if strings.Contains(line, "Users:(OI)(CI)(F)") ||
                  strings.Contains(line, "Users:(F)") {
            result.Details = append(result.Details,
                fmt.Sprintf("%s WARNING: Full control granted to Users group on %s",
                    types.SymbolWarning, line))
        } else {
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolInfo, line))
        }
    }

    return nil
}

func (p *WindowsPermissionChecker) checkNetworkShares(result *types.AuditResult) {
    cmd := exec.Command("net", "share")
    output, err := cmd.CombinedOutput()
    if err != nil {
        result.Details = append(result.Details,
            fmt.Sprintf("%s Error checking network shares: %v",
                types.SymbolError, err))
        return
    }

    shares := strings.Split(string(output), "\n")
    result.Details = append(result.Details, "\nNetwork Shares:")
    
    for _, share := range shares {
        share = strings.TrimSpace(share)
        if share == "" || strings.HasPrefix(share, "Share name") ||
           strings.HasPrefix(share, "---") {
            continue
        }

        // Check share permissions
        shareName := strings.Fields(share)[0]
        if shareName == "ADMIN$" || shareName == "C$" || shareName == "IPC$" {
            result.Details = append(result.Details,
                fmt.Sprintf("%s Administrative share: %s",
                    types.SymbolWarning, share))
        } else {
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolInfo, share))
        }
    }
}