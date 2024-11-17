// internal/security/checker/users.go
package checker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"path/filepath"
	"github.com/papa0four/cpscan/internal/security/types"
)

// UserChecker defines interface for user account checking
type UserChecker interface {
	Check() types.AuditResult
}

// platformConfig implements UserChecker for Unix-like systems
type platformConfig struct {
	userSources		[]string
	minUID			int
	systemPaths		[]string
	authSources		[]string
}

// UnixUserChecker implements UserChecker for Unix-like systems
type UnixUserChecker struct {
	config platformConfig
	osType string
}

// WindowsUserChecker implements UserChecker for Windows systems
type WindowsUserChecker struct {}

// userAccount represents a parsed user account
type userAccount struct {
	username	string
	uid			int
	gid			int
	homeDir		string
	shell		string
	isSystem	bool
	isLocked	bool
	isAdmin		bool
	isDisabled	bool
	authMethod	string
}

// getPlatformConfig returns the appropriate configuration for the current OS
func getPlatformConfig() platformConfig {
	switch runtime.GOOS {
	case "darwin":
		return platformConfig{
			userSources: []string{
				"/etc/passwd",
				"/var/db/dslocal/nodes/Default/users",
			},
			minUID: 500,
			systemPaths: []string{
				"/bin", "/sbin", "/usr/bin", "/usr/sbin",
			},
			authSources: []string{
				"/etc/authorization",
				"/etc/pam.d/authorization",
				"/Library/Security/SecurityAgentPlugins",
			},
		}
	case "freebsd", "openbsd":
		return platformConfig{
			userSources: []string{
				"/etc/passwd",
				"/etc/master.passwd",
				"/etc/pwd.db",
				"/etc/spwd.db",
			},
			minUID: 1000,
			systemPaths: []string{
				"/bin", "/sbin", "/usr/bin", "/usr/sbin",
				"/usr/local/bin", "/usr/local/sbin",
			},
			authSources: []string{
				"/etc/login.conf",
				"/etc/auth.conf",
				"/etc/pam.d",
			},
		}
	default: // Linux and others
		return platformConfig{
			userSources: []string{
				"/etc/passwd",
				"/etc/shadow",
				"/etc/security/passwd",
				"/etc/security/opasswd",
				"/etc/gshadow",
			},
			minUID: 1000,
			systemPaths: []string{
				"/bin", "/sbin", "/usr/bin", "/usr/sbin",
				"/usr/local/bin", "/usr/local/sbin",
			},
			authSources: []string{
				"/etc/pam.d",
				"/etc/security/access.conf",
				"/etc/security/limits.conf",
				"/etc/login.defs",
			},
		}
	}
}

// NewUnixUserChecker creates a new Unix user checker with OS-specific settings
func NewUnixUserChecker() *UnixUserChecker {
	return &UnixUserChecker{
		config: getPlatformConfig(),
		osType: runtime.GOOS,
	}
}

// NewWindowsUserChecker creates a new Windows user checker
func NewWindowsUserChecker() *WindowsUserChecker {
	return &WindowsUserChecker{}
}

// Check implements UserChecker interface for Unix systems
func (u *UnixUserChecker) Check() types.AuditResult {
	result := types.AuditResult{
		Name:			"User Account Security",
		Status:			"CHECKING",
		Description:	fmt.Sprintf("Analyzing user accounts on %s", u.osType),
		Details:		make([]string, 0),
	}

	// Check authenticate configuration
	result.Details = append(result.Details, u.checkAuthConfig()...)

	// Get users based on OS type
	users, err := u.getUsers()
	if err != nil {
		result.Status = "ERROR"
		result.Description = fmt.Sprintf("Failed to analyze users: %v", err)
		return result
	}

	// Analyze users
	u.analyzeUsers(users, &result)

	// Check for additional security concerns
	u.checkSecurityConcerns(&result)

	result.Status = "COMPLETED"
	return result
}

// getUsers retrieves user accounts based on OS type
func (u *UnixUserChecker) getUsers() ([]userAccount, error) {
	switch u.osType {
	case "darwin":
		return u.getMacOSUsers()
	case "freebsd", "openbsd":
		return u.getBSDUsers()
	default:
		return u.getLinuxUsers()
	}
}

func (u *UnixUserChecker) getMacOSUsers() ([]userAccount, error) {
	var users []userAccount

	// Use dscl to get user list
	cmd := exec.Command("dscl", ".", "list", "/Users")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get macOS users; %v", err)
	}

	// Get admin group members
	adminUsers := make(map[string]bool)
	adminCmd := exec.Command("dscacheutil", "-q", "group", "-a", "name", "admin")
	if adminOutput, err := adminCmd.CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(adminOutput), "\n") {
			if strings.HasPrefix(line, "users:") {
				users := strings.TrimPrefix(line, "users:")
				for _, user := range strings.Fields(users) {
					adminUsers[user] = true
				}
			}
		}
	}

	// Process each user
	for _, username := range strings.Split(string(output), "\n") {
		username = strings.TrimSpace(username)
		if username == "" || username[0] == '_' {
			continue
		}

		// Get user details
		infoCmd := exec.Command("dscl", ".", "read", "/Users/"+username, "UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell")
		infoOutput, err := infoCmd.CombinedOutput()
		if err != nil {
			continue
		}

		account := userAccount{username: username}

		// Parse user information
		for _, line := range strings.Split(string(infoOutput), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			switch fields[0] {
			case "UniqueID:":
				account.uid, _ = strconv.Atoi(fields[1])
			case "PrimaryGroupID:":
				account.gid, _ = strconv.Atoi(fields[1])
			case "NFSHomeDirectory:":
				account.homeDir = fields[1]
			case "UserShell:":
				account.shell = fields[1]
			}
		}

		account.isSystem = account.uid < u.config.minUID
		account.isAdmin = adminUsers[username]

		// check if account is disabled
		authCmd := exec.Command("dscl", ".", "read", "/Users/"+username, "AuthenticationAuthority")
		authOutput, _ := authCmd.CombinedOutput()
		account.isDisabled = strings.Contains(string(authOutput), "DisabledUser")

		users = append(users, account)
	}

	return users, nil
}

func (u *UnixUserChecker) getBSDUsers() ([]userAccount, error) {
	var users []userAccount

	// Try to use pwd_mkdb -c to check password database consistency
	if u.osType == "openbsd" {
		exec.Command("pwd_mkdb", "-c", "/etc/master.passwd").Run()
	}

	// Read passwd file
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])

		account := userAccount{
			username:	fields[0],
			uid:		uid,
			gid:		gid,
			homeDir:	fields[5],
			shell:		fields[6],
			isSystem: uid < u.config.minUID,
		}

		// check wheel group membership for admin status
		groupCmd := exec.Command("id", "-Gn", account.username)
        if output, err := groupCmd.CombinedOutput(); err == nil {
            groups := strings.Fields(string(output))
            for _, group := range groups {
                if group == "wheel" {
                    account.isAdmin = true
                    break
                }
            }
        }

        users = append(users, account)
    }

    return users, nil
}

func (u *UnixUserChecker) getLinuxUsers() ([]userAccount, error) {
    var users []userAccount
    
    // Read passwd file
    passwdFile, err := os.Open("/etc/passwd")
    if err != nil {
        return nil, err
    }
    defer passwdFile.Close()

    // Read shadow file for password status
    shadowEntries := make(map[string]string)
    if shadow, err := os.Open("/etc/shadow"); err == nil {
        defer shadow.Close()
        scanner := bufio.NewScanner(shadow)
        for scanner.Scan() {
            fields := strings.Split(scanner.Text(), ":")
            if len(fields) >= 2 {
                shadowEntries[fields[0]] = fields[1]
            }
        }
    }

    // Get sudo group members
    sudoers := make(map[string]bool)
    sudoCmd := exec.Command("getent", "group", "sudo", "wheel", "admin")
    if output, err := sudoCmd.CombinedOutput(); err == nil {
        for _, line := range strings.Split(string(output), "\n") {
            if fields := strings.Split(line, ":"); len(fields) >= 4 {
                for _, user := range strings.Split(fields[3], ",") {
                    sudoers[strings.TrimSpace(user)] = true
                }
            }
        }
    }

    scanner := bufio.NewScanner(passwdFile)
    for scanner.Scan() {
        line := scanner.Text()
        if line == "" || line[0] == '#' {
            continue
        }

        fields := strings.Split(line, ":")
        if len(fields) < 7 {
            continue
        }

        uid, _ := strconv.Atoi(fields[2])
        gid, _ := strconv.Atoi(fields[3])

        account := userAccount{
            username: fields[0],
            uid:      uid,
            gid:      gid,
            homeDir:  fields[5],
            shell:    fields[6],
            isSystem: uid < u.config.minUID,
            isAdmin:  sudoers[fields[0]],
        }

        // Check if account is locked
        if shadowEntry, exists := shadowEntries[account.username]; exists {
            account.isLocked = strings.HasPrefix(shadowEntry, "!") || strings.HasPrefix(shadowEntry, "*")
        }

        users = append(users, account)
    }

    return users, nil
}

func (u *UnixUserChecker) analyzeUsers(users []userAccount, result *types.AuditResult) {
    var (
        regularUsers   []string
        adminUsers     []string
        systemUsers    []string
        suspiciousUsers []string
    )

    for _, user := range users {
        details := fmt.Sprintf("%s (UID: %d, Shell: %s)", user.username, user.uid, user.shell)

        if user.isAdmin {
            adminUsers = append(adminUsers, details)
        } else if user.isSystem {
            systemUsers = append(systemUsers, details)
        } else if isSuspiciousUser(user) {
            suspiciousUsers = append(suspiciousUsers, details)
        } else {
            regularUsers = append(regularUsers, details)
        }

        // Check for specific security concerns
        if user.isAdmin && !user.isSystem {
            result.Details = append(result.Details,
                fmt.Sprintf("%s WARNING: Regular user %s has administrative privileges", 
                    types.SymbolWarning, user.username))
        }

        if isWeakShell(user.shell) && !user.isSystem {
            result.Details = append(result.Details,
                fmt.Sprintf("%s WARNING: User %s has a potentially insecure shell: %s", 
                    types.SymbolWarning, user.username, user.shell))
        }
    }

    // Report findings
    if len(adminUsers) > 0 {
        result.Details = append(result.Details, "\nAdministrative Users:")
        for _, user := range adminUsers {
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolWarning, user))
        }
    }

    if len(regularUsers) > 0 {
        result.Details = append(result.Details, "\nRegular Users:")
        for _, user := range regularUsers {
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolOK, user))
        }
    }

    if len(suspiciousUsers) > 0 {
        result.Details = append(result.Details, "\nSuspicious Users:")
        for _, user := range suspiciousUsers {
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolWarning, user))
        }
    }
}

func (u *UnixUserChecker) checkAuthConfig() []string {
    var details []string

    // Check PAM configuration
    if _, err := os.Stat("/etc/pam.d"); err == nil {
        details = append(details, fmt.Sprintf("%s PAM authentication is configured", types.SymbolInfo))
        
        // Check for specific PAM modules
        for _, module := range []string{"pam_unix.so", "pam_ldap.so", "pam_sss.so"} {
            found := false
            filepath.Walk("/etc/pam.d", func(path string, info os.FileInfo, err error) error {
                if err != nil {
                    return nil
                }
                if info.IsDir() {
                    return nil
                }
                if data, err := os.ReadFile(path); err == nil {
                    if strings.Contains(string(data), module) {
                        found = true
                        return filepath.SkipDir
                    }
                }
                return nil
            })
            if found {
                details = append(details, fmt.Sprintf("%s Found authentication module: %s", 
                    types.SymbolInfo, module))
            }
        }
    }

    // Check for LDAP configuration
    // internal/security/checker/users.go (continued...)

    // Check for LDAP configuration
    if _, err := os.Stat("/etc/ldap.conf"); err == nil {
        details = append(details, fmt.Sprintf("%s LDAP authentication is configured", types.SymbolWarning))
    }

    // Check for Kerberos configuration
    if _, err := os.Stat("/etc/krb5.conf"); err == nil {
        details = append(details, fmt.Sprintf("%s Kerberos authentication is configured", types.SymbolWarning))
    }

    // Check for SSSD configuration
    if _, err := os.Stat("/etc/sssd/sssd.conf"); err == nil {
        details = append(details, fmt.Sprintf("%s SSSD authentication is configured", types.SymbolWarning))
    }

    return details
}

func (u *UnixUserChecker) checkSecurityConcerns(result *types.AuditResult) {
    // Check for empty passwords in shadow file
    if u.osType != "darwin" {
        if shadow, err := os.Open("/etc/shadow"); err == nil {
            defer shadow.Close()
            scanner := bufio.NewScanner(shadow)
            for scanner.Scan() {
                fields := strings.Split(scanner.Text(), ":")
                if len(fields) >= 2 && fields[1] == "" {
                    result.Details = append(result.Details,
                        fmt.Sprintf("%s CRITICAL: User %s has no password set", 
                            types.SymbolError, fields[0]))
                }
            }
        }
    }

    // Check root account status
    if u.osType != "darwin" {
        out, err := exec.Command("passwd", "-S", "root").CombinedOutput()
        if err == nil {
            if strings.Contains(string(out), "NP") || strings.Contains(string(out), "L") {
                result.Details = append(result.Details,
                    fmt.Sprintf("%s Root account is locked", types.SymbolOK))
            } else {
                result.Details = append(result.Details,
                    fmt.Sprintf("%s WARNING: Root account is unlocked", types.SymbolWarning))
            }
        }
    }

    // Check for users with UID 0 (other than root)
    for _, source := range u.config.userSources {
        if file, err := os.Open(source); err == nil {
            defer file.Close()
            scanner := bufio.NewScanner(file)
            for scanner.Scan() {
                fields := strings.Split(scanner.Text(), ":")
                if len(fields) >= 3 {
                    if uid, err := strconv.Atoi(fields[2]); err == nil && uid == 0 && fields[0] != "root" {
                        result.Details = append(result.Details,
                            fmt.Sprintf("%s CRITICAL: User %s has UID 0", 
                                types.SymbolError, fields[0]))
                    }
                }
            }
        }
    }
}

// Check implements UserChecker interface for Windows systems
func (w *WindowsUserChecker) Check() types.AuditResult {
    result := types.AuditResult{
        Name:        "Windows User Account Security",
        Status:      "CHECKING",
        Description: "Analyzing Windows user accounts and security settings",
        Details:     make([]string, 0),
    }

    // Get detailed user information
    users, err := w.getWindowsUsers()
    if err != nil {
        result.Status = "ERROR"
        result.Description = fmt.Sprintf("Failed to get user information: %v", err)
        return result
    }

    // Analyze users
    w.analyzeWindowsUsers(users, &result)

    // Check security policies
    w.checkSecurityPolicies(&result)

    result.Status = "COMPLETED"
    return result
}

func (w *WindowsUserChecker) getWindowsUsers() ([]windowsUserInfo, error) {
    var users []windowsUserInfo

    // Get user list using PowerShell
    cmd := exec.Command("powershell", "-Command",
        `Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,AccountExpires,Description | ConvertTo-Csv -NoTypeInformation`)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return nil, err
    }

    // Get administrator group members
    adminCmd := exec.Command("powershell", "-Command",
        `Get-LocalGroupMember -Group "Administrators" | Select-Object Name | ConvertTo-Csv -NoTypeInformation`)
    adminOutput, _ := adminCmd.CombinedOutput()
    adminUsers := make(map[string]bool)
    for _, line := range strings.Split(string(adminOutput), "\n") {
        if strings.Contains(line, "\\") {
            parts := strings.Split(line, "\\")
            adminUsers[strings.TrimSpace(parts[len(parts)-1])] = true
        }
    }

    // Parse user information
    lines := strings.Split(string(output), "\n")
    for i, line := range lines {
        if i == 0 || strings.TrimSpace(line) == "" { // Skip header and empty lines
            continue
        }

        fields := strings.Split(line, ",")
        if len(fields) < 7 {
            continue
        }

        // Remove quotes from fields
        for i := range fields {
            fields[i] = strings.Trim(fields[i], `"`)
        }

        user := windowsUserInfo{
            Name:             fields[0],
            Enabled:          fields[1] == "True",
            PasswordRequired: fields[2] == "True",
            PasswordLastSet:  fields[3],
            LastLogon:        fields[4],
            AccountExpires:   fields[5],
            Description:      fields[6],
            IsAdmin:         adminUsers[fields[0]],
        }

        users = append(users, user)
    }

    return users, nil
}

func (w *WindowsUserChecker) analyzeWindowsUsers(users []windowsUserInfo, result *types.AuditResult) {
    for _, user := range users {
        details := fmt.Sprintf("%s", user.Name)
        
        if user.IsAdmin {
            details += " (Administrator)"
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolWarning, details))
        } else if !user.Enabled {
            details += " (Disabled)"
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolInfo, details))
        } else if !user.PasswordRequired {
            details += " (No Password Required)"
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolWarning, details))
        } else {
            result.Details = append(result.Details,
                fmt.Sprintf("%s %s", types.SymbolOK, details))
        }
    }
}

func (w *WindowsUserChecker) checkSecurityPolicies(result *types.AuditResult) {
    // Check password policies
    cmd := exec.Command("net", "accounts")
    output, err := cmd.CombinedOutput()
    if err == nil {
        result.Details = append(result.Details, "\nPassword Policies:")
        policies := strings.Split(string(output), "\n")
        for _, policy := range policies {
            policy = strings.TrimSpace(policy)
            if policy != "" && !strings.HasPrefix(policy, "The command completed") {
                result.Details = append(result.Details,
                    fmt.Sprintf("%s %s", types.SymbolInfo, policy))
            }
        }
    }

    // Check UAC status
    uacCmd := exec.Command("powershell", "-Command",
        `Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA`)
    uacOutput, err := uacCmd.CombinedOutput()
    if err == nil {
        if strings.Contains(string(uacOutput), "1") {
            result.Details = append(result.Details,
                fmt.Sprintf("%s User Account Control (UAC) is enabled", types.SymbolOK))
        } else {
            result.Details = append(result.Details,
                fmt.Sprintf("%s WARNING: User Account Control (UAC) is disabled", types.SymbolWarning))
        }
    }
}

// Helper types and functions

type windowsUserInfo struct {
    Name             string
    Enabled          bool
    PasswordRequired bool
    PasswordLastSet  string
    LastLogon        string
    AccountExpires   string
    Description      string
    IsAdmin         bool
}

func isSuspiciousUser(user userAccount) bool {
    // Check for suspicious patterns in username
    return strings.HasPrefix(user.username, ".") ||
           strings.Contains(user.username, "$") ||
           strings.Contains(user.username, "tmp") ||
           strings.Contains(user.username, "temp") ||
           strings.Contains(user.username, "test")
}

func isWeakShell(shell string) bool {
    weakShells := []string{
        "/bin/sh",
        "/usr/bin/sh",
        "/bin/bash",
        "/usr/bin/bash",
        "cmd.exe",
        "powershell.exe",
    }
    
    for _, weakShell := range weakShells {
        if strings.HasSuffix(shell, weakShell) {
            return true
        }
    }
    return false
}