// internal/security/checker/users.go
package checker

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/types"
)

// UserChecker defines interface for user account checking
type UserChecker interface {
	Check() types.AuditResult
}

// platformConfig holds OS-specific configuration for user checking
type platformConfig struct {
	userSources []string
	minUID      int
}

// UnixUserChecker implements UserChecker for Unix-like systems
type UnixUserChecker struct {
	config platformConfig
	osType string
}

// WindowsUserChecker implements UserChecker for Windows systems
type WindowsUserChecker struct{}

// userAccount represents a parsed user account
type userAccount struct {
	username   string
	uid        int
	gid        int
	homeDir    string
	shell      string
	isSystem   bool
	isLocked   bool
	isAdmin    bool
	isDisabled bool
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
		}
	default: // Linux
		return platformConfig{
			userSources: []string{
				"/etc/passwd",
				"/etc/shadow",
				"/etc/security/passwd",
				"/etc/security/opasswd",
				"/etc/gshadow",
			},
			minUID: 1000,
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
		Name:        "User Account Security",
		Status:      "CHECKING",
		Description: fmt.Sprintf("Analyzing user accounts on %s", u.osType),
		Details:     make([]string, 0),
	}

	result.Details = append(result.Details, u.checkAuthConfig()...)

	users, err := u.getUsers()
	if err != nil {
		result.Status = "ERROR"
		result.Description = fmt.Sprintf("Failed to analyze users: %v", err)
		return result
	}

	u.analyzeUsers(users, &result)
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

	cmd := exec.Command("dscl", ".", "list", "/Users")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get macOS users: %v", err)
	}

	adminUsers := make(map[string]bool)
	adminCmd := exec.Command("dscacheutil", "-q", "group", "-a", "name", "admin")
	if adminOutput, err := adminCmd.CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(adminOutput), "\n") {
			if strings.HasPrefix(line, "users:") {
				members := strings.TrimPrefix(line, "users:")
				for _, user := range strings.Fields(members) {
					adminUsers[user] = true
				}
			}
		}
	}

	for _, username := range strings.Split(string(output), "\n") {
		username = strings.TrimSpace(username)
		if username == "" || username[0] == '_' {
			continue
		}

		if !isSafeUsername(username) {
			continue
		}

		infoCmd := exec.Command("dscl", ".", "read", "/Users/"+username, // #nosec G204 -- username validated by isSafeUsername before use
			"UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell")
		infoOutput, err := infoCmd.CombinedOutput()
		if err != nil {
			continue
		}

		account := userAccount{username: username}

		for _, line := range strings.Split(string(infoOutput), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			switch fields[0] {
			case "UniqueID:":
				if uid, err := strconv.Atoi(fields[1]); err == nil {
					account.uid = uid
				}
			case "PrimaryGroupID:":
				if gid, err := strconv.Atoi(fields[1]); err == nil {
					account.gid = gid
				}
			case "NFSHomeDirectory:":
				account.homeDir = fields[1]
			case "UserShell:":
				account.shell = fields[1]
			}
		}

		account.isSystem = account.uid < u.config.minUID
		account.isAdmin = adminUsers[username]

		if !isSafeUsername(username) {
			continue
		}

		authCmd := exec.Command("dscl", ".", "read", "/Users/"+username, "AuthenticationAuthority") // #nosec G204 -- username validated by isSafeUsername before use
		authOutput, err := authCmd.CombinedOutput()
		if err != nil {
			account.isDisabled = strings.Contains(string(authOutput), "DisabledUser")
		}
		account.isDisabled = strings.Contains(string(authOutput), "DisabledUser")

		users = append(users, account)
	}

	return users, nil
}

func (u *UnixUserChecker) getBSDUsers() ([]userAccount, error) {
	var users []userAccount

	if u.osType == "openbsd" {
		// pwd_mkdb consistency check — failure is non-fatal, read proceeds regardless
		if err := exec.Command("pwd_mkdb", "-c", "/etc/master.passwd").Run(); err != nil {
			// non-fatal: continue regardless of outcome
			_ = err
		}
	}

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close() // nolint:errcheck // read-only passwd file; close error does not affect scan results

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

		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}

		account := userAccount{
			username: fields[0],
			uid:      uid,
			gid:      gid,
			homeDir:  fields[5],
			shell:    fields[6],
			isSystem: uid < u.config.minUID,
		}

		if !isSafeUsername(account.username) {
			continue
		}

		groupCmd := exec.Command("id", "-Gn", account.username) // #nosec G204 -- username validated by isSafeUsername before use
		if output, err := groupCmd.CombinedOutput(); err == nil {
			for _, group := range strings.Fields(string(output)) {
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

	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer passwdFile.Close() // nolint:errcheck // read-only passwd file; close error does not affect scan results

	shadowEntries := make(map[string]string)
	if shadow, err := os.Open("/etc/shadow"); err == nil {
		defer shadow.Close() // nolint:errcheck // read-only shadow file; close error does not affect scan results
		scanner := bufio.NewScanner(shadow)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= 2 {
				shadowEntries[fields[0]] = fields[1]
			}
		}
	}

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

		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}

		account := userAccount{
			username: fields[0],
			uid:      uid,
			gid:      gid,
			homeDir:  fields[5],
			shell:    fields[6],
			isSystem: uid < u.config.minUID,
			isAdmin:  sudoers[fields[0]],
		}

		if shadowEntry, exists := shadowEntries[account.username]; exists {
			account.isLocked = strings.HasPrefix(shadowEntry, "!") ||
				strings.HasPrefix(shadowEntry, "*")
		}

		users = append(users, account)
	}

	return users, nil
}

func (u *UnixUserChecker) analyzeUsers(users []userAccount, result *types.AuditResult) {
	var (
		regularUsers    []string
		adminUsers      []string
		suspiciousUsers []string
	)

	for _, user := range users {
		details := fmt.Sprintf("%s (UID: %d, Shell: %s)", user.username, user.uid, user.shell)

		if user.isAdmin {
			adminUsers = append(adminUsers, details)
		} else if isSuspiciousUser(user) {
			suspiciousUsers = append(suspiciousUsers, details)
		} else if !user.isSystem {
			regularUsers = append(regularUsers, details)
		}

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
	if _, err := os.Stat("/etc/pam.d"); err == nil {
		details = append(details,
			fmt.Sprintf("%s PAM authentication is configured", types.SymbolInfo))

		// Use os.DirFS to scope file reads to /etc/pam.d,
		// preventing symlink TOCTOU traversal (CWE-367)
		pamFS := os.DirFS("/etc/pam.d")

		for _, module := range []string{"pam_unix.so", "pam_ldap.so", "pam_sss.so"} {
			found := false
			if err := fs.WalkDir(pamFS, ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					return nil
				}
				data, err := fs.ReadFile(pamFS, path)
				if err != nil {
					return nil
				}
				if strings.Contains(string(data), module) {
					found = true
					return fs.SkipAll
				}
				return nil
			}); err != nil {
				details = append(details,
					fmt.Sprintf("%s Could not scan PAM configuration: %v",
						types.SymbolInfo, err))
			}
			if found {
				details = append(details,
					fmt.Sprintf("%s Found authentication module: %s",
						types.SymbolInfo, module))
			}
		}
	}

	if _, err := os.Stat("/etc/ldap.conf"); err == nil {
		details = append(details,
			fmt.Sprintf("%s LDAP authentication is configured", types.SymbolWarning))
	}

	if _, err := os.Stat("/etc/krb5.conf"); err == nil {
		details = append(details,
			fmt.Sprintf("%s Kerberos authentication is configured", types.SymbolWarning))
	}

	if _, err := os.Stat("/etc/sssd/sssd.conf"); err == nil {
		details = append(details,
			fmt.Sprintf("%s SSSD authentication is configured", types.SymbolWarning))
	}

	return details
}

func (u *UnixUserChecker) checkSecurityConcerns(result *types.AuditResult) {
	if u.osType != "darwin" {
		if shadow, err := os.Open("/etc/shadow"); err == nil {
			defer shadow.Close() // nolint:errcheck // read-only shadow file; close error does not affect scan results
			scanner := bufio.NewScanner(shadow)
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), ":")
				if len(fields) >= 2 && fields[1] == "" {
					result.Details = append(result.Details,
						fmt.Sprintf("%s CRITICAL: User %s has no password set",
							types.SymbolCritical, fields[0]))
				}
			}
		}

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

	for _, source := range u.config.userSources {
		if file, err := os.Open(source); err == nil { // #nosec G304 -- paths sourced from hardcoded userSources config, not user input
			defer file.Close() //nolint:errcheck // read-only passwd source file; close error does not affect scan results
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), ":")
				if len(fields) >= 3 {
					if uid, err := strconv.Atoi(fields[2]); err == nil && uid == 0 && fields[0] != "root" {
						result.Details = append(result.Details,
							fmt.Sprintf("%s CRITICAL: User %s has UID 0",
								types.SymbolCritical, fields[0]))
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

	users, err := w.getWindowsUsers()
	if err != nil {
		result.Status = "ERROR"
		result.Description = fmt.Sprintf("Failed to get user information: %v", err)
		return result
	}

	w.analyzeWindowsUsers(users, &result)
	w.checkSecurityPolicies(&result)

	result.Status = "COMPLETED"
	return result
}

func (w *WindowsUserChecker) getWindowsUsers() ([]windowsUserInfo, error) {
	var users []windowsUserInfo

	cmd := exec.Command("powershell", "-Command",
		`Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,AccountExpires,Description | ConvertTo-Csv -NoTypeInformation`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	adminCmd := exec.Command("powershell", "-Command",
		`Get-LocalGroupMember -Group "Administrators" | Select-Object Name | ConvertTo-Csv -NoTypeInformation`)
	adminOutput, err := adminCmd.CombinedOutput()
	if err != nil {
		adminOutput = []byte{}
	}
	adminUsers := make(map[string]bool)
	for _, line := range strings.Split(string(adminOutput), "\n") {
		if strings.Contains(line, "\\") {
			parts := strings.Split(line, "\\")
			adminUsers[strings.TrimSpace(parts[len(parts)-1])] = true
		}
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 7 {
			continue
		}

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
			IsAdmin:          adminUsers[fields[0]],
		}

		users = append(users, user)
	}

	return users, nil
}

func (w *WindowsUserChecker) analyzeWindowsUsers(users []windowsUserInfo, result *types.AuditResult) {
	for _, user := range users {
		details := user.Name

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
	cmd := exec.Command("net", "accounts")
	output, err := cmd.CombinedOutput()
	if err == nil {
		result.Details = append(result.Details, "\nPassword Policies:")
		for _, policy := range strings.Split(string(output), "\n") {
			policy = strings.TrimSpace(policy)
			if policy != "" && !strings.HasPrefix(policy, "The command completed") {
				result.Details = append(result.Details,
					fmt.Sprintf("%s %s", types.SymbolInfo, policy))
			}
		}
	}

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

// windowsUserInfo holds parsed Windows user account data
type windowsUserInfo struct {
	Name             string
	Enabled          bool
	PasswordRequired bool
	PasswordLastSet  string
	LastLogon        string
	AccountExpires   string
	Description      string
	IsAdmin          bool
}

func isSuspiciousUser(user userAccount) bool {
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

func isSafeUsername(username string) bool {
	for _, r := range username {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return len(username) > 0
}
