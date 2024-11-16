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

		fields := stirngs.Split(line, ":")
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
	}
}