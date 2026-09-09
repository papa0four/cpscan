// internal/security/checker/users.go

package checker

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

const (
	// windowsUserCSVFields is the number of columns produced by Get-LocalUser
	windowsUserCSVFields = 8

	// windowsAdminCSVFields is the number of columns produced by
	// Get-LocalGroupMember
	windowsAdminCSVFields = 1
)

type (
	// UserChecker defines interface for user account checking
	UserChecker interface {
		Name() string
		Description() string
		Check(ctx context.Context) types.AuditResult
	}

	// platformConfig holds OS-specific configuration for user checking
	platformConfig struct {
		userSources []string
		minUID      uint32
	}

	// UnixUserChecker implements UserChecker for Unix-like systems.
	// shadowReadable is set to true when /etc/shadow was successfully opened
	// during getLinuxUsers; it gates the no-password finding and surfaces a
	// diagnostic when the check runs without sufficient privileges.
	UnixUserChecker struct {
		checkIdentity
		config         platformConfig
		osType         string
		shadowReadable bool
	}

	// WindowsUserChecker implements UserChecker for Windows systems.
	// adminLookupErr is set when Administrators group membership could not be
	// read; analyzeWindowsUsers reports the condition rather than presenting
	// every account as non-administrative.
	WindowsUserChecker struct {
		checkIdentity
		adminLookupErr error
	}

	// userAccount represents a parsed user account from /etc/passwd and,
	// where available, /etc/shadow. isSystem is true when the UID falls
	// below the platform minimum for regular user accounts. isLocked is
	// true when the shadow password field begins with ! or *. hasPassword
	// is true when a non-empty, non-placeholder password hash is present
	// in /etc/shadow; false indicates no credential is set.
	userAccount struct {
		username    string
		uid         uint32
		gid         uint32
		homeDir     string
		shell       string
		isSystem    bool
		isLocked    bool
		isAdmin     bool
		isDisabled  bool
		hasPassword bool
	}

	// authConfigResult holds the outcome of auth configuration detection.
	authConfigResult struct {
		Details []string
		Keys    []registry.FindingKey
	}

	// windowsUserInfo holds parsed Windows user account data
	windowsUserInfo struct {
		Name             string
		Enabled          bool
		PasswordRequired bool
		PasswordLastSet  string
		LastLogon        string
		AccountExpires   string
		Description      string
		PrincipalSource  string
		IsAdmin          bool
	}
)

// getPlatformConfig returns the appropriate configuration for the current OS
func getPlatformConfig() platformConfig {
	switch runtime.GOOS {
	case "darwin":
		return platformConfig{
			userSources: []string{
				"/etc/passwd",
				"/var/db/dslocal/nodes/Default/users",
			},
			minUID: minUIDMacOS,
		}
	case "freebsd", "openbsd":
		return platformConfig{
			userSources: []string{
				"/etc/passwd",
				"/etc/master.passwd",
				"/etc/pwd.db",
				"/etc/spwd.db",
			},
			minUID: minUIDDefault,
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
			minUID: minUIDDefault,
		}
	}
}

// NewUnixUserChecker creates a new Unix user checker with OS-specific settings
func NewUnixUserChecker(osCtx registry.OSContext) *UnixUserChecker {
	return &UnixUserChecker{
		checkIdentity: checkIdentity{
			domain:   "User Account Security",
			analyzes: "user accounts and security settings",
			osCtx:    osCtx,
		},
		config: getPlatformConfig(),
		osType: runtime.GOOS,
	}
}

// NewWindowsUserChecker creates a new Windows user checker
func NewWindowsUserChecker(osCtx registry.OSContext) *WindowsUserChecker {
	return &WindowsUserChecker{checkIdentity: checkIdentity{
		domain:   "User Account Security",
		analyzes: "user accounts and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements UserChecker interface for Unix systems
func (u *UnixUserChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        u.Name(),
		Status:      types.StatusChecking,
		Description: u.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	authResult := u.checkAuthConfig()
	result.Details = append(result.Details, authResult.Details...)
	for _, key := range authResult.Keys {
		emitFinding(&result, u.osCtx, key)
	}

	users, err := u.getUsers(ctx)
	if err != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Failed to analyze users: %v", err)
		return result
	}

	u.analyzeUsers(users, &result)
	u.checkSecurityConcerns(ctx, &result)

	result.Status = types.StatusCompleted
	return result
}

// getUsers retrieves user accounts based on OS type
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	switch u.osType {
	case "darwin":
		return u.getMacOSUsers(ctx)
	case "freebsd", "openbsd":
		return u.getBSDUsers(ctx)
	default:
		return u.getLinuxUsers(ctx)
	}
}

func (u *UnixUserChecker) getMacOSUsers(ctx context.Context) ([]userAccount, error) {
	var users []userAccount

	cmd := exec.CommandContext(ctx, "dscl", ".", "list", "/Users")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get macOS users: %v", err)
	}

	adminUsers := make(map[string]bool)
	adminCmd := exec.CommandContext(ctx, "dscacheutil", "-q", "group", "-a", "name", "admin")
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

		infoCmd := exec.CommandContext(ctx, "dscl", ".", "read", "/Users/"+username, // #nosec G204 -- username validated by isSafeUsername before use
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
				if uid, ok := parseUnixID(fields[1]); ok {
					account.uid = uid
				}
			case "PrimaryGroupID:":
				if gid, ok := parseUnixID(fields[1]); ok {
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

		authCmd := exec.CommandContext(ctx, "dscl", ".", "read", "/Users/"+username, "AuthenticationAuthority") // #nosec G204 -- username validated by isSafeUsername before use
		// A dscl failure means the account's disabled state is unknown, not
		// enabled -- leave isDisabled false only when the read succeeded and
		// the DisabledUser marker is genuinely absent.
		if authOutput, err := authCmd.CombinedOutput(); err == nil {
			account.isDisabled = strings.Contains(string(authOutput), "DisabledUser")
		}

		users = append(users, account)
	}

	return users, nil
}

func (u *UnixUserChecker) getBSDUsers(ctx context.Context) ([]userAccount, error) {
	var users []userAccount

	if u.osType == "openbsd" {
		// pwd_mkdb consistency check — failure is non-fatal, read proceeds regardless
		if err := exec.CommandContext(ctx, "pwd_mkdb", "-c", "/etc/master.passwd").Run(); err != nil {
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
		if len(fields) < passwdFieldCount {
			continue
		}

		uid, ok := parseUnixID(fields[passwdFieldUID])
		if !ok {
			continue
		}
		gid, ok := parseUnixID(fields[passwdFieldGID])
		if !ok {
			continue
		}

		account := userAccount{
			username: fields[passwdFieldUsername],
			uid:      uid,
			gid:      gid,
			homeDir:  fields[passwdFieldHomeDir],
			shell:    fields[passwdFieldShell],
			isSystem: uid < u.config.minUID,
		}

		if !isSafeUsername(account.username) {
			continue
		}

		groupCmd := exec.CommandContext(ctx, "id", "-Gn", account.username) // #nosec G204 -- username validated by isSafeUsername before use
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

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /etc/passwd: %w", err)
	}

	return users, nil
}

func (u *UnixUserChecker) getLinuxUsers(ctx context.Context) ([]userAccount, error) {
	var users []userAccount

	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer passwdFile.Close() // nolint:errcheck // read-only passwd file; close error does not affect scan results

	shadowEntries := make(map[string]string)
	if shadow, err := os.Open("/etc/shadow"); err == nil {
		u.shadowReadable = true
		defer shadow.Close() // nolint:errcheck // read-only shadow file; close error does not affect scan results
		scanner := bufio.NewScanner(shadow)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= shadowMinFields {
				shadowEntries[fields[passwdFieldUsername]] = fields[passwdFieldPassword]
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading /etc/shadow: %w", err)
		}
	}

	// Query each privileged group independently so a missing group (e.g. wheel
	// or admin absent on Debian-family systems) does not cause the entire
	// lookup to fail and silently zero out the sudoers map.
	sudoers := make(map[string]bool)
	for _, group := range []string{"sudo", "wheel", "admin"} {
		cmd := exec.CommandContext(ctx, "getent", "group", group) // #nosec G204 -- group names are hardcoded literals, not user input
		if output, err := cmd.CombinedOutput(); err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				if fields := strings.Split(line, ":"); len(fields) >= groupFieldCount {
					for _, member := range strings.Split(fields[groupFieldMembers], ",") {
						if name := strings.TrimSpace(member); name != "" {
							sudoers[name] = true
						}
					}
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
		if len(fields) < passwdFieldCount {
			continue
		}

		uid, ok := parseUnixID(fields[passwdFieldUID])
		if !ok {
			continue
		}
		gid, ok := parseUnixID(fields[passwdFieldGID])
		if !ok {
			continue
		}

		account := userAccount{
			username: fields[passwdFieldUsername],
			uid:      uid,
			gid:      gid,
			homeDir:  fields[passwdFieldHomeDir],
			shell:    fields[passwdFieldShell],
			isSystem: uid < u.config.minUID,
			isAdmin:  sudoers[fields[passwdFieldUsername]],
		}

		if shadowEntry, exists := shadowEntries[account.username]; exists {
			account.isLocked = strings.HasPrefix(shadowEntry, "!") ||
				strings.HasPrefix(shadowEntry, "*")
			// Only set hasPassword when shadow was readable and the entry is
			// a real hash -- not a lock prefix, placeholder, or empty field.
			// When shadow is unreadable the entry will not exist and hasPassword
			// stays false; the no-password finding is suppressed in that case.
			account.hasPassword = shadowEntry != "" &&
				!strings.HasPrefix(shadowEntry, "!") &&
				!strings.HasPrefix(shadowEntry, "*")
		} else {
			// Shadow entry absent -- either shadow is unreadable or the account
			// has no shadow entry. Treat password status as unknown rather than
			// assuming no password is set, to avoid false positives when running
			// without elevated privileges.
			account.hasPassword = true
		}

		users = append(users, account)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /etc/passwd: %w", err)
	}

	return users, nil
}

func (u *UnixUserChecker) analyzeUsers(users []userAccount, result *types.AuditResult) {
	var (
		regularUsers    []string
		adminUsers      []string
		suspiciousUsers []string
	)

	seen := make(map[registry.FindingKey]struct{})
	for _, user := range users {
		details := fmt.Sprintf("%s (UID: %d, Shell: %s)", user.username, user.uid, user.shell)

		if user.isAdmin {
			adminUsers = append(adminUsers, details)
		} else if isSuspiciousUser(user) {
			suspiciousUsers = append(suspiciousUsers, details)
		} else if !user.isSystem {
			regularUsers = append(regularUsers, details)
		}

		// UID 0 on any account other than root is unconditional root equivalence
		// regardless of account name, group membership, or sudo policy.
		if user.uid == rootUID && user.username != "root" {
			result.Details = append(result.Details,
				fmt.Sprintf("%s CRITICAL: Account %s has UID 0 (root-equivalent)",
					types.SymbolCritical, user.username))
			emitFindingOnce(result, u.osCtx, "users.uid_zero_non_root", seen)
		}

		// An account with no password and an interactive shell can be accessed
		// without any credential on systems where empty passwords are permitted.
		if !user.hasPassword && isInteractiveShell(user.shell) && !user.isLocked {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Account %s has no password and an interactive login shell",
					types.SymbolWarning, user.username))
			emitFindingOnce(result, u.osCtx, "users.no_password_login_shell", seen)
		}

		if user.isAdmin && !user.isSystem {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Regular user %s has administrative privileges",
					types.SymbolWarning, user.username))
			emitFindingOnce(result, u.osCtx, "users.regular_user_admin_privileges", seen)
		}

		if isInteractiveShell(user.shell) && !user.isSystem {
			result.Details = append(result.Details,
				fmt.Sprintf("%s User %s has an interactive login shell: %s",
					types.SymbolWarning, user.username, user.shell))
			emitFindingOnce(result, u.osCtx, "users.login_shell_present", seen)
		}
	}

	if !u.shadowReadable {
		result.Details = append(result.Details,
			fmt.Sprintf("%s No-password check skipped: /etc/shadow is not readable without elevated privileges",
				types.SymbolInfo))
	}

	if len(adminUsers) > 0 {
		result.Details = append(result.Details, "", "Administrative Users:")
		for _, user := range adminUsers {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolWarning, user))
		}
	}

	if len(regularUsers) > 0 {
		result.Details = append(result.Details, "", "Regular Users:")
		for _, user := range regularUsers {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolOK, user))
		}
	}

	if len(suspiciousUsers) > 0 {
		result.Details = append(result.Details, "", "Suspicious Users:")
		for _, user := range suspiciousUsers {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolWarning, user))
		}
	}
}

// checkAuthConfig detects authentication mechanisms configured on the system.
func (u *UnixUserChecker) checkAuthConfig() authConfigResult {
	var r authConfigResult

	if _, err := os.Stat("/etc/pam.d"); err == nil {
		r.Details = append(r.Details,
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
				r.Details = append(r.Details,
					fmt.Sprintf("%s Could not scan PAM configuration: %v",
						types.SymbolInfo, err))
			}
			if found {
				r.Details = append(r.Details,
					fmt.Sprintf("%s Found authentication module: %s",
						types.SymbolInfo, module))
			}
		}
	}

	if _, err := os.Stat("/etc/ldap.conf"); err == nil {
		r.Details = append(r.Details,
			fmt.Sprintf("%s LDAP authentication is configured", types.SymbolWarning))
		r.Keys = append(r.Keys, "users.ldap_configured")
	}

	if _, err := os.Stat("/etc/krb5.conf"); err == nil {
		r.Details = append(r.Details,
			fmt.Sprintf("%s Kerberos authentication is configured", types.SymbolWarning))
		r.Keys = append(r.Keys, "users.kerberos_configured")
	}

	if _, err := os.Stat("/etc/sssd/sssd.conf"); err == nil {
		r.Details = append(r.Details,
			fmt.Sprintf("%s SSSD authentication is configured", types.SymbolWarning))
		r.Keys = append(r.Keys, "users.sssd_configured")
	}

	return r
}

func (u *UnixUserChecker) checkSecurityConcerns(ctx context.Context, result *types.AuditResult) {
	if u.osType != "darwin" {
		if shadow, err := os.Open("/etc/shadow"); err == nil {
			defer shadow.Close() // nolint:errcheck // read-only shadow file; close error does not affect scan results
			scanner := bufio.NewScanner(shadow)
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), ":")
				if len(fields) >= shadowMinFields && fields[passwdFieldPassword] == "" {
					result.Details = append(result.Details,
						fmt.Sprintf("%s CRITICAL: User %s has no password set",
							types.SymbolCritical, fields[passwdFieldUsername]))
					emitFinding(result, u.osCtx, "users.empty_password_hash")
				}
			}

			if err := scanner.Err(); err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("%s Error reading shadow file: %v",
						types.SymbolError, err))
			}
		}

		u.checkRootPasswordStatus(ctx, result)
	}

	for _, source := range u.config.userSources {
		if file, err := os.Open(source); err == nil { // #nosec G304 -- paths sourced from hardcoded userSources config, not user input
			defer file.Close() //nolint:errcheck // read-only passwd source file; close error does not affect scan results
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), ":")
				if len(fields) >= passwdMinFieldsForUID {
					uid, ok := parseUnixID(fields[passwdFieldUID])
					if ok && uid == rootUID && fields[passwdFieldUsername] != "root" {
						result.Details = append(result.Details,
							fmt.Sprintf("%s CRITICAL: User %s has UID 0",
								types.SymbolCritical, fields[0]))
						emitFinding(result, u.osCtx, "users.uid_zero_non_root")
					}
				}
			}

			if err := scanner.Err(); err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("%s Error reading %s: %v",
						types.SymbolError, source, err))
			}
		}
	}
}

// checkRootPasswordStatus reports root's password state from passwd -S. The
// status field distinguishes three conditions a substring search cannot: NP
// means no password is set, which is more dangerous than an unlocked account
// rather than safer. A failed query is reported instead of skipped, because
// passwd refuses to disclose root's status to an unprivileged caller, so a
// silent skip would read as a clean result on every unprivileged run.
func (u *UnixUserChecker) checkRootPasswordStatus(ctx context.Context, result *types.AuditResult) {
	out, err := exec.CommandContext(ctx, "passwd", "-S", "root").Output()
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Root password status could not be determined: %v",
				types.SymbolWarning, execError(err)))
		return
	}

	fields := strings.Fields(string(out))
	if len(fields) <= passwdStatusField {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Root password status could not be determined: unexpected passwd -S output",
				types.SymbolWarning))
		return
	}

	switch fields[passwdStatusField] {
	case passwdStatusLocked:
		result.Details = append(result.Details,
			fmt.Sprintf("%s Root account password is locked", types.SymbolOK))
	case passwdStatusNoPassword:
		result.Details = append(result.Details,
			fmt.Sprintf("%s CRITICAL: Root account has no password set", types.SymbolCritical))
		emitFinding(result, u.osCtx, "user.empty_password_hash")
	case passwdStatusUsable:
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: Root account is unlocked", types.SymbolWarning))
		emitFinding(result, u.osCtx, "users.root_account_unlocked")
	default:
		result.Details = append(result.Details,
			fmt.Sprintf("%s Root password status could not be determined: unrecognized status %q",
				types.SymbolWarning, fields[passwdStatusField]))
	}
}

// Check implements UserChecker interface for Windows systems
func (u *WindowsUserChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        u.Name(),
		Status:      types.StatusChecking,
		Description: u.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	users, err := u.getWindowsUsers(ctx)
	if err != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Failed to get user information: %v", err)
		return result
	}

	u.analyzeWindowsUsers(users, &result)
	u.checkSecurityPolicies(ctx, &result)

	result.Status = types.StatusCompleted
	return result
}

func (u *WindowsUserChecker) getWindowsUsers(ctx context.Context) ([]windowsUserInfo, error) {
	psCmd := `Get-LocalUser | ` +
		`Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,AccountExpires,Description,PrincipalSource | ` +
		`ConvertTo-Csv -NoTypeInformation`
	output, err := exec.CommandContext(ctx, "powershell", "-Command", psCmd).Output()
	if err != nil {
		return nil, fmt.Errorf("enumerate local users: %w", execError(err))
	}

	records, err := parsePowershellCSV(output, windowsUserCSVFields)
	if err != nil {
		return nil, fmt.Errorf("enumerate local users: %w", err)
	}

	// A failed membership lookup leaves admins nil, which reads as "no
	// administrators" at every index. analyzeWindowsUsers reports the
	// condition so the run cannot pass that off as a clean result.
	admins, err := u.getWindowsAdmins(ctx)
	if err != nil {
		u.adminLookupErr = err
	}

	users := make([]windowsUserInfo, 0, len(records))
	for _, rec := range records {
		users = append(users, windowsUserInfo{
			Name:             rec[0],
			Enabled:          rec[1] == "True",
			PasswordRequired: rec[2] == "True",
			PasswordLastSet:  rec[3],
			LastLogon:        rec[4],
			AccountExpires:   rec[5],
			Description:      rec[6],
			PrincipalSource:  rec[7],
			IsAdmin:          admins[rec[0]],
		})
	}

	return users, nil
}

// getWindowsAdmins returns local Administrators group membership keyed by bare
// account name. An error means membership could not be determined, which is
// distinct from an empty group, and callers must not report accounts as
// non-administrative on the strength of it.
func (u *WindowsUserChecker) getWindowsAdmins(ctx context.Context) (map[string]bool, error) {
	output, err := exec.CommandContext(ctx, "powershell", "-Command",
		`Get-LocalGroupMember -Group "Administrators" | Select-Object Name | ConvertTo-CSV -NoTypeInformation`).Output()
	if err != nil {
		return nil, execError(err)
	}

	records, err := parsePowershellCSV(output, windowsAdminCSVFields)
	if err != nil {
		return nil, execError(err)
	}

	// Names arrive qualified as SOURCE\account, where SOURCE is the machine,
	// a domain, or AzureAD. An unqualified name is kept as-is rather than
	// dropped, so a member that cannot be split is still counted.
	admins := make(map[string]bool, len(records))
	for _, rec := range records {
		name := rec[0]
		if idx := strings.LastIndex(name, `\`); idx >= 0 {
			name = name[idx+1:]
		}
		if name != "" {
			admins[name] = true
		}
	}

	return admins, nil
}

// passwordlessAccount maps a principal source to the annotation, finding key
// and severity for an account that requires no local password. A source that
// validates credentials off the host explains the missing local hash; a local
// or unrecognized source does not.
//
// Get-LocalUser reports PrincipalSource Local for a Microsoft account signed
// into a local profile, so the MicrosoftAccount case does not fire for that
// configuration and such an account is reported as a local account with no
// password.
func passwordlessAccount(source string) (note string, key registry.FindingKey, severe bool) {
	switch source {
	case "MicrosoftAccount":
		return "Microsoft Account -- no local password hash",
			"users.microsoft_account_no_local_password", false
	case "AzureAD":
		return "Azure AD -- no local password hash",
			"users.azure_ad_account_no_local_password", false
	case "ActiveDirectory":
		return "Active Directory -- no local password hash",
			"users.domain_account_no_local_password", false
	case "Unknown":
		return "Unknown principal source -- no local password hash",
			"users.unknown_principal_no_local_password", true
	default:
		return "No local password required", "users.no_password_required", true
	}
}

func (u *WindowsUserChecker) analyzeWindowsUsers(users []windowsUserInfo, result *types.AuditResult) {
	seen := make(map[registry.FindingKey]struct{})
	for _, user := range users {
		notes := make([]string, 0, 2)
		symbol := types.SymbolOK

		// Administrator membership is independent of whether the account is
		// enabled or requires a local password, so it annotates the entry
		// instead of replacing its other state. The finding is emitted only
		// for enabled members, matching the key's claim that the account is
		// active; a disabled member is still annotated so the membership
		// stays visible.
		if user.IsAdmin {
			notes = append(notes, "Administrator")
			symbol = types.SymbolWarning
			if user.Enabled {
				emitFindingOnce(result, u.osCtx, "users.administrator_account_active", seen)
			}
		}

		switch {
		case !user.Enabled:
			// A disabled account cannot be logged into, so its password state
			// is recorded but not judged.
			notes = append(notes, "Disabled")
			if !user.IsAdmin {
				symbol = types.SymbolInfo
			}
		case !user.PasswordRequired:
			note, key, severe := passwordlessAccount(user.PrincipalSource)
			notes = append(notes, note)
			if severe {
				symbol = types.SymbolWarning
			} else if !user.IsAdmin {
				symbol = types.SymbolInfo
			}
			emitFindingOnce(result, u.osCtx, key, seen)
		}

		details := user.Name
		if len(notes) > 0 {
			details += " (" + strings.Join(notes, ", ") + ")"
		}
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s", symbol, details))
	}

	if u.adminLookupErr != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Administrator membership could not be determined; accounts above are not marked administrative: %v",
				types.SymbolWarning, u.adminLookupErr))
	}
}

func (u *WindowsUserChecker) checkSecurityPolicies(ctx context.Context, result *types.AuditResult) {
	cmd := exec.CommandContext(ctx, "net", "accounts")
	output, err := cmd.CombinedOutput()
	if err == nil {
		result.Details = append(result.Details, "", "Password Policies:")
		for _, policy := range strings.Split(string(output), "\n") {
			policy = strings.TrimSpace(policy)
			if policy != "" && !strings.HasPrefix(policy, "The command completed") {
				result.Details = append(result.Details,
					fmt.Sprintf("%s %s", types.SymbolInfo, policy))
			}
		}
	}

	uacCmd := exec.CommandContext(ctx, "powershell", "-Command",
		`Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA`)
	uacOutput, err := uacCmd.CombinedOutput()
	if err == nil {
		if strings.Contains(string(uacOutput), "1") {
			result.Details = append(result.Details,
				fmt.Sprintf("%s User Account Control (UAC) is enabled", types.SymbolOK))
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: User Account Control (UAC) is disabled", types.SymbolWarning))
			emitFinding(result, u.osCtx, "users.uac_disabled")
		}
	}
}

func isSuspiciousUser(user userAccount) bool {
	return strings.HasPrefix(user.username, ".") ||
		strings.Contains(user.username, "$") ||
		strings.Contains(user.username, "tmp") ||
		strings.Contains(user.username, "temp") ||
		strings.Contains(user.username, "test")
}

// isInteractiveShell reports whether shell allows interactive login. Shells
// that do not appear in the nologin/false/sync family are considered
// interactive regardless of whether they are considered "secure" -- the
// analyst decides whether the assignment is intentional.
func isInteractiveShell(shell string) bool {
	nonInteractive := []string{
		"nologin",
		"/bin/false",
		"/usr/bin/false",
		"/bin/sync",
		"/usr/bin/sync",
		"/sbin/halt",
		"/sbin/shutdown",
	}
	for _, s := range nonInteractive {
		if strings.HasSuffix(shell, s) {
			return false
		}
	}
	// empty shell field defaults to /bin/sh which is interactive
	return true
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
