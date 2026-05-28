// internal/security/checker/permissions.go
package checker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// Expected file and directory permission modes
const (
	permStandardFile   os.FileMode = 0644
	permOwnerReadOnly  os.FileMode = 0400
	permSudoers        os.FileMode = 0440
	permOwnerReadWrite os.FileMode = 0600
	permStandardDir    os.FileMode = 0755
	permPrivateDir     os.FileMode = 0700
	permReadOnlyDir    os.FileMode = 0555
)

// Permission bit masks
const (
	bitWorldWritable os.FileMode = 0002
)

// find command permission arguments
const (
	findPermSUID          = "-4000"
	findPermSGID          = "-2000"
	findPermWorldWritable = "-0002"
)

// PermissionChecker defines interface for permission checking
type PermissionChecker interface {
	Check() types.AuditResult
}

// UnixPermissionChecker implements PermissionChecker for Unix-like systems
type UnixPermissionChecker struct {
	paths  []criticalPath
	osType string
}

// WindowsPermissionChecker implements PermissionChecker for Windows systems
type WindowsPermissionChecker struct {
	Paths []string
	ctx   registry.OSContext
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
	checker.paths = checker.getCriticalPathConfigs()
	return checker
}

// NewWindowsPermissionChecker creates a new Windows permission checker
func NewWindowsPermissionChecker(ctx registry.OSContext) *WindowsPermissionChecker {
	return &WindowsPermissionChecker{
		Paths: []string{
			"C:\\Windows\\System32",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
			"C:\\ProgramData",
			"C:\\Users",
		},
		ctx: ctx,
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

	for _, cpath := range p.paths {
		if err := p.checkPathPermissions(cpath, &result); err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Error checking %s: %v",
					types.SymbolError, cpath.path, err))
		}
	}

	p.checkSUIDFiles(&result)
	p.checkWorldWritableFiles(&result)
	p.checkUnownedFiles(&result)

	result.Status = "COMPLETED"
	return result
}

func (p *UnixPermissionChecker) getCriticalPathConfigs() []criticalPath {
	configs := []criticalPath{
		{"/etc/passwd", "Password file", permStandardFile, false},
		{"/etc/shadow", "Shadow password file", permOwnerReadOnly, false},
		{"/etc/group", "Group file", permStandardFile, false},
		{"/etc/sudoers", "Sudo configuration", permSudoers, false},
		{"/etc/ssh/sshd_config", "SSH daemon configuration", permOwnerReadWrite, false},
		{"/var/log", "Log directory", permStandardDir, true},
		{"/home", "User home directories", permStandardDir, true},
	}

	// Add OS-specific paths
	switch p.osType {
	case "darwin":
		configs = append(configs,
			criticalPath{"/private/etc", "System configuration directory", permStandardDir, true},
			criticalPath{"/System", "System directory", permStandardDir, true},
			criticalPath{"/usr/local/bin", "User-installed binaries", permStandardDir, true},
		)
	case "freebsd", "openbsd":
		configs = append(configs,
			criticalPath{"/boot", "Boot directory", permStandardDir, false},
			criticalPath{"/root", "Root user directory", permPrivateDir, false},
			criticalPath{"/usr/local/etc", "Local configuration", permStandardDir, true},
		)
	default: // Linux
		configs = append(configs,
			criticalPath{"/boot", "Boot directory", permStandardDir, false},
			criticalPath{"/root", "Root user directory", permPrivateDir, false},
			criticalPath{"/proc", "Process information", permReadOnlyDir, false},
			criticalPath{"/sys", "System information", permReadOnlyDir, false},
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
			if mode&bitWorldWritable != 0 { // World-writable
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
		"-perm", findPermSUID, // SUID
		"-o", "-perm", findPermSGID, // SGID
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
		"-perm", findPermWorldWritable,
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
		Findings:    make([]types.Finding, 0),
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
	cmd := exec.Command("icacls", path) // #nosec G204 -- path sourced from hardcoded Windows system directory list, not user input
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check permissions: %v", err)
	}

	everyoneFindingAdded := false
	usersFindingAdded := false

	// Analyze permissions
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "Everyone:(OI)(CI)(F)") ||
			strings.Contains(line, "Everyone:(F)") {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Full control granted to Everyone group on %s",
					types.SymbolWarning, line))
			if !everyoneFindingAdded {
				if def, ok := registry.Lookup(p.ctx, "permissions.everyone_full_control"); ok {
					result.Findings = append(result.Findings, types.Finding{
						Title:       def.Title,
						Severity:    def.Severity,
						Description: def.Description,
						Impact:      def.Impact,
						Resolution:  def.Resolution,
					})
				}
				everyoneFindingAdded = true
			}
		} else if strings.Contains(line, "Users:(OI)(CI)(F)") ||
			strings.Contains(line, "Users:(F)") {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Full control granted to Users group on %s",
					types.SymbolWarning, line))
			if !usersFindingAdded {
				if def, ok := registry.Lookup(p.ctx, "permissions.users_full_control"); ok {
					result.Findings = append(result.Findings, types.Finding{
						Title:       def.Title,
						Severity:    def.Severity,
						Description: def.Description,
						Impact:      def.Impact,
						Resolution:  def.Resolution,
					})
				}
				usersFindingAdded = true
			}
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

	adminShareFindingAdded := false

	for _, share := range shares {
		share = strings.TrimSpace(share)
		if share == "" || strings.HasPrefix(share, "Share name") ||
			strings.HasPrefix(share, "---") {
			continue
		}

		shareName := strings.Fields(share)[0]
		if shareName == "ADMIN$" || shareName == "C$" || shareName == "IPC$" {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Administrative share: %s",
					types.SymbolWarning, share))
			if !adminShareFindingAdded {
				if def, ok := registry.Lookup(p.ctx, "permissions.admin_share_present"); ok {
					result.Findings = append(result.Findings, types.Finding{
						Title:       def.Title,
						Severity:    def.Severity,
						Description: def.Description,
						Impact:      def.Impact,
						Resolution:  def.Resolution,
					})
				}
				adminShareFindingAdded = true
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolInfo, share))
		}
	}
}
