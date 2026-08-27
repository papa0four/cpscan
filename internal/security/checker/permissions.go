// internal/security/checker/permissions.go
package checker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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

	// Permission bit masks
	bitWorldWritable os.FileMode = 0002

	// find command permission arguments
	findPermSUID          = "-4000"
	findPermSGID          = "-2000"
	findPermWorldWritable = "-0002"

	// findScanTimeout bounds each FS-wide find operation to prevent audit hang
	findScanTimeout = 60 * time.Second
)

type (
	// PermissionChecker defines interface for permission checking. Check
	// honors ctx cancellation: exec invocations and filesystem walks stop
	// when the caller's deadline expires.
	PermissionChecker interface {
		Name() string
		Description() string
		Check(ctx context.Context) types.AuditResult
	}

	// UnixPermissionChecker implements PermissionChecker for Unix-like systems
	UnixPermissionChecker struct {
		checkIdentity
		paths    []criticalPath
		osType   string
		scanRoot string
	}

	// WindowsPermissionChecker implements PermissionChecker for Windows systems
	WindowsPermissionChecker struct {
		checkIdentity
		Paths    []string
		scanRoot string
	}

	// criticalPath represents a path that needs permission checking
	criticalPath struct {
		path        string
		description string
		expected    os.FileMode
		recursive   bool
	}
)

// countUnreadablePaths counts the paths find could not read, i.e. permission denied
func countUnreadablePaths(stderr []byte) int {
	if len(stderr) == 0 {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.Contains(line, "Permission denied") {
			count++
		}
	}
	return count
}

// runBoundedFind executes find rooted at "/" and is bounded by findScanTimeout
func runBoundedFind(ctx context.Context, root string, args []string) (output []byte, skipped int, err error) {
	ctx, cancel := context.WithTimeout(ctx, findScanTimeout)
	defer cancel()

	full := append([]string{root, "-xdev"}, args...)
	cmd := exec.CommandContext(ctx, "find", full...) // #nosec G204 -- root validated by caller; predicate args sourced from hardcoded permission constants

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, 0, fmt.Errorf("find timed out after %s", findScanTimeout)
	}

	// ExitError means find ran and exited non-zero; this is okay
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return nil, 0, runErr
	}

	return stdout.Bytes(), countUnreadablePaths(stderr.Bytes()), nil
}

// nonEmptyLines splits find output into clean line-by-line output
func nonEmptyLines(output []byte) []string {
	raw := strings.Split(string(output), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// appendSkippedNote annotates the number of paths find could not read
func appendSkippedNote(result *types.AuditResult, scan string, skipped int) {
	if skipped <= 0 {
		return
	}
	result.Details = append(result.Details,
		fmt.Sprintf("%s %s: %d unreadable paths skipped (run with elevated privileges for complete coverage)",
			types.SymbolInfo, scan, skipped))
}

// NewUnixPermissionChecker creates a new Unix permission checker
func NewUnixPermissionChecker(osCtx registry.OSContext, scanRoot string) *UnixPermissionChecker {
	checker := &UnixPermissionChecker{
		checkIdentity: checkIdentity{
			domain:   "File Permissions Security",
			analyzes: "file and directory permissions",
			osCtx:    osCtx,
		},
		osType:   runtime.GOOS,
		scanRoot: scanRoot,
	}

	// Set default critical paths based on OS
	checker.paths = checker.getCriticalPathConfigs()
	return checker
}

// NewWindowsPermissionChecker creates a new Windows permission checker
func NewWindowsPermissionChecker(osCtx registry.OSContext, scanRoot string) *WindowsPermissionChecker {
	return &WindowsPermissionChecker{
		checkIdentity: checkIdentity{
			domain:   "File Permissions Security",
			analyzes: "file and directory permissions",
			osCtx:    osCtx,
		},
		Paths: []string{
			"C:\\Windows\\System32",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
			"C:\\ProgramData",
			"C:\\Users",
		},
		scanRoot: scanRoot,
	}
}

// Check implements PermissionChecker interface for Unix systems
func (p *UnixPermissionChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        p.Name(),
		Status:      types.StatusChecking,
		Description: p.Description(),
		Details:     make([]string, 0),
	}

	if p.scanRoot == "" {
		for _, cpath := range p.paths {
			if err := p.checkPathPermissions(ctx, cpath, &result); err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("%s Error checking %s: %v",
						types.SymbolError, cpath.path, err))
			}
		}
	}

	p.checkSUIDFiles(ctx, &result)
	p.checkWorldWritableFiles(ctx, &result)
	p.checkUnownedFiles(ctx, &result)

	result.Status = types.StatusCompleted
	return result
}

// effectiveRoot resolves the find scan root; operator supplied
func (p *UnixPermissionChecker) effectiveRoot() string {
	if p.scanRoot == "" {
		return "/"
	}
	return p.scanRoot
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

func (p *UnixPermissionChecker) checkPathPermissions(ctx context.Context, cp criticalPath, result *types.AuditResult) error {
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
		emitFinding(result, p.osCtx, "permissions.path_exceeds_expected_mode")
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s has correct permissions: %v",
				types.SymbolOK, cp.path, mode.Perm()))
	}

	if cp.recursive && info.IsDir() {
		return filepath.Walk(cp.path, func(path string, info os.FileInfo, err error) error {
			// Abort the walk as soon as the caller's deadline expires;
			// returning the ctx error stops filepath.Walk immediately.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
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

func (p *UnixPermissionChecker) checkSUIDFiles(ctx context.Context, result *types.AuditResult) {
	const scan string = "SUID/SGID scan"
	output, skipped, err := runBoundedFind(ctx, p.effectiveRoot(), []string{
		"-type", "f",
		"(", "-perm", findPermSUID, "-o", "-perm", findPermSGID, ")",
	})
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking SUID/SGID files: %v", types.SymbolError, err))
		return
	}

	files := nonEmptyLines(output)
	if len(files) > 0 {
		result.Details = append(result.Details, "", "SUID/SGID Files Found:")
		for _, file := range files {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolWarning, file))
		}
		emitFinding(result, p.osCtx, "permissions.suid_sgid_binary")
	}
	appendSkippedNote(result, scan, skipped)
}

func (p *UnixPermissionChecker) checkWorldWritableFiles(ctx context.Context, result *types.AuditResult) {
	const scan string = "World-writable scan"
	output, skipped, err := runBoundedFind(ctx, p.effectiveRoot(), []string{
		"-type", "f",
		"-perm", findPermWorldWritable,
		"-not", "-type", "l",
		"-ls",
	})
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking world-writable files: %v", types.SymbolError, err))
		return
	}

	files := nonEmptyLines(output)
	if len(files) > 0 {
		result.Details = append(result.Details, "", "World-Writable Files Found:")
		for _, file := range files {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolWarning, file))
		}
		emitFinding(result, p.osCtx, "permissions.world_writable_file")
	}
	appendSkippedNote(result, scan, skipped)
}

func (p *UnixPermissionChecker) checkUnownedFiles(ctx context.Context, result *types.AuditResult) {
	const scan string = "Unowned-files scan"
	output, skipped, err := runBoundedFind(ctx, p.effectiveRoot(), []string{
		"-nouser", "-o", "-nogroup",
		"-ls",
	})
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking unowned files: %v", types.SymbolError, err))
		return
	}

	files := nonEmptyLines(output)
	if len(files) > 0 {
		result.Details = append(result.Details, "", "Unowned Files Found:")
		for _, file := range files {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolWarning, file))
		}
		emitFinding(result, p.osCtx, "permissions.unowned_file")
	}
	appendSkippedNote(result, scan, skipped)
}

// Check implements PermissionChecker interface for Windows systems
func (p *WindowsPermissionChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        p.Name(),
		Status:      types.StatusChecking,
		Description: p.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	if p.scanRoot != "" {
		if err := p.checkWindowsPermissions(ctx, p.scanRoot, true, &result); err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Error checking %s: %v",
					types.SymbolError, p.scanRoot, err))
		}
		result.Status = types.StatusCompleted
		return result
	}

	for _, path := range p.Paths {
		if err := p.checkWindowsPermissions(ctx, path, false, &result); err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Error checking %s: %v",
					types.SymbolError, path, err))
		}
	}

	// Check for potentially insecure shares
	p.checkNetworkShares(ctx, &result)

	result.Status = types.StatusCompleted
	return result
}

func (p *WindowsPermissionChecker) checkWindowsPermissions(ctx context.Context, path string, recursive bool, result *types.AuditResult) error {
	const scan string = "ACL traversal"
	output, skipped, err := runICACLS(ctx, path, recursive)
	if err != nil {
		return fmt.Errorf("failed to check permissions: %w", err)
	}

	seen := make(map[registry.FindingKey]struct{})

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
			emitFindingOnce(result, p.osCtx, "permissions.everyone_full_control", seen)
		} else if strings.Contains(line, "Users:(OI)(CI)(F)") ||
			strings.Contains(line, "Users:(F)") {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Full control granted to Users group on %s",
					types.SymbolWarning, line))
			emitFindingOnce(result, p.osCtx, "permissions.users_full_control", seen)
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolInfo, line))
		}
	}

	appendSkippedNote(result, scan, skipped)
	return nil
}

func (p *WindowsPermissionChecker) checkNetworkShares(ctx context.Context, result *types.AuditResult) {
	cmd := exec.CommandContext(ctx, "net", "share")
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking network shares: %v",
				types.SymbolError, err))
		return
	}

	shares := strings.Split(string(output), "\n")
	result.Details = append(result.Details, "", "Network Shares:")

	seen := make(map[registry.FindingKey]struct{})

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
			emitFindingOnce(result, p.osCtx, "permissions.admin_share_present", seen)
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolInfo, share))
		}
	}
}

// runICACLS executes against the given path with optional recursion for tree
// traversal. ctx bounds the invocation; icacls /T over a large tree is the
// slowest operation in the Windows permission path.
func runICACLS(ctx context.Context, path string, recursive bool) (output []byte, skipped int, err error) {
	args := []string{path}
	if recursive {
		args = append(args, "/T")
	}
	cmd := exec.CommandContext(ctx, "icacls", args...) // #nosec G204 -- path validated by caller; flags are fixed literals

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// icacls exits nonzero when any subtree entry is denied while still
	// emitting valid ACL lines for everything it could read. An ExitError is
	// therefore deliberately tolerated: partial output plus the denied-path
	// count is the correct result, and only non-exit failures (binary
	// missing, ctx kill) abort.
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return nil, 0, runErr
	}

	return stdout.Bytes(), countDeniedPaths(stderr.Bytes()), nil
}

// countDeniedPaths counts the paths icacls could not access
func countDeniedPaths(stderr []byte) int {
	if len(stderr) == 0 {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.Contains(line, "Access is denied") {
			count++
		}
	}
	return count
}
