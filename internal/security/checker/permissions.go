// internal/security/checker/permissions.go

package checker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

	// Permission bit masks
	bitWorldWritable os.FileMode = 0002

	// Account databases consulted before the name service, and the
	// colon-delimited field holding each numeric identifier.
	unixPasswdFile = "/etc/passwd"
	unixGroupFile  = "/etc/group"
	unixIDField    = 2

	identityKindUser  identityKind = "user"
	identityKindGroup identityKind = "group"
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

	// identityCache reports whether numeric owners and groups resolve to a real
	// principal, memoizing by identifier. A filesystem holds orders of magnitude
	// more entries than distinct identifiers, so resolution collapses from one
	// lookup per file to one per identifier.
	identityCache struct {
		users  map[uint32]bool
		groups map[uint32]bool
	}

	// fsScan is the outcome of one filesystem traversal.
	fsScan struct {
		suid       []string
		worldWrite []string
		unowned    []string
		unreadable int
	}

	// identityKind selects which account database a lookup consults.
	identityKind string
)

// newIdentityCache seeds the cache from the local account databases. Anything
// they declare is known without consulting the name service.
func newIdentityCache() *identityCache {
	return &identityCache{
		users:  localIDs(unixPasswdFile),
		groups: localIDs(unixGroupFile),
	}
}

// localIDs returns the numeric identifiers declared by a colon-delimited
// account database. An unreadable file yields an empty set, which is safe:
// every identifier then falls through to the name service
func localIDs(path string) map[uint32]bool {
	ids := make(map[uint32]bool)
	data, err := os.ReadFile(path) // #nosec G304 -- path is a package constant
	if err != nil {
		return ids
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) <= unixIDField {
			continue
		}
		if id, ok := parseUnixID(fields[unixIDField]); ok {
			ids[id] = true
		}
	}
	return ids
}

// resolves reports whether both identifiers map to a known principal.
func (c *identityCache) resolves(ctx context.Context, uid, gid uint32) bool {
	return c.known(ctx, c.users, identityKindUser, uid) &&
		c.known(ctx, c.groups, identityKindGroup, gid)
}

// known consults the cache, falling back to the name service for identifiers
// the local database does not declare. Directory-provided accounts exist only
// in the name service, so a local miss alone is not evidence of an orphan.
func (c *identityCache) known(ctx context.Context, cache map[uint32]bool, kind identityKind, id uint32) bool {
	if resolved, seen := cache[id]; seen {
		return resolved
	}
	resolved := nameServiceKnows(ctx, kind, id)
	cache[id] = resolved
	return resolved
}

// nameServiceKnows asks the platform name service about a single identifier.
// getent reports absence through its exit status while dscacheutil reports it
// through empty output, so both conditions are treated as unresolved.
func nameServiceKnows(ctx context.Context, kind identityKind, id uint32) bool {
	const base = 10
	value := strconv.FormatUint(uint64(id), base)

	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name = "dscacheutil"
		args = []string{"-q", string(kind), "-a", string(kind) + "id", value}
	default:
		database := "passwd"
		if kind == identityKindGroup {
			database = "group"
		}
		name = "getent"
		args = []string{database, value}
	}

	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- command is platform-fixed and the sole argument is a numeric identifier read from the filesystem
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
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

	scan, err := p.scanFilesystem(ctx)
	p.reportScan(&result, scan)

	switch {
	case err != nil:
		result.Status = types.StatusWarning
		result.Description = fmt.Sprintf("Filesystem scan did not complete: %v", err)
		result.Details = append(result.Details,
			fmt.Sprintf("%s Filesystem scan did not complete: %v", types.SymbolError, err))
	case scan.unreadable > 0:
		result.Status = types.StatusWarning
		result.Description = fmt.Sprintf("Filesystem scan could not read %d paths", scan.unreadable)
		result.Details = append(result.Details,
			fmt.Sprintf("%s %d paths were unreadable and went unscanned; rerun with elevated privileges for complete coverage",
				types.SymbolWarning, scan.unreadable))
	default:
		result.Status = types.StatusCompleted
	}
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

// scanFilesystem walks the effective root once, collecting setuid, group- and
// world-writable, and unowned entries together. Identity lookups are cached
// per identifier rather than performed per entry, which is what makes a single
// pass cheaper than the three it replaces.
func (p *UnixPermissionChecker) scanFilesystem(ctx context.Context) (fsScan, error) {
	var scan fsScan
	root := p.effectiveRoot()

	rootInfo, err := os.Lstat(root)
	if err != nil {
		return scan, fmt.Errorf("stat scan root %s: %w", root, err)
	}
	_, _, rootDev, haveRootDev := fileIdentity(rootInfo)

	ids := newIdentityCache()

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			scan.unreadable++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			scan.unreadable++
			return nil
		}

		uid, gid, dev, haveIdentity := fileIdentity(info)

		// Stay on one filesystem. Pseudo-filesystems and network mounts are
		// out of scope and can be pathologically slow to traverse.
		if haveRootDev && haveIdentity && dev != rootDev {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		mode := info.Mode()
		if mode.IsRegular() {
			if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
				scan.suid = append(scan.suid, describeEntry(path, info, uid, gid))
			}
			if mode.Perm()&bitWorldWritable != 0 {
				scan.worldWrite = append(scan.worldWrite, describeEntry(path, info, uid, gid))
			}
		}

		if haveIdentity && !ids.resolves(ctx, uid, gid) {
			scan.unowned = append(scan.unowned, describeEntry(path, info, uid, gid))
		}
		return nil
	})

	return scan, walkErr
}

// describeEntry renders one entry with its mode and numeric owner and group.
// The identifiers stay numeric deliberately: for an unowned entry they are the
// values that failed to resolve, and a name would be misleading.
func describeEntry(path string, info fs.FileInfo, uid, gid uint32) string {
	return fmt.Sprintf("%v uid=%d gid=%d %s", info.Mode(), uid, gid, path)
}

// reportScan records each category the traversal found.
func (p *UnixPermissionChecker) reportScan(result *types.AuditResult, scan fsScan) {
	sections := []struct {
		heading string
		entries []string
		key     registry.FindingKey
	}{
		{"SUID/SGID Files Found:", scan.suid, "permissions.suid_sgid_binary"},
		{"World-Writable Files Found:", scan.worldWrite, "permissions.world_writable_file"},
		{"Unowned Files Found:", scan.unowned, "permissions.unowned_file"},
	}

	for _, section := range sections {
		if len(section.entries) == 0 {
			continue
		}
		result.Details = append(result.Details, "", section.heading)
		for _, entry := range section.entries {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolWarning, entry))
		}
		emitFinding(result, p.osCtx, section.key)
	}
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
	output, err := cmd.Output()
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
