// internal/report/report_windows.go
//go:build windows

package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func refusedReason(target string) string {
	// Windows paths are case-insensitive, so fold both sides before comparing.
	target = strings.ToLower(filepath.Clean(target))
	for _, base := range refusedBases() {
		if pathWithin(target, strings.ToLower(filepath.Clean(base))) {
			return base
		}
	}
	return ""
}

// refusedBases resolves system and per-user persistence locations from the
// environment, refused because they hold OS files, installed programs, and the
// Startup folders an attacker would use for persistence.
func refusedBases() []string {
	startupRel := filepath.Join("Microsoft", "Windows", "Start Menu", "Programs", "Startup")

	bases := make([]string, 0, 5)
	for _, env := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)"} {
		if v := os.Getenv(env); v != "" {
			bases = append(bases, v)
		}
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		bases = append(bases, filepath.Join(pd, startupRel))
	}
	if ad := os.Getenv("APPDATA"); ad != "" {
		bases = append(bases, filepath.Join(ad, startupRel))
	}
	return bases
}

// canonicalParent returns the OS-resolved long-form path of parent so the
// location checks cannot be evaded by 8.3 short names, links, or trailing dots
// and spaces. Extended-length and device prefixes are refused, since a report
// path has no legitimate use for them.
func canonicalParent(parent string) (string, error) {
	if strings.HasPrefix(parent, `\\?\`) || strings.HasPrefix(parent, `\\.\`) {
		return "", fmt.Errorf("%w: extended-length or device path", ErrRefusedLocation)
	}

	p, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		return "", fmt.Errorf("encode path: %w", err)
	}

	// Backup semantics are required to obtain a directory handle.
	h, err := windows.CreateFile(
		p,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrParentMissing, parent)
	}
	defer windows.CloseHandle(h)

	const finalPathFlags = 0
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathFlags)
	if err != nil {
		return "", fmt.Errorf("canonicalize path: %w", err)
	}
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		if _, err := windows.GetFinalPathNameByHandle(h, &buf[0], n, finalPathFlags); err != nil {
			return "", fmt.Errorf("canonicalize path: %w", err)
		}
	}

	final := windows.UTF16ToString(buf)
	if rest := strings.TrimPrefix(final, `\\?\UNC\`); rest != final {
		return `\\` + rest, nil
	}
	return strings.TrimPrefix(final, `\\?\`), nil
}

// isElevated reports an elevated (Administrator) token, where a write can land
// anywhere and the tool becomes a privileged write primitive.
func isElevated() (bool, error) {
	return windows.GetCurrentProcessToken().IsElevated(), nil
}

// withinAllowlist permits an elevated write only under roots the operator
// clearly owns, so a privileged run cannot silently write elsewhere.
func withinAllowlist(target string) (bool, error) {
	target = strings.ToLower(filepath.Clean(target))
	for _, root := range allowlistRoots() {
		real, err := canonicalParent(root)
		if err != nil {
			continue
		}
		if pathWithin(target, strings.ToLower(filepath.Clean(real))) {
			return true, nil
		}
	}
	return false, nil
}

func allowlistRoots() []string {
	roots := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, home)
	}
	return roots
}

var (
	advapi32                      = windows.NewLazySystemDLL("advapi32.dll")
	procGetEffectiveRightsFromACL = advapi32.NewProc("GetEffectiveRightsFromAclW")
)

// trusteeW mirrors TRUSTEE_W. For a SID-form trustee, Name holds the SID pointer.
type trusteeW struct {
	MultipleTrustee          *trusteeW
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32
	TrusteeType              uint32
	Name                     *uint16
}

const (
	trusteeIsSid     = 0 // TRUSTEE_IS_SID
	trusteeIsUnknown = 0 // TRUSTEE_IS_UNKNOWN
)

// parentWritableByOthers reports whether a broad group has effective write
// access to dir.
func parentWritableByOthers(dir string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read security info: %w", err)
	}
	dacl, present, err := sd.DACL()
	if err != nil {
		return false, fmt.Errorf("read dacl: %w", err)
	}
	// A NULL DACL grants everyone full access, so treat its absence as exposed.
	if !present || dacl == nil {
		return true, nil
	}

	broad, err := broadSIDs()
	if err != nil {
		return false, err
	}

	const fileDeleteChild = 0x40
	const writeMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		fileDeleteChild | windows.DELETE |
		windows.GENERIC_WRITE | windows.GENERIC_ALL |
		windows.WRITE_DAC | windows.WRITE_OWNER

	for _, sid := range broad {
		mask, err := effectiveRights(dacl, sid)
		if err != nil {
			return false, err
		}
		if mask&writeMask != 0 {
			return true, nil
		}
	}
	return false, nil
}

func effectiveRights(dacl *windows.ACL, sid *windows.SID) (uint32, error) {
	trustee := trusteeW{
		TrusteeForm: trusteeIsSid,
		TrusteeType: trusteeIsUnknown,
		Name:        (*uint16)(unsafe.Pointer(sid)),
	}
	var mask uint32
	ret, _, _ := procGetEffectiveRightsFromACL.Call(
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(&trustee)),
		uintptr(unsafe.Pointer(&mask)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("effective rights: error %d", ret)
	}
	return mask, nil
}

func broadSIDs() ([]*windows.SID, error) {
	types := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,             // Everyone
		windows.WinAuthenticatedUserSid, // Authenticated Users
		windows.WinBuiltinUsersSid,      // Users
	}
	sids := make([]*windows.SID, 0, len(types))
	for _, t := range types {
		sid, err := windows.CreateWellKnownSid(t)
		if err != nil {
			return nil, fmt.Errorf("well-known sid: %w", err)
		}
		sids = append(sids, sid)
	}
	return sids, nil
}

// openAndWrite writes data to target without traversing a reparse point
func openAndWrite(target string, data []byte) error {
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("%w: reparse point", ErrNotRegularFile)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s", ErrNotRegularFile, target)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat destination: %w", err)
	}

	path, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("encode path: %w", err)
	}

	// OPEN_REPARSE_POINT opens the final component literally instead of
	// traversing it; OPEN_ALWAYS avoids truncating before the reparse check.
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	f := os.NewFile(uintptr(handle), target)

	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &fi); err != nil {
		f.Close()
		return fmt.Errorf("inspect destination: %w", err)
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		f.Close()
		return fmt.Errorf("%w: reparse point", ErrNotRegularFile)
	}

	// Truncate only after the reparse check so a rejected link keeps its content.
	if err := windows.SetEndOfFile(handle); err != nil {
		f.Close()
		return fmt.Errorf("truncate destination: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write report: %w", err)
	}
	return f.Close()
}
