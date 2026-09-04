//go:build windows

// internal/report/report_windows.go

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

// fileDeleteChild is the directory right to delete child objects
const fileDeleteChild = 0x40

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

	var bases []string
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
// and spaces.
func canonicalParent(parent string) (final string, err error) {
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
	defer func() {
		if cerr := windows.CloseHandle(h); cerr != nil && err == nil {
			err = fmt.Errorf("close directory handle: %w", cerr)
		}
	}()

	const finalPathFlags = 0
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], windows.MAX_PATH, finalPathFlags)
	if err != nil {
		return "", fmt.Errorf("canonicalize path: %w", err)
	}
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		if _, err := windows.GetFinalPathNameByHandle(h, &buf[0], n, finalPathFlags); err != nil {
			return "", fmt.Errorf("canonicalize path: %w", err)
		}
	}

	final = windows.UTF16ToString(buf)
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
	roots := make([]string, 0, maxOperatorHomes)
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, home)
	}
	return roots
}

// parentWritableByOthers reports whether a broad group has effective write
// access to dir.
func parentWritableByOthers(dir string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, fmt.Errorf("read security info: %w", err)
	}

	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		// No DACL exists; a NULL DACL grants everyone full access.
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read dacl: %w", err)
	}
	// A nil DACL here is an empty, fully permissive DACL.
	if dacl == nil {
		return true, nil
	}

	trusted, err := trustedSIDs(sd)
	if err != nil {
		return false, err
	}

	const writeMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		fileDeleteChild | windows.DELETE |
		windows.GENERIC_WRITE | windows.GENERIC_ALL |
		windows.WRITE_DAC | windows.WRITE_OWNER

	// ACL field construction
	type aclLayout struct {
		revision byte
		sbz1     byte
		size     byte
		count    uint16
		sbz2     uint16
	}
	hdr := (*aclLayout)(unsafe.Pointer(dacl))                                  // #nosec G103 -- audited ACE walk over the fixed OS ACL layout
	end := uintptr(unsafe.Pointer(dacl)) + uintptr(hdr.size)                   // #nosec G103 -- ACL end boundary, compared only and never converted back to a pointer
	ace := unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + unsafe.Sizeof(*hdr)) // #nosec G103 -- first ACE follows the ACL header

	for i := 0; i < int(hdr.count); i++ {
		header := (*windows.ACE_HEADER)(ace) // #nosec G103 -- bounded ACE read within the ACL buffer
		if header.AceSize == 0 || uintptr(ace)+uintptr(header.AceSize) > end {
			break // malformed entry; do not read past the ACL buffer
		}

		if header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			allowed := (*windows.ACCESS_ALLOWED_ACE)(ace)
			if allowed.Mask&writeMask != 0 {
				sid := (*windows.SID)(unsafe.Pointer(&allowed.SidStart)) // #nosec G103 -- SID embedded in the validated ACE
				if !sidTrusted(sid, trusted) {
					return true, nil
				}
			}
		}

		ace = unsafe.Pointer(uintptr(ace) + uintptr(header.AceSize)) // #nosec G103 -- advance within the bounds-checked ACL buffer
	}
	return false, nil
}

func trustedSIDs(sd *windows.SECURITY_DESCRIPTOR) ([]*windows.SID, error) {
	wellKnown := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
		windows.WinCreatorOwnerSid,
	}
	trusted := make([]*windows.SID, 0, len(wellKnown)+1)
	for _, t := range wellKnown {
		sid, err := windows.CreateWellKnownSid(t)
		if err != nil {
			return nil, fmt.Errorf("well-known sid: %w", err)
		}
		trusted = append(trusted, sid)
	}
	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		trusted = append(trusted, owner)
	}
	return trusted, nil
}

func sidTrusted(sid *windows.SID, trusted []*windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}

// openAndWrite writes data to target without traversing a reparse point
func openAndWrite(target string, data []byte) (err error) {
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
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	var fi windows.ByHandleFileInformation
	if ierr := windows.GetFileInformationByHandle(handle, &fi); ierr != nil {
		return fmt.Errorf("inspect destination: %w", ierr)
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: reparse point", ErrNotRegularFile)
	}

	if serr := windows.SetEndOfFile(handle); serr != nil {
		return fmt.Errorf("truncate destination: %w", serr)
	}

	if _, werr := f.Write(data); werr != nil {
		return fmt.Errorf("write report: %w", werr)
	}
	return nil
}
