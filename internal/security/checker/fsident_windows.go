// internal/security/checker/fsident_windows.go
//go:build windows

package checker

import "io/fs"

// fileIdentity reports that Windows exposes no POSIX owner, group, or, device
// identifiers. The Windows checker inspects ACLs and SIDs instead.
func fileIdentity(_ fs.FileInfo) (uid, gid uint32, dev uint64, ok bool) {
	return 0, 0, 0, false
}
