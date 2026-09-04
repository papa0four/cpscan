//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/fsident_unix.go

package checker

import (
	"io/fs"
	"syscall"
)

// fileIdentity returns the numeric owner, group, and device of info, and
// reports whether the platform supplies them.
func fileIdentity(info fs.FileInfo) (uid, gid uint32, dev uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, uint64(st.Dev), true
}
