//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/uac_unix.go

package checker

import "errors"

// uacEnabled reports that User Account Control has no meaning off Windows.
// WindowsUserChecker is its only caller and never runs here; this exists so
// so the package compiles on every supported target, mirroring fileIdentity.
func uacEnabled() (bool, error) {
	return false, errors.New("UAC is a Windows-only setting")
}
