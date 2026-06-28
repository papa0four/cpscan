// Package `scan` defines the CheckMask type and constants used to identify
// which audit checks are enabled for a given scan. The bitmask representation
// keeps check composition O(1) and scales to 64 discrete check types without
// structural changes.
package scan

import "strings"

// CheckMask is a bitmask of enabled audit checks. Each bit represents a single
// check type. Callers compose a mask by OR-ing the constants defined in this
// package.
type CheckMask uint64

const (
	CheckSSH      CheckMask = 1 << iota
	CheckFirewall
	CheckUsers
	CheckPerms

	// Module bits occupy the upper 32 positions
	ModuleOS       CheckMask = 1 << 32
	ModuleSoftware CheckMask = 1 << 33
	// TODO: ModuleNetwork, ModuleSyslog, ModuleListeners
)

// Codes returns a filename-safe string encoding the enabled checks within the
// mask. Module-level segments (os, soft) are joined by hyphens; security check
// letters are alphabetically ordered and concatenated without a delimiter.
func Codes(mask CheckMask) string {
	var segments []string

	if mask&ModuleOS != 0 {
		segments = append(segments, "os")
	}
	if mask&Mo

	var letters strings.Builder
	if mask&CheckFirewall != 0 {
		letters.WriteByte('f')
	}
	if mask&CheckPerms != 0 {
		letters.WriteByte('p')
	}
	if mask&CheckSSH != 0 {
		letters.WriteByte('s')
	}
	if mask&CheckUsers != 0 {
		letters.WriteByte('u')
	}
	if letters.Len() > 0 {
		segments = append(segments, letters.String())
	}

	return strings.Join(segments, "-")
}

// EnabledChecks returns a slice of check name strings for the enabled security
// checks in mask. The returned slice is used by the audit runner to select
// which checks to execute.
func EnabledChecks(mask CheckMask) []string {
	var checks []string
	if mask&CheckSSH != 0 {
		checks = append(checks, "ssh")
	}
	if mask&CheckFirewall != 0 {
		checks = append(checks, "firewall")
	}
	if mask&CheckUsers != 0 {
		checks = append(checks, "users")
	}
	if mask&CheckPerms != 0 {
		checks = append(checks, "permissions")
	}
	return checks
}