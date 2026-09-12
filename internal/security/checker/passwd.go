// internal/security/checker/passwd.go

package checker

import (
	"strconv"
	"strings"
)

const (
	// decimalBase and idBitSize describe the numeric identifiers in a POSIX
	// account database: base-10 text, uid_t and gid_t width.
	decimalBase = 10
	idBitSize   = 32
)

// parseUnixID converts a numeric identifier field from a POSIX account
// database to its native width, reporting whether the field was well formed.
// uid_t and gid_t are unsigned 32-bit on every supported platform, so a
// negative or oversized field is a malformed record rather than an account:
// accepting one would place it below the regular-user minimum, mark it a
// system account, and drop it from the report.
func parseUnixID(field string) (uint32, bool) {
	id, err := strconv.ParseUint(field, decimalBase, idBitSize)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}

// addGroupMembers records the members listed in POSIX group-database entries
// into members. An entry is name:password:gid:comma-separated-members; a line
// with fewer fields is skipped rather than treated as a group with no members.
func addGroupMembers(output []byte, members map[string]bool) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < groupFieldCount {
			continue
		}
		for _, member := range strings.Split(fields[groupFieldMembers], ",") {
			if name := strings.TrimSpace(member); name != "" {
				members[name] = true
			}
		}
	}
}
