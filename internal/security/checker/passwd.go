// internal/security/checker/passwd.go

package checker

import "strconv"

// parseUnixID converts a numeric identifier field from a POSIX account
// database to its native width, reporting whether the field was well formed.
// uid_t and gid_t are unsigned 32-bit on every supported platform, so a
// negative or oversized field is a malformed record rather than an account:
// accepting one would place it below the regular-user minimum, mark it a
// system account, and drop it from the report.
func parseUnixID(field string) (uint32, bool) {
	base := 10
	bitSize := 32
	id, err := strconv.ParseUint(field, base, bitSize)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}
