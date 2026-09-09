// internal/security/checker/passwd.go

package checker

import "strconv"

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
	const base = 10
	const bitSize = 32
	id, err := strconv.ParseUint(field, decimalBase, idBitSize)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}
