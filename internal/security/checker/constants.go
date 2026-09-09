// internal/security/checker/constants.go

package checker

// /etc/passwd field indices as defined by POSIX.
const (
	passwdFieldUsername = 0
	passwdFieldPassword = 1
	passwdFieldUID      = 2
	passwdFieldGID      = 3
	passwdFieldGECOS    = 4
	passwdFieldHomeDir  = 5
	passwdFieldShell    = 6
	passwdFieldCount    = 7

	// Minimum field counts for Unix authentication files.
	shadowMinFields       = 2
	passwdMinFieldsForUID = 3

	// passwd -S reports account status as the second whitespace-separated
	// field, in one of three states: a usable password, no password set, or
	// a locked password
	passwdStatusField      = 1
	passwdStatusUsable     = "P"
	passwdStatusNoPassword = "NP"
	passwdStatusLocked     = "L"

	// /etc/group field indices and minimum field count as defined by POSIX.
	groupFieldMembers = 3
	groupFieldCount   = 4

	// macOS starts regular user UIDs at 500; Linux and BSD start at 1000.
	minUIDMacOS   = 500
	minUIDDefault = 1000
	rootUID       = 0
)
