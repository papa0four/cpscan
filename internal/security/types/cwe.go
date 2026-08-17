// internal/security/types/cwe.go
package types

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidCWEID indicates a CWE identifier failed format validation
// Returned when input does not match CWE-N+
var ErrInvalidCWEID = errors.New("invalid CWE identifier")

const (
	cweIDPrefix       = "CWE-"
	cweIDPrefixLength = 4
	cweIDMinLength    = 5 // CWE- plus at least one digit
	cweURLPrefix      = "https://cwe.mitre.org/data/definitions/"
	cweURLSuffix      = ".html"
)

// NormalizeCWEID returns the canonical CWE-N form for an identifier
// supplied in canonical or URL form. Returns an error wrapping
// ErrInvalidCWE for input that does not match either form.
func NormalizeCWEID(input string) (string, error) {
	if id, ok := extractCWEFromURL(input); ok {
		return validateCanonicalCWE(id)
	}
	return validateCanonicalCWE(input)
}

func extractCWEFromURL(input string) (string, bool) {
	if !strings.HasPrefix(input, cweURLPrefix) {
		return "", false
	}
	if !strings.HasSuffix(input, cweURLSuffix) {
		return "", false
	}
	num := strings.TrimPrefix(input, cweURLPrefix)
	num = strings.TrimSuffix(num, cweURLSuffix)
	if num == "" {
		return "", false
	}
	for i := 0; i < len(num); i++ {
		if !isASCIIDigit(num[i]) {
			return "", false
		}
	}
	return cweIDPrefix + num, true
}

func validateCanonicalCWE(id string) (string, error) {
	if len(id) < cweIDMinLength {
		return "", fmt.Errorf("%w: length %d below minimum %d: %q", ErrInvalidCWEID, len(id), cweIDMinLength, id)
	}
	if !strings.HasPrefix(id, cweIDPrefix) {
		return "", fmt.Errorf("%w: missing %q prefix: %q", ErrInvalidCWEID, cweIDPrefix, id)
	}
	for i := cweIDPrefixLength; i < len(id); i++ {
		if !isASCIIDigit(id[i]) {
			return "", fmt.Errorf("%w: non-digit byte 0x%02x at position %d: %q", ErrInvalidCWEID, id[i], i, id)
		}
	}
	return id, nil
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
