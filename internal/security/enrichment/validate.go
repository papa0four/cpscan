// internal/security/enrichment/validate.go
package enrichment

import (
	"fmt"
	"strings"
)

const (
	cweIDPrefix          = "CWE-"
	cweIDPrefixLength    = 4
	cweIDMinLength       = 5 // CWE- plus at least one digit
	cweURLPrefix         = "https://cwe.mitre.org/data/definitions/"
	cweURLSuffix         = ".html"
	maxBulkValidateInput = 10000
)

// NormalizeCWEID returns the canonical CWE-N form for an identifier
// supplied in canonical or URL form. Returns an error wrapping
// ErrInvalidCWEID for input that does not match either form.
func NormalizeCWEID(input string) (string, error) {
	if id, ok := extractCWEFromURL(input); ok {
		return validateCanonicalCWE(id)
	}
	return validateCanonicalCWE(input)
}

// ValidateCWEID returns nil if input is a valid CWE identifier in
// canonical or URL form. Use NormalizeCWEID when the canonical form
// is needed for downstream use.
func ValidateCWEID(input string) error {
	_, err := NormalizeCWEID(input)
	return err
}

// NormalizeCWEIDs normalizes a slice of CWE identifiers. Returns the
// canonical IDs that validated successfully and errors for the rest.
// Rejects bulk input above the documented limit. Does not deduplicate.
func NormalizeCWEIDs(inputs []string) (valid []string, errs []error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if len(inputs) > maxBulkValidateInput {
		return nil, []error{
			fmt.Errorf("%w: input size %d exceeds limit %d",
				ErrInvalidCWEID, len(inputs), maxBulkValidateInput),
		}
	}

	valid = make([]string, 0, len(inputs))
	for _, input := range inputs {
		id, err := NormalizeCWEID(input)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		valid = append(valid, id)
	}
	return valid, errs
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
		return "", fmt.Errorf("%w: length %d below minimum %d: %q",
			ErrInvalidCWEID, len(id), cweIDMinLength, id)
	}
	if !strings.HasPrefix(id, cweIDPrefix) {
		return "", fmt.Errorf("%w: missing %q prefix: %q",
			ErrInvalidCWEID, cweIDPrefix, id)
	}
	for i := cweIDPrefixLength; i < len(id); i++ {
		if !isASCIIDigit(id[i]) {
			return "", fmt.Errorf("%w: non-digit byte 0x%02x at position %d: %q",
				ErrInvalidCWEID, id[i], i, id)
		}
	}
	return id, nil
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
