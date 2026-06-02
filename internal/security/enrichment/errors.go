// internal/security/enrichment/errors.go
package enrichment

import "errors"

// ErrNoEnricherConfigured indicates that no enrichment source adapter has been registered.
var ErrNoEnricherConfigured = errors.New("no enrichment source configured")

// ErrInvalidCWEID indicates a CWE identifier failed format validation.
// Returned when input does not match CWE-N+
var ErrInvalidCWEID = errors.New("invalid CWE identifier")

// ErrEmptyRequest indicates an EnrichRequest contained no CVE identifiers to enrich.
var ErrEmptyRequest = errors.New("enrichment request contains no CVE identifiers")

// ErrMissingAPIKey indicates an adapter that requires an API key could not find the required credential
var ErrMissingAPIKey = errors.New("required API key not found in environment")
