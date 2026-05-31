// internal/security/types/types.go
package types

import (
	"fmt"
	"time"
)

// Status symbols for check results
const (
	SymbolOK       = "[+]"
	SymbolError    = "[-]"
	SymbolWarning  = "[!]"
	SymbolInfo     = "[*]"
	SymbolCritical = "[X]"
)

// Status constants for audit results
const (
	StatusCompleted = "COMPLETED"
	StatusWarning   = "WARNING"
	StatusError     = "ERROR"
	StatusSkipped   = "SKIPPED"
	StatusChecking  = "CHECKING"
)

// Severity levels for audit findings
const (
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// AuditResult represents the result of a security check
type AuditResult struct {
	Name        string         // Name of the check
	Status      string         // Status of the check (using Status constants)
	Description string         // Description of what was checked
	Details     []string       // Detailed findings
	Findings    []Finding      // Structured findings
	StartTime   time.Time      // When the check started
	EndTime     time.Time      // When the check completed
	Duration    time.Duration  // How long the check took
	Metadata    map[string]any // Additional check-specific metadata
}

// Finding represents a specific security finding
type Finding struct {
	Title       string
	Description string
	Severity    string
	Category    string
	Impact      string
	Resolution  string
	References  []Reference
	Metadata    map[string]any
}

// Reference provides additional information about a finding
type Reference struct {
	Title string
	URL   string
	Type  string // e.g., "CVE", "CWE", "NIST", "MITRE", etc.
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Checker string
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error in %s: %s - %s", e.Checker, e.Field, e.Message)
}

// SeverityFormat returns the display symbol and fixed-width padded severity label
func SeverityFormat(severity string) (symbol, label string) {
	switch severity {
	case SeverityCritical:
		return SymbolCritical, "CRITICAL"
	case SeverityHigh:
		return SymbolWarning, "HIGH    "
	case SeverityMedium:
		return SymbolWarning, "MEDIUM  "
	case SeverityLow:
		return SymbolInfo, "LOW     "
	default:
		return SymbolInfo, severity
	}
}
