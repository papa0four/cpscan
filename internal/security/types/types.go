// internal/security/types/types.go
package types

import (
    "time"
	"fmt"
)

// Status symbols for check results
const (
    // Checkmark symbol
    SymbolOK = "\u2713"
    
    // Warning symbol
    SymbolWarning = "\u26A0"
    
    // Error symbol
    SymbolError = "\u2717"
    
    // Info symbol
    SymbolInfo = "\u2139"
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
    SeverityLow     = "LOW"
    SeverityMedium  = "MEDIUM"
    SeverityHigh    = "HIGH"
    SeverityCritical = "CRITICAL"
)

// AuditResult represents the result of a security check
type AuditResult struct {
    Name        string          // Name of the check
    Status      string          // Status of the check (using Status constants)
    Description string          // Description of what was checked
    Details     []string        // Detailed findings
    Findings    []Finding       // Structured findings
    StartTime   time.Time       // When the check started
    EndTime     time.Time       // When the check completed
    Duration    time.Duration   // How long the check took
    Metadata    map[string]any  // Additional check-specific metadata
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

// SecurityCheck defines the interface that all security checkers must implement
type SecurityCheck interface {
    // Check performs the security check and returns the results
    Check() AuditResult
    
    // Validate validates the checker's configuration
    Validate() error
    
    // Name returns the name of the checker
    Name() string
}

// CheckerConfig provides common configuration options for checkers
type CheckerConfig struct {
    Paths          []string          // Paths to check
    ExcludePaths   []string          // Paths to exclude
    MinSeverity    string            // Minimum severity to report
    Timeout        time.Duration     // Maximum time to run the check
    CustomRules    map[string]string // Custom rules to apply
    MetadataOnly   bool              // Only collect metadata, don't perform checks
}

// ValidationError represents a configuration validation error
type ValidationError struct {
    Checker  string
    Field    string
    Message  string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation error in %s: %s - %s", e.Checker, e.Field, e.Message)
}

// ResultBuilder helps construct AuditResults with a fluent interface
type ResultBuilder struct {
    result AuditResult
}

// NewResultBuilder creates a new ResultBuilder
func NewResultBuilder(name string) *ResultBuilder {
    return &ResultBuilder{
        result: AuditResult{
            Name:      name,
            Status:    StatusChecking,
            StartTime: time.Now(),
            Metadata:  make(map[string]any),
        },
    }
}

// WithDescription sets the description
func (rb *ResultBuilder) WithDescription(desc string) *ResultBuilder {
    rb.result.Description = desc
    return rb
}

// WithStatus sets the status
func (rb *ResultBuilder) WithStatus(status string) *ResultBuilder {
    rb.result.Status = status
    return rb
}

// AddDetail adds a detail to the result
func (rb *ResultBuilder) AddDetail(detail string) *ResultBuilder {
    rb.result.Details = append(rb.result.Details, detail)
    return rb
}

// AddFinding adds a finding to the result
func (rb *ResultBuilder) AddFinding(finding Finding) *ResultBuilder {
    rb.result.Findings = append(rb.result.Findings, finding)
    return rb
}

// WithMetadata adds metadata to the result
func (rb *ResultBuilder) WithMetadata(key string, value any) *ResultBuilder {
    rb.result.Metadata[key] = value
    return rb
}

// Build completes the result and returns it
func (rb *ResultBuilder) Build() AuditResult {
    rb.result.EndTime = time.Now()
    rb.result.Duration = rb.result.EndTime.Sub(rb.result.StartTime)
    return rb.result
}

// FindingBuilder helps construct Findings with a fluent interface
type FindingBuilder struct {
    finding Finding
}

// NewFindingBuilder creates a new FindingBuilder
func NewFindingBuilder(title string) *FindingBuilder {
    return &FindingBuilder{
        finding: Finding{
            Title:    title,
            Metadata: make(map[string]any),
        },
    }
}

// WithDescription sets the description
func (fb *FindingBuilder) WithDescription(desc string) *FindingBuilder {
    fb.finding.Description = desc
    return fb
}

// WithSeverity sets the severity
func (fb *FindingBuilder) WithSeverity(severity string) *FindingBuilder {
    fb.finding.Severity = severity
    return fb
}

// WithCategory sets the category
func (fb *FindingBuilder) WithCategory(category string) *FindingBuilder {
    fb.finding.Category = category
    return fb
}

// WithImpact sets the impact
func (fb *FindingBuilder) WithImpact(impact string) *FindingBuilder {
    fb.finding.Impact = impact
    return fb
}

// WithResolution sets the resolution
func (fb *FindingBuilder) WithResolution(resolution string) *FindingBuilder {
    fb.finding.Resolution = resolution
    return fb
}

// AddReference adds a reference
func (fb *FindingBuilder) AddReference(title, url, refType string) *FindingBuilder {
    fb.finding.References = append(fb.finding.References, Reference{
        Title: title,
        URL:   url,
        Type:  refType,
    })
    return fb
}

// WithMetadata adds metadata
func (fb *FindingBuilder) WithMetadata(key string, value any) *FindingBuilder {
    fb.finding.Metadata[key] = value
    return fb
}

// Build returns the constructed Finding
func (fb *FindingBuilder) Build() Finding {
    return fb.finding
}

// Helper functions for result formatting
func FormatDetail(symbol string, format string, args ...interface{}) string {
    return fmt.Sprintf("%s %s", symbol, fmt.Sprintf(format, args...))
}

func FormatWarning(format string, args ...interface{}) string {
    return FormatDetail(SymbolWarning, format, args...)
}

func FormatError(format string, args ...interface{}) string {
    return FormatDetail(SymbolError, format, args...)
}

func FormatSuccess(format string, args ...interface{}) string {
    return FormatDetail(SymbolOK, format, args...)
}

func FormatInfo(format string, args ...interface{}) string {
    return FormatDetail(SymbolInfo, format, args...)
}