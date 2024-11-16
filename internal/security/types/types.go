package types

// AuditResult represents the result of a security check
type AuditResult struct {
	Name			string
	Status			string
	Description		string
	Details			[]string
}

// SecurityChecker defines the interface for security checks
type SecurityChecker interface {
	Check() AuditResult
}