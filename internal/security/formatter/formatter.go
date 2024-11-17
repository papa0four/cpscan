// internal/security/formatter/formatter.go
package formatter

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "strings"
    "text/template"
    "time"

	"gopkg.in/yaml.v3"
    "github.com/papa0four/cpscan/internal/security/audit"
    "github.com/papa0four/cpscan/internal/security/types"
)

// OutputFormat represents supported output formats
type OutputFormat string

const (
    FormatText OutputFormat = "text"
    FormatJSON OutputFormat = "json"
    FormatYAML OutputFormat = "yaml"
)

// FormatOptions configures the output formatting
type FormatOptions struct {
    Format        OutputFormat
    Verbose       bool
    ColorOutput   bool
    TemplateFile  string
    MinSeverity   string
    IncludeSystem bool
    Compact       bool
}

// Formatter handles the formatting of audit results
type Formatter struct {
    options FormatOptions
    writer  io.Writer
}

// NewFormatter creates a new formatter with the specified options
func NewFormatter(w io.Writer, opts FormatOptions) *Formatter {
    return &Formatter{
        options: opts,
        writer:  w,
    }
}

// Format formats the audit result according to the specified options
func (f *Formatter) Format(result *audit.AuditResult) error {
    switch f.options.Format {
    case FormatJSON:
        return f.formatJSON(result)
    case FormatYAML:
        return f.formatYAML(result)
    default:
        return f.formatText(result)
    }
}

// formatJSON handles JSON output formatting
func (f *Formatter) formatJSON(result *audit.AuditResult) error {
    // Convert result to map for customization
    data := f.prepareOutput(result)

    encoder := json.NewEncoder(f.writer)
    if !f.options.Compact {
        encoder.SetIndent("", "  ")
    }
    
    return encoder.Encode(data)
}

// formatYAML handles YAML output formatting
func (f *Formatter) formatYAML(result *audit.AuditResult) error {
    data := f.prepareOutput(result)
    return yaml.NewEncoder(f.writer).Encode(data)
}

// formatText handles text output formatting
func (f *Formatter) formatText(result *audit.AuditResult) error {
    var tmpl *template.Template
    var err error

    if f.options.TemplateFile != "" {
        tmpl, err = template.ParseFiles(f.options.TemplateFile)
    } else {
        tmpl, err = template.New("audit").Parse(defaultTemplate)
    }

    if err != nil {
        return fmt.Errorf("template error: %w", err)
    }

    data := f.prepareOutput(result)
    return tmpl.Execute(f.writer, data)
}

// prepareOutput prepares the audit result for output
func (f *Formatter) prepareOutput(result *audit.AuditResult) map[string]interface{} {
    output := make(map[string]interface{})

    // Add metadata
    output["timestamp"] = time.Now().UTC().Format(time.RFC3339)
    output["duration"] = result.Duration.String()

    // Add system information if requested
    if f.options.IncludeSystem {
        output["system"] = result.SystemInfo
    }

    // Filter and format check results
    var formattedResults []map[string]interface{}
    for _, check := range result.Results {
        if formattedCheck := f.formatCheck(check); formattedCheck != nil {
            formattedResults = append(formattedResults, formattedCheck)
        }
    }
    output["results"] = formattedResults

    // Add summary
    output["summary"] = map[string]interface{}{
        "total_checks":    result.Summary.TotalChecks,
        "passed_checks":   result.Summary.PassedChecks,
        "warning_checks":  result.Summary.WarningChecks,
        "failed_checks":   result.Summary.FailedChecks,
        "skipped_checks":  result.Summary.SkippedChecks,
    }

    return output
}

// formatCheck formats a single check result
func (f *Formatter) formatCheck(check types.AuditResult) map[string]interface{} {
    formatted := make(map[string]interface{})

    formatted["name"] = check.Name
    formatted["status"] = check.Status
    formatted["description"] = check.Description
    formatted["duration"] = check.Duration.String()

    // Filter findings by severity
    var relevantFindings []map[string]interface{}
    for _, finding := range check.Findings {
        if isSeverityRelevant(finding.Severity, f.options.MinSeverity) {
            formattedFinding := map[string]interface{}{
                "title":       finding.Title,
                "severity":    finding.Severity,
                "category":    finding.Category,
            }

            if f.options.Verbose {
                formattedFinding["description"] = finding.Description
                formattedFinding["impact"] = finding.Impact
                formattedFinding["resolution"] = finding.Resolution
                formattedFinding["references"] = finding.References
                formattedFinding["metadata"] = finding.Metadata
            }

            relevantFindings = append(relevantFindings, formattedFinding)
        }
    }

    if len(relevantFindings) > 0 {
        formatted["findings"] = relevantFindings
    }

    if f.options.Verbose {
        formatted["details"] = check.Details
        formatted["metadata"] = check.Metadata
    }

    return formatted
}

// Helper functions

func isSeverityRelevant(findingSeverity, minSeverity string) bool {
    severityMap := map[string]int{
        "LOW":      0,
        "MEDIUM":   1,
        "HIGH":     2,
        "CRITICAL": 3,
    }

    findingLevel, ok1 := severityMap[strings.ToUpper(findingSeverity)]
    minLevel, ok2 := severityMap[strings.ToUpper(minSeverity)]

    if !ok1 || !ok2 {
        return true // Include if severity levels are unknown
    }

    return findingLevel >= minLevel
}

// ColorizeText adds ANSI color codes to text if color output is enabled
func (f *Formatter) ColorizeText(text, color string) string {
    if !f.options.ColorOutput {
        return text
    }

    colors := map[string]string{
        "red":    "\033[31m",
        "green":  "\033[32m",
        "yellow": "\033[33m",
        "blue":   "\033[34m",
        "reset":  "\033[0m",
    }

    if code, ok := colors[color]; ok {
        return fmt.Sprintf("%s%s%s", code, text, colors["reset"])
    }

    return text
}

// Default text template
const defaultTemplate = `
Security Audit Report
====================
Generated: {{.timestamp}}
Duration: {{.duration}}

{{if .system}}
System Information
-----------------
OS: {{.system.OS}}
Architecture: {{.system.Architecture}}
Hostname: {{.system.Hostname}}
Kernel Version: {{.system.KernelVersion}}
Software Count: {{.system.SoftwareCount}}
{{if .verbose}}
Software Info:
{{.system.SoftwareInfo}}
{{end}}
{{end}}

Check Results
------------
{{range .results}}
Check: {{.name}}
Status: {{.status}}
Description: {{.description}}
Duration: {{.duration}}

{{if .findings}}
Findings:
{{range .findings}}
  - [{{.severity}}] {{.title}}
  {{- if $.verbose}}
    Description: {{.description}}
    Impact: {{.impact}}
    Resolution: {{.resolution}}
    {{if .references}}
    References:
    {{range .references}}
      * {{.title}}: {{.url}}
    {{end}}
    {{end}}
  {{end}}
{{end}}
{{end}}

{{if .details}}
Details:
{{range .details}}
  {{.}}
{{end}}
{{end}}
{{end}}

Summary
-------
Total Checks: {{.summary.total_checks}}
Passed: {{.summary.passed_checks}}
Warnings: {{.summary.warning_checks}}
Failed: {{.summary.failed_checks}}
Skipped: {{.summary.skipped_checks}}
`

// JSON/YAML schema version
const SchemaVersion = "1.0"

// Custom time format for outputs
const TimeFormat = "2006-01-02T15:04:05Z07:00"

// Helper function for error formatting
func FormatError(err error) string {
    var buf bytes.Buffer
    fmt.Fprintf(&buf, "Error: %v\n", err)
    if f, ok := err.(interface{ StackTrace() string }); ok {
        fmt.Fprintf(&buf, "\nStack Trace:\n%s", f.StackTrace())
    }
    return buf.String()
}