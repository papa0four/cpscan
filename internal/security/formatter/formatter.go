// internal/security/formatter/formatter.go
package formatter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// OutputFormat represents supported output formats
type OutputFormat string

// Output format constants define the supported report output formats
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
func (f *Formatter) Format(result *audit.Result) error {
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
func (f *Formatter) formatJSON(result *audit.Result) error {
	// Convert result to map for customization
	data := f.prepareOutput(result)

	encoder := json.NewEncoder(f.writer)
	if !f.options.Compact {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(data)
}

// formatYAML handles YAML output formatting
func (f *Formatter) formatYAML(result *audit.Result) error {
	data := f.prepareOutput(result)
	return yaml.NewEncoder(f.writer).Encode(data)
}

// formatText handles text output formatting
func (f *Formatter) formatText(result *audit.Result) error {
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
func (f *Formatter) prepareOutput(result *audit.Result) map[string]interface{} {
	output := make(map[string]interface{})

	// Add metadata
	output["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	output["duration"] = result.Duration.String()
	output["verbose"] = f.options.Verbose
	output["non_verbose"] = !f.options.Verbose

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
		"total_checks":   result.Summary.TotalChecks,
		"passed_checks":  result.Summary.PassedChecks,
		"warning_checks": result.Summary.WarningChecks,
		"failed_checks":  result.Summary.FailedChecks,
		"skipped_checks": result.Summary.SkippedChecks,
		"duration":       result.Duration.String(),
	}

	hasFindings := false
	for _, r := range formattedResults {
		if _, ok := r["findings"]; ok {
			hasFindings = true
			break
		}
	}
	output["has_findings"] = hasFindings
	output["enrichment_requested"] = result.EnrichmentRequested
	output["enrichment_error"] = ""
	if result.EnrichmentError != nil {
		output["enrichment_error"] = result.EnrichmentError.Error()
	}
	output["reference_cwes"] = result.References.CWEs
	output["reference_errors"] = formatReferenceErrors(result.References.Errors)
	output["enrichment_entries"] = buildEnrichmentEntries(result)
	output["enrichment_failures"] = buildEnrichmentFailures(result)

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
			symbol, label := types.SeverityFormat(finding.Severity)
			formattedFinding := map[string]interface{}{
				"title":    finding.Title,
				"severity": finding.Severity,
				"category": finding.Category,
				"symbol":   symbol,
				"label":    label,
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

func formatReferenceErrors(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}

func buildEnrichmentEntries(result *audit.Result) []map[string]interface{} {
	if result.Enrichment == nil {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(result.References.CWEs))
	for _, cwe := range result.References.CWEs {
		entry, ok := result.Enrichment.Successes[cwe]
		if !ok {
			continue
		}
		matches := make([]map[string]interface{}, 0, len(entry.MatchedCVEs))
		for _, match := range entry.MatchedCVEs {
			symbol, label := types.SeverityFormat(match.CVSSSeverity)
			matches = append(matches, map[string]interface{}{
				"cve_id":          match.CVEID,
				"source":          string(match.Source),
				"cvss_base_score": match.CVSSBaseScore,
				"cvss_severity":   match.CVSSSeverity,
				"symbol":          symbol,
				"label":           label,
				"description":     match.Description,
				"known_exploited": match.KnownExploited,
				"patch_available": match.PatchAvailable,
			})
		}
		out = append(out, map[string]interface{}{
			"cwe_id":        cwe,
			"weakness_name": entry.WeaknessName,
			"no_matches":    string(entry.Status) == "NO_MATCHES" || len(matches) == 0,
			"matches":       matches,
		})
	}
	return out
}

func buildEnrichmentFailures(result *audit.Result) []map[string]interface{} {
	if result.Enrichment == nil || len(result.Enrichment.Failures) == 0 {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(result.Enrichment.Failures))
	for cwe, failure := range result.Enrichment.Failures {
		out = append(out, map[string]interface{}{
			"cwe_id":    cwe,
			"source":    string(failure.Source),
			"reason":    failure.Reason,
			"retryable": failure.Retryable,
		})
	}
	return out
}

// Default text template
const defaultTemplate = `Security Audit Report
====================
Generated: {{.timestamp}}
{{if .system}}
System Information
-----------------
OS: {{.system.OS}}
Architecture: {{.system.Architecture}}
Hostname: {{.system.Hostname}}
Kernel Version: {{.system.KernelVersion}}
Software Count: {{.system.SoftwareCount}}
{{end}}
Check Results
------------
{{range .results}}
Check: {{.name}}
Status: {{.status}}
Duration: {{.duration}}
{{if .findings}}Findings:
{{range .findings}}{{.symbol}} {{.label}}  {{.title}}
{{if $.verbose}}{{if .description}}  Description: {{.description}}
{{end}}{{if .impact}}  Impact: {{.impact}}
{{end}}{{if .resolution}}  Resolution: {{.resolution}}
{{end}}{{end}}{{end}}{{end}}{{if and $.verbose .details}}Raw Diagnostic Output:
{{range .details}}  {{.}}
{{end}}{{end}}
{{end}}{{if .enrichment_requested}}
Enrichment:
{{if .enrichment_error}}  Unavailable: {{.enrichment_error}}
{{else if not .reference_cwes}}  No CWE references found in current findings.
{{else if not .enrichment_entries}}  No enrichment data returned.
{{else}}{{range .enrichment_entries}}  {{.cwe_id}}{{if .weakness_name}} - {{.weakness_name}}{{end}}
{{if .no_matches}}    No CVE matches in queried sources.
{{else}}{{range .matches}}    {{.symbol}} {{.label}}  {{.cve_id}} ({{printf "%.1f" .cvss_base_score}}) [{{.source}}]
{{if $.verbose}}{{if .description}}      Description: {{.description}}
{{end}}{{if .known_exploited}}      Known Exploited: yes
{{end}}{{if .patch_available}}      Patch Available: yes
{{end}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .enrichment_failures}}
  Failed enrichments:
{{range .enrichment_failures}}    {{.cwe_id}} [{{.source}}]: {{.reason}}{{if .retryable}} (retryable){{end}}
{{end}}{{end}}{{if .reference_errors}}  Reference parsing errors:
{{range .reference_errors}}    {{.}}
{{end}}{{end}}{{end}}
Summary:
Checks Run: {{.summary.total_checks}}
Passed:     {{.summary.passed_checks}}
Warnings:   {{.summary.warning_checks}}
Failed:     {{.summary.failed_checks}}
Duration:   {{.summary.duration}}
{{if and .non_verbose .has_findings}}
Run with -v for full finding details, impact analysis, and remediation guidance.
{{end}}`
