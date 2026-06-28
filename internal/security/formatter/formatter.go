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

// formatterResult is the typed output structure for JSON and YAML serialization.
// Only data fields are included; presentation state is excluded by design.
type formatterResult struct {
	Timestamp           string              `json:"timestamp" yaml:"timestamp"`
	Duration            string              `json:"duration" yaml:"duration"`
	System              *audit.SystemInfo   `json:"system_info,omitempty" yaml:"system_info,omitempty"`
	Results             []formatterCheck    `json:"results" yaml:"results"`
	Summary             formatterSummary    `json:"summary" yaml:"summary"`
	EnrichmentRequested bool                `json:"enrichment_requested" yaml:"enrichment_requested"`
	EnrichmentError     string              `json:"enrichment_error,omitempty" yaml:"enrichment_error,omitempty"`
	ReferenceCWEs       []string            `json:"reference_cwes,omitempty" yaml:"reference_cwes,omitempty"`
	ReferenceErrors     []string            `json:"reference_errors,omitempty" yaml:"reference_errors,omitempty"`
	EnrichmentEntries   []enrichmentEntry   `json:"enrichment_entries,omitempty" yaml:"enrichment_entries,omitempty"`
	EnrichmentFailures  []enrichmentFailure `json:"enrichment_failures,omitempty" yaml:"enrichment_failures,omitempty"`
}

// formatterCheck is the typed representation of a single check result.
type formatterCheck struct {
	Name        string             `json:"name" yaml:"name"`
	Status      string             `json:"status" yaml:"status"`
	Description string             `json:"description" yaml:"description"`
	Duration    string             `json:"duration" yaml:"duration"`
	Findings    []formatterFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
	Details     []string           `json:"details,omitempty" yaml:"details,omitempty"`
}

// formatterFinding is the typed representation of a single finding.
// Presentation fields (symbol, label, category) are excluded from serialization.
type formatterFinding struct {
	Title       string            `json:"title" yaml:"title"`
	Severity    string            `json:"severity" yaml:"severity"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Impact      string            `json:"impact,omitempty" yaml:"impact,omitempty"`
	Resolution  string            `json:"resolution,omitempty" yaml:"resolution,omitempty"`
	References  []types.Reference `json:"references,omitempty" yaml:"references,omitempty"`
}

// formatterSummary carries per-severity finding counts for serialized output.
type formatterSummary struct {
	TotalChecks      int    `json:"total_checks" yaml:"total_checks"`
	PassedChecks     int    `json:"passed_checks" yaml:"passed_checks"`
	SkippedChecks    int    `json:"skipped_checks" yaml:"skipped_checks"`
	TotalFindings    int    `json:"total_findings" yaml:"total_findings"`
	CriticalFindings int    `json:"critical_findings" yaml:"critical_findings"`
	HighFindings     int    `json:"high_findings" yaml:"high_findings"`
	MediumFindings   int    `json:"medium_findings" yaml:"medium_findings"`
	LowFindings      int    `json:"low_findings" yaml:"low_findings"`
	Duration         string `json:"duration" yaml:"duration"`
}

// enrichmentEntry is the typed representation of a CWE enrichment result.
type enrichmentEntry struct {
	CWEID        string            `json:"cwe_id" yaml:"cwe_id"`
	WeaknessName string            `json:"weakness_name,omitempty" yaml:"weakness_name,omitempty"`
	NoMatches    bool              `json:"no_matches" yaml:"no_matches"`
	Matches      []enrichmentMatch `json:"matches,omitempty" yaml:"matches,omitempty"`
}

// enrichmentMatch is the typed representation of a single CVE match.
type enrichmentMatch struct {
	CVEID          string  `json:"cve_id" yaml:"cve_id"`
	Source         string  `json:"source" yaml:"source"`
	CVSSBaseScore  float64 `json:"cvss_base_score" yaml:"cvss_base_score"`
	CVSSSeverity   string  `json:"cvss_severity" yaml:"cvss_severity"`
	Description    string  `json:"description,omitempty" yaml:"description,omitempty"`
	KnownExploited bool    `json:"known_exploited" yaml:"known_exploited"`
	PatchAvailable bool    `json:"patch_available" yaml:"patch_available"`
}

// enrichmentFailure is the typed representation of a failed enrichment lookup.
type enrichmentFailure struct {
	CWEID     string `json:"cwe_id" yaml:"cwe_id"`
	Source    string `json:"source" yaml:"source"`
	Reason    string `json:"reason" yaml:"reason"`
	Retryable bool   `json:"retryable" yaml:"retryable"`
}

// toFormatterResult converts an audit.Result into the typed serialization
// structure. Only data fields are included; presentation state is excluded.
func (f *Formatter) toFormatterResult(result *audit.Result) formatterResult {
	out := formatterResult{
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		Duration:            result.Duration.String(),
		EnrichmentRequested: result.EnrichmentRequested,
		Summary: formatterSummary{
			TotalChecks:      result.Summary.TotalChecks,
			PassedChecks:     result.Summary.PassedChecks,
			SkippedChecks:    result.Summary.SkippedChecks,
			TotalFindings:    result.Summary.TotalFindings,
			CriticalFindings: result.Summary.CriticalFindings,
			HighFindings:     result.Summary.HighFindings,
			MediumFindings:   result.Summary.MediumFindings,
			LowFindings:      result.Summary.LowFindings,
			Duration:         result.Duration.String(),
		},
	}

	if f.options.IncludeSystem {
		out.System = &result.SystemInfo
	}

	if result.EnrichmentError != nil {
		out.EnrichmentError = result.EnrichmentError.Error()
	}

	if len(result.References.CWEs) > 0 {
		out.ReferenceCWEs = result.References.CWEs
	}

	out.ReferenceErrors = formatReferenceErrors(result.References.Errors)
	out.EnrichmentEntries = buildTypedEnrichmentEntries(result)
	out.EnrichmentFailures = buildTypedEnrichmentFailures(result)

	for _, check := range result.Results {
		fc := formatterCheck{
			Name:        check.Name,
			Status:      check.Status,
			Description: check.Description,
			Duration:    check.Duration.String(),
		}
		if f.options.Verbose {
			fc.Details = check.Details
		}
		for _, finding := range check.Findings {
			if !isSeverityRelevant(finding.Severity, f.options.MinSeverity) {
				continue
			}
			ff := formatterFinding{
				Title:    finding.Title,
				Severity: finding.Severity,
			}
			if f.options.Verbose {
				ff.Description = finding.Description
				ff.Impact = finding.Impact
				ff.Resolution = finding.Resolution
				ff.References = finding.References
			}
			fc.Findings = append(fc.Findings, ff)
		}
		out.Results = append(out.Results, fc)
	}

	return out
}

// buildTypedEnrichmentEntries converts enrichment successes to typed structs.
func buildTypedEnrichmentEntries(result *audit.Result) []enrichmentEntry {
	if result.Enrichment == nil {
		return nil
	}
	out := make([]enrichmentEntry, 0, len(result.References.CWEs))
	for _, cwe := range result.References.CWEs {
		entry, ok := result.Enrichment.Successes[cwe]
		if !ok {
			continue
		}
		e := enrichmentEntry{
			CWEID:        cwe,
			WeaknessName: entry.WeaknessName,
			NoMatches:    string(entry.Status) == "NO_MATCHES" || len(entry.MatchedCVEs) == 0,
		}
		for _, match := range entry.MatchedCVEs {
			e.Matches = append(e.Matches, enrichmentMatch{
				CVEID:          match.CVEID,
				Source:         string(match.Source),
				CVSSBaseScore:  match.CVSSBaseScore,
				CVSSSeverity:   match.CVSSSeverity,
				Description:    match.Description,
				KnownExploited: match.KnownExploited,
				PatchAvailable: match.PatchAvailable,
			})
		}
		out = append(out, e)
	}
	return out
}

// buildTypedEnrichmentFailures converts enrichment failures to typed structs.
func buildTypedEnrichmentFailures(result *audit.Result) []enrichmentFailure {
	if result.Enrichment == nil || len(result.Enrichment.Failures) == 0 {
		return nil
	}
	out := make([]enrichmentFailure, 0, len(result.Enrichment.Failures))
	for cwe, failure := range result.Enrichment.Failures {
		out = append(out, enrichmentFailure{
			CWEID:     cwe,
			Source:    string(failure.Source),
			Reason:    failure.Reason,
			Retryable: failure.Retryable,
		})
	}
	return out
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

// formatJSON serializes the audit result to JSON using typed structs.
// Presentation fields are excluded by the type definitions.
func (f *Formatter) formatJSON(result *audit.Result) error {
	data := f.toFormatterResult(result)
	encoder := json.NewEncoder(f.writer)
	if !f.options.Compact {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(data)
}

// formatYAML serializes the audit result to YAML using typed structs.
// Presentation fields are excluded by the type definitions.
func (f *Formatter) formatYAML(result *audit.Result) error {
	data := f.toFormatterResult(result)
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
		"total_checks":      result.Summary.TotalChecks,
		"passed_checks":     result.Summary.PassedChecks,
		"skipped_checks":    result.Summary.SkippedChecks,
		"total_findings":    result.Summary.TotalFindings,
		"critical_findings": result.Summary.CriticalFindings,
		"high_findings":     result.Summary.HighFindings,
		"medium_findings":   result.Summary.MediumFindings,
		"low_findings":      result.Summary.LowFindings,
		"duration":          result.Duration.String(),
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
	output["enrichment_entries"] = buildTypedEnrichmentEntries(result)
	output["enrichment_failures"] = buildTypedEnrichmentFailures(result)

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
{{end}}{{end}}{{end}}{{if .enrichment_requested}}
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
Checks Run:      {{.summary.total_checks}}
Passed:          {{.summary.passed_checks}}
Skipped:         {{.summary.skipped_checks}}
Total Findings:  {{.summary.total_findings}}
  Critical:      {{.summary.critical_findings}}
  High:          {{.summary.high_findings}}
  Medium:        {{.summary.medium_findings}}
  Low:           {{.summary.low_findings}}
Duration:        {{.summary.duration}}
{{if and .non_verbose .has_findings}}
Run with -v for full finding details, impact analysis, and remediation guidance.
{{end}}`
