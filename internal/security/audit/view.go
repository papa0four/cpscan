// internal/security/audit/view.go
package audit

import (
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// View is the serializable projection of a completed Result, filtered to
	// findings at or above minSeverity. It is the single shape every
	// consumer -- JSON, YAML and WriteText -- renders from, so JSON/YAML
	// and text output cannot drift from each other the way two independent
	// conversions could.
	View struct {
		Timestamp           string                    `json:"timestamp" yaml:"timestamp"`
		Duration            string                    `json:"duration" yaml:"duration"`
		SystemInfo          *osfingerprint.SystemView `json:"system_info,omitempty" yaml:"system_info,omitempty"`
		Results             []CheckView               `json:"results" yaml:"results"`
		Summary             SummaryView               `json:"summary" yaml:"summary"`
		FindingsSuppressed  int                       `json:"findings_suppressed,omitempty" yaml:"findings_suppressed,omitempty"`
		MinSeverityApplied  string                    `json:"min_severity_applied,omitempty" yaml:"min_severity_applied,omitempty"`
		EnrichmentRequested bool                      `json:"enrichment_requested" yaml:"enrichment_requested"`
		EnrichmentError     string                    `json:"enrichment_error,omitempty" yaml:"enrichment_error,omitempty"`
		ReferenceCWEs       []string                  `json:"reference_cwes,omitempty" yaml:"reference_cwes.omitempty"`
		ReferenceErrors     []string                  `json:"reference_errors,omitempty" yaml:"reference_errors,omitempty"`
		Entries             []enrichment.EntryView    `json:"enrichment_entries,omitempty" yaml:"enrichment_entries,omitempty"`
		Failures            []enrichment.FailureView  `json:"enrichment_failures,omitempty" yaml:"enrichment_failures,omitempty"`

		// minSeverity is the threshold View was build with. Unexported: it
		// never marshals, and exists only so WriteText can render an
		// accurate clean-pass message without needing separate access to
		// the command's flag state.
		minSeverity string
	}

	// CheckView is the serializable projection of a single check's result
	CheckView struct {
		Name        string        `json:"name" yaml:"name"`
		Status      string        `json:"status" yaml:"status"`
		Description string        `json:"description" yaml:"description"`
		Duration    string        `json:"duration" yaml:"duration"`
		Findings    []FindingView `json:"findings,omitempty" yaml:"findings,omitempty"`
		Details     []string      `json:"details,omitempty" yaml:"details,omitempty"`
	}

	// FindingView is the serializable projection of a single finding
	FindingView struct {
		Title       string            `json:"title" yaml:"title"`
		Severity    string            `json:"severity" yaml:"severity"`
		Categories  []string          `json:"categories,omitempty" yaml:"categories,omitempty"`
		Description string            `json:"description,omitempty" yaml:"description,omitempty"`
		Impact      string            `json:"impact,omitempty" yaml:"impact,omitempty"`
		Resolution  string            `json:"resolution,omitempty" yaml:"resolution,omitempty"`
		References  []types.Reference `json:"references,omitempty" yaml:"references,omitempty"`
	}

	// SummaryView carries per-severity finding counts and check-level
	// pass/skip totals for structured output formats
	SummaryView struct {
		TotalChecks      int `json:"total_checks" yaml:"total_checks"`
		PassedChecks     int `json:"passed_checks" yaml:"passed_checks"`
		SkippedChecks    int `json:"skipped_checks" yaml:"skipped_checks"`
		TotalFindings    int `json:"total_findings" yaml:"total_findings"`
		CriticalFindings int `json:"critical_findings" yaml:"critical_findings"`
		HighFindings     int `json:"high_findings" yaml:"high_findings"`
		MediumFindings   int `json:"medium_findings" yaml:"medium_findings"`
		LowFindings      int `json:"low_findings" yaml:"low_findings"`
	}
)

// View returns r's serializable projection, filtering each check's findings
// to those at or above minSeverity. It is the single conversion from a
// completed Result to the shape JSON, YAML, and WriteText all render from.
func (r *Result) View(minSeverity string) View {
	v := View{
		Timestamp: r.StartTime.Format(time.RFC3339),
		Duration:  r.Duration.String(),
		Summary: SummaryView{
			TotalChecks:      r.Summary.TotalChecks,
			PassedChecks:     r.Summary.PassedChecks,
			SkippedChecks:    r.Summary.SkippedChecks,
			TotalFindings:    r.Summary.TotalFindings,
			CriticalFindings: r.Summary.CriticalFindings,
			HighFindings:     r.Summary.HighFindings,
			MediumFindings:   r.Summary.MediumFindings,
			LowFindings:      r.Summary.LowFindings,
		},
		EnrichmentRequested: r.EnrichmentRequested,
		minSeverity:         minSeverity,
	}

	if r.HostInfo != nil {
		sv := r.HostInfo.View()
		v.SystemInfo = &sv
	}

	if r.EnrichmentError != nil {
		v.EnrichmentError = r.EnrichmentError.Error()
	}
	if len(r.References.CWEs) > 0 {
		v.ReferenceCWEs = r.References.CWEs
	}
	v.ReferenceErrors = enrichment.ReferenceErrorStrings(r.References.Errors)
	v.Entries = enrichment.Entries(r.References.CWEs, r.Enrichment)
	v.Failures = enrichment.Failures(r.Enrichment)

	var shownFindings int
	for _, check := range r.Results {
		cv := CheckView{
			Name:        check.Name,
			Status:      check.Status,
			Description: check.Description,
			Duration:    check.Duration.String(),
			Details:     check.Details,
		}

		for _, finding := range check.Findings {
			sev := types.EffectiveSeverity(finding)
			if !types.MeetsMinSeverity(sev, minSeverity) {
				continue
			}
			shownFindings++
			cv.Findings = append(cv.Findings, FindingView{
				Title:       finding.Title,
				Severity:    sev,
				Categories:  finding.Categories,
				Description: finding.Description,
				Impact:      finding.Impact,
				Resolution:  finding.Resolution,
				References:  finding.References,
			})
		}

		v.Results = append(v.Results, cv)
	}

	if suppressed := v.Summary.TotalFindings - shownFindings; suppressed > 0 {
		v.FindingsSuppressed = suppressed
		v.MinSeverityApplied = strings.ToUpper(minSeverity)
	}

	return v
}
