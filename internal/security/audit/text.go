// internal/security/audit/text.go
package audit

import (
	"fmt"
	"io"
	"strings"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// WriteText renders a completed audit as text: each check with its
// findings, the enrichment block, suppression notice, and summary. It does
// not render the system block; callers write that separately via
// osfingerprint.WriteText. The first write error, if any, is returned.
func WriteText(w io.Writer, result *Result, minSeverity string) error {
	if result == nil {
		return fmt.Errorf("audit: cannot render nil Result")
	}

	v := result.View(minSeverity)
	ew := render.NewErrWriter(w)
	var shownFindings int

	for _, check := range v.Results {
		ew.Printf("Check: %s\n", check.Name)
		ew.Printf("Status: %s\n", check.Status)
		if check.Description != "" {
			ew.Printf("Description: %s\n", check.Description)
		}
		if check.Status == types.StatusSkipped {
			ew.Printf("\n")
			continue
		}
		ew.Printf("Duration: %s\n", check.Duration)

		shownFindings += len(check.Findings)
		if len(check.Findings) > 0 {
			ew.Printf("Findings:\n")
			for _, finding := range check.Findings {
				if ew.Err() == nil {
					if err := render.FindingLine(w, "", finding.Severity, finding.Title); err != nil {
						return err
					}
				}
				if len(finding.Categories) > 0 {
					ew.Printf("  Categories: %s\n", strings.Join(finding.Categories, ", "))
				}
				if finding.Description != "" {
					ew.Printf("  Description: %s\n", finding.Description)
				}
				if finding.Impact != "" {
					ew.Printf("  Impact: %s\n", finding.Impact)
				}
				if finding.Resolution != "" {
					ew.Printf("  Resolution: %s\n", finding.Resolution)
				}
				if len(finding.References) > 0 {
					ew.Printf("  References:\n")
					for _, ref := range finding.References {
						writeReference(ew, ref)
					}
				}
			}
		} else {
			ew.Printf("Findings:\n%s No findings at or above %s severity\n",
				types.SymbolOK, strings.ToUpper(minSeverity))
		}

		if len(check.Details) > 0 {
			ew.Printf("Raw Diagnostic Output:\n")
			for _, detail := range check.Details {
				if detail == "" {
					ew.Printf("\n")
					continue
				}
				ew.Printf("  %s\n", detail)
			}
		}

		ew.Printf("\n")
	}

	if err := enrichment.Block(w, enrichment.Data{
		Requested:  result.EnrichmentRequested,
		Err:        result.EnrichmentError,
		References: result.References,
		Result:     result.Enrichment,
		Verbose:    true,
	}); err != nil {
		return err
	}

	if err := render.SuppressionNotice(w, v.Summary.TotalFindings-shownFindings,
		v.Summary.TotalFindings, minSeverity); err != nil {
		return err
	}

	return render.DetailedSummary(w, render.SummaryData{
		TotalChecks:   v.Summary.TotalChecks,
		PassedChecks:  v.Summary.PassedChecks,
		SkippedChecks: v.Summary.SkippedChecks,
		TotalFindings: v.Summary.TotalFindings,
		Shown:         shownFindings,
		Critical:      v.Summary.CriticalFindings,
		High:          v.Summary.HighFindings,
		Medium:        v.Summary.MediumFindings,
		Low:           v.Summary.LowFindings,
		Duration:      result.Duration,
	})
}

// writeReference writes a single reference as "Type: Title", appending the
// URL in parentheses when it differs from Title. registry.classifyReference
// always sets Title to the human- or ID-readable form and sets URL only
// when a distinct link exists, so the two are never printed twice.
func writeReference(ew *render.ErrWriter, ref types.Reference) {
	if ref.URL != "" && ref.URL != ref.Title {
		ew.Printf("    %s: %s (%s)\n", ref.Type, ref.Title, ref.URL)
		return
	}
	ew.Printf("    %s: %s\n", ref.Type, ref.Title)
}
