// internal/render/summary.go
package render

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// SummaryData carries the counts and duration both summary layouts render.
// Shown is the number of findings that survived the active min-severity
// threshold; the suppressed count is derived from it.
type SummaryData struct {
	TotalChecks   int
	PassedChecks  int
	SkippedChecks int
	TotalFindings int
	Shown         int
	Critical      int
	High          int
	Medium        int
	Low           int
	Duration      time.Duration
}

// suppressed returns how many findings the active min-severity threshold
// filtered out of the displayed set.
func (d SummaryData) suppressed() int {
	return d.TotalFindings - d.Shown
}

// SuppressionNotice writes the min-severity suppression disclosure, or
// nothing when no findings were suppressed.
func SuppressionNotice(w io.Writer, suppressed, total int, minSeverity string) error {
	if suppressed <= 0 {
		return nil
	}
	_, err := fmt.Fprintf(w, "%d of %d findings suppressed by --min-severity %s. "+
		"Rerun with a lower threshold or without --min-severity to see all findings.\n\n",
		suppressed, total, strings.ToUpper(minSeverity))
	return err
}

// CompactSummary writes the single-line summary used by the all command,
// expanding to total/present/suppressed counts when the min-severity
// threshold filtered out findings.
func CompactSummary(w io.Writer, d SummaryData) error {
	if s := d.suppressed(); s > 0 {
		_, err := fmt.Fprintf(w, "Summary: %d checks  %d passed  %d findings total  %d present  %d suppressed  %s\n",
			d.TotalChecks, d.PassedChecks, d.TotalFindings, d.Shown, s, d.Duration)
		return err
	}
	_, err := fmt.Fprintf(w, "Summary: %d checks  %d passed  %d findings  %s\n",
		d.TotalChecks, d.PassedChecks, d.TotalFindings, d.Duration)
	return err
}

// DetailedSummary writes the multi-line summary block used by the audit
// command, with per-severity finding counts and check-level totals. The
// first write error, if any, is returned.
func DetailedSummary(w io.Writer, d SummaryData) error {
	ew := &ErrWriter{w: w}
	ew.Printf("Summary:\n")
	ew.Printf("Checks Run:      %d\n", d.TotalChecks)
	ew.Printf("Passed:          %d\n", d.PassedChecks)
	ew.Printf("Skipped:         %d\n", d.SkippedChecks)
	if s := d.suppressed(); s > 0 {
		ew.Printf("Total Findings:  %d (%d present, %d suppressed)\n",
			d.TotalFindings, d.Shown, s)
	} else {
		ew.Printf("Total Findings:  %d\n", d.TotalFindings)
	}
	ew.Printf("  Critical:      %d\n", d.Critical)
	ew.Printf("  High:          %d\n", d.High)
	ew.Printf("  Medium:        %d\n", d.Medium)
	ew.Printf("  Low:           %d\n", d.Low)
	ew.Printf("Duration:        %v\n", d.Duration)
	return ew.err
}
