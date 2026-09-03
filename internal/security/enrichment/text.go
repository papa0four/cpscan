// internal/security/enrichment/text.go

package enrichment

import (
	"io"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// Data carries everything the enrichment text block needs to
// render, decoupled from the audit engine's result type so this package
// never has to import the orchestration layer to render its own data
type Data struct {
	Requested  bool
	Err        error
	References types.ReferenceExtraction
	Result     *Result
	Verbose    bool
}

// Block writes the six-state enrichment text rendering: not
// requested (nothing), unavailable, no CWE references, no data returned,
// per-CWE matches with optional verbose detail, and per-CWE failures.
// Reference parsing errors are appended in every rendered state. The first
// write error, if any, is returned.
func Block(w io.Writer, d Data) error {
	if !d.Requested {
		return nil
	}

	ew := render.NewErrWriter(w)
	ew.Printf("Enrichment:\n")

	if d.Err != nil {
		ew.Printf("  Unavailable: %v\n\n", d.Err)
		referenceErrors(ew, d.References)
		return ew.Err()
	}

	if len(d.References.CWEs) == 0 {
		ew.Printf("  No CWE references found in current findings.\n\n")
		referenceErrors(ew, d.References)
		return ew.Err()
	}

	if d.Result == nil {
		ew.Printf("  No enrichment data returned.\n\n")
		referenceErrors(ew, d.References)
		return ew.Err()
	}

	rendered := 0
	for _, cwe := range d.References.CWEs {
		entry, ok := d.Result.Successes[cwe]
		if !ok {
			continue
		}
		rendered++
		ew.Printf("  %s", cwe)
		if entry.WeaknessName != "" {
			ew.Printf(" - %s", entry.WeaknessName)
		}
		ew.Printf("\n")

		if entry.Status == StatusNoMatches || len(entry.MatchedCVEs) == 0 {
			ew.Printf("    No CVE matches in queried sources.\n")
			continue
		}

		for _, match := range entry.MatchedCVEs {
			symbol, label := types.SeverityFormat(match.CVSSSeverity)
			ew.Printf("    %s %s  %s (%.1f) [%s]\n",
				symbol, label, match.CVEID, match.CVSSBaseScore, match.Source)
			if d.Verbose {
				if match.Description != "" {
					ew.Printf("      Description: %s\n", match.Description)
				}
				if match.KnownExploited {
					ew.Printf("      Known Exploited: yes\n")
				}
				if match.PatchAvailable {
					ew.Printf("      Patch Available: yes\n")
				}
			}
		}
	}

	if rendered == 0 {
		ew.Printf("  No enrichment data returned.\n")
	}

	if len(d.Result.Failures) > 0 {
		ew.Printf("\n  Failed enrichments:\n")
		for _, cwe := range sortedFailureKeys(d.Result.Failures) {
			failure := d.Result.Failures[cwe]
			ew.Printf("    %s [%s]: %s", cwe, failure.Source, failure.Reason)
			if failure.Retryable {
				ew.Printf(" (retryable)")
			}
			ew.Printf("\n")
		}
	}

	ew.Printf("\n")
	referenceErrors(ew, d.References)
	return ew.Err()
}

// referenceErrors writes reference parsing errors as an indented block,
// or nothing when there are none. It is only reachable through
// Block, which owns the surrounding layout
func referenceErrors(ew *render.ErrWriter, refs types.ReferenceExtraction) {
	if len(refs.Errors) == 0 {
		return
	}
	ew.Printf("  Reference parsing errors:\n")
	for _, err := range refs.Errors {
		ew.Printf("    %v\n", err)
	}
	ew.Printf("\n")
}
