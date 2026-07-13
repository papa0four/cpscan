// internal/render/enrichment.go
package render

import (
	"io"
	"sort"

	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// EnrichmentData carries everything the enrichment text block needs,
// decoupled from the audit engine's result type so this package never
// imports the orchestration layer.
type EnrichmentData struct {
	Requested  bool
	Err        error
	References types.ReferenceExtraction
	Result     *enrichment.Result
	Verbose    bool
}

type (
	// EnrichmentMatch is the typed serialization of a single CVE match for
	// JSON and YAML command output.
	EnrichmentMatch struct {
		CVEID          string  `json:"cve_id" yaml:"cve_id"`
		Source         string  `json:"source" yaml:"source"`
		CVSSBaseScore  float64 `json:"cvss_base_score" yaml:"cvss_base_score"`
		CVSSSeverity   string  `json:"cvss_severity" yaml:"cvss_severity"`
		Description    string  `json:"description,omitempty" yaml:"description,omitempty"`
		KnownExploited bool    `json:"known_exploited" yaml:"known_exploited"`
		PatchAvailable bool    `json:"patch_available" yaml:"patch_available"`
	}

	// EnrichmentEntry is the typed serialization of a single CWE's
	// enrichment result for JSON and YAML command output.
	EnrichmentEntry struct {
		CWEID        string            `json:"cwe_id" yaml:"cwe_id"`
		WeaknessName string            `json:"weakness_name,omitempty" yaml:"weakness_name,omitempty"`
		NoMatches    bool              `json:"no_matches" yaml:"no_matches"`
		Matches      []EnrichmentMatch `json:"matches,omitempty" yaml:"matches,omitempty"`
	}

	// EnrichmentFailure is the typed serialization of a failed per-CWE
	// enrichment lookup for JSON and YAML command output.
	EnrichmentFailure struct {
		CWEID     string `json:"cwe_id" yaml:"cwe_id"`
		Source    string `json:"source" yaml:"source"`
		Reason    string `json:"reason" yaml:"reason"`
		Retryable bool   `json:"retryable" yaml:"retryable"`
	}
)

// EnrichmentBlock writes the six-state enrichment text rendering: not
// requested (nothing), unavailable, no CWE references, no data returned,
// per-CWE matches with optional verbose detail, and per-CWE failures.
// Reference parsing errors are appended in every rendered state. The first
// write error, if any, is returned.
func EnrichmentBlock(w io.Writer, d EnrichmentData) error {
	if !d.Requested {
		return nil
	}

	ew := &errWriter{w: w}
	ew.printf("Enrichment:\n")

	if d.Err != nil {
		ew.printf("  Unavailable: %v\n\n", d.Err)
		referenceErrors(ew, d.References)
		return ew.err
	}

	if len(d.References.CWEs) == 0 {
		ew.printf("  No CWE references found in current findings.\n\n")
		referenceErrors(ew, d.References)
		return ew.err
	}

	if d.Result == nil {
		ew.printf("  No enrichment data returned.\n\n")
		referenceErrors(ew, d.References)
		return ew.err
	}

	rendered := 0
	for _, cwe := range d.References.CWEs {
		entry, ok := d.Result.Successes[cwe]
		if !ok {
			continue
		}
		rendered++
		ew.printf("  %s", cwe)
		if entry.WeaknessName != "" {
			ew.printf(" - %s", entry.WeaknessName)
		}
		ew.printf("\n")

		if entry.Status == enrichment.StatusNoMatches || len(entry.MatchedCVEs) == 0 {
			ew.printf("    No CVE matches in queried sources.\n")
			continue
		}

		for _, match := range entry.MatchedCVEs {
			symbol, label := types.SeverityFormat(match.CVSSSeverity)
			ew.printf("    %s %s  %s (%.1f) [%s]\n",
				symbol, label, match.CVEID, match.CVSSBaseScore, match.Source)
			if d.Verbose {
				if match.Description != "" {
					ew.printf("      Description: %s\n", match.Description)
				}
				if match.KnownExploited {
					ew.printf("      Known Exploited: yes\n")
				}
				if match.PatchAvailable {
					ew.printf("      Patch Available: yes\n")
				}
			}
		}
	}

	if rendered == 0 {
		ew.printf("  No enrichment data returned.\n")
	}

	if len(d.Result.Failures) > 0 {
		ew.printf("\n  Failed enrichments:\n")
		for _, cwe := range sortedFailureKeys(d.Result.Failures) {
			failure := d.Result.Failures[cwe]
			ew.printf("    %s [%s]: %s", cwe, failure.Source, failure.Reason)
			if failure.Retryable {
				ew.printf(" (retryable)")
			}
			ew.printf("\n")
		}
	}

	ew.printf("\n")
	referenceErrors(ew, d.References)
	return ew.err
}

// sortedFailureKeys returns the failure map's CWE keys in ascending order,
// giving both the text block and the serialization converters one shared
// definition of failure ordering.
func sortedFailureKeys(failures map[string]enrichment.Failure) []string {
	keys := make([]string, 0, len(failures))
	for cwe := range failures {
		keys = append(keys, cwe)
	}
	sort.Strings(keys)
	return keys
}

// referenceErrors writes reference parsing errors as an indented block,
// or nothing when there are none. It is only reachable through
// EnrichmentBlock, which owns the surrounding layout.
func referenceErrors(ew *errWriter, refs types.ReferenceExtraction) {
	if len(refs.Errors) == 0 {
		return
	}
	ew.printf("  Reference parsing errors:\n")
	for _, err := range refs.Errors {
		ew.printf("    %v\n", err)
	}
	ew.printf("\n")
}

// EnrichmentEntries converts enrichment successes into typed serialization
// structs, in the same CWE order as refs.CWEs so output order is stable
// across runs.
func EnrichmentEntries(refs types.ReferenceExtraction, res *enrichment.Result) []EnrichmentEntry {
	if res == nil {
		return nil
	}
	out := make([]EnrichmentEntry, 0, len(refs.CWEs))
	for _, cwe := range refs.CWEs {
		entry, ok := res.Successes[cwe]
		if !ok {
			continue
		}
		e := EnrichmentEntry{
			CWEID:        cwe,
			WeaknessName: entry.WeaknessName,
			NoMatches:    entry.Status == enrichment.StatusNoMatches || len(entry.MatchedCVEs) == 0,
		}
		for _, match := range entry.MatchedCVEs {
			e.Matches = append(e.Matches, EnrichmentMatch{
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

// EnrichmentFailures converts enrichment failures into typed serialization
// structs, sorted by CWE ID so serialized output order is stable across
// runs -- Go map iteration order is randomized and would otherwise produce
// nondeterministic diffs in reports.
func EnrichmentFailures(res *enrichment.Result) []EnrichmentFailure {
	if res == nil || len(res.Failures) == 0 {
		return nil
	}
	out := make([]EnrichmentFailure, 0, len(res.Failures))
	for _, cwe := range sortedFailureKeys(res.Failures) {
		failure := res.Failures[cwe]
		out = append(out, EnrichmentFailure{
			CWEID:     cwe,
			Source:    string(failure.Source),
			Reason:    failure.Reason,
			Retryable: failure.Retryable,
		})
	}
	return out
}

// ReferenceErrorStrings converts reference parsing errors into strings for
// JSON and YAML output.
func ReferenceErrorStrings(errs []error) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}
