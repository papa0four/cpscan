// internal/security/enrichment/types.go
package enrichment

import "time"

// Source identifies which enrichment adapter contributed a field
// value.
type Source string

// Enrichment adapter source identifiers.
const (
	SourceNVD   Source = "NVD"
	SourceKEV   Source = "CISA-KEV"
	SourceEPSS  Source = "EPSS"
	SourceGHSA  Source = "GHSA"
	SourceMITRE Source = "MITRE-CWE"
)

// Status reports the terminal state of an enrichment attempt for a single CVE.
type Status string

// Enrichment status values.
const (
	StatusEnriched         Status = "ENRICHED"
	StatusFailed           Status = "FAILED"
	StatusNoMatches        Status = "NO_MATCHES"
	StatusNoSourcesQueried Status = "NO_SOURCES_QUERIED"
)

// CWEEnrichment is per-CWE enrichment data with per-field source
// attribution.
type CWEEnrichment struct {
	CWEID  string
	Status Status

	WeaknessName       string
	WeaknessNameSource Source

	WeaknessDescription       string
	WeaknessDescriptionSource Source

	MatchedCVEs       []CVEMatch
	MatchedCVEsSource Source

	LastQueried time.Time
}

// CVEMatch is a single CVE returned by an enrichment source as
// associated with a CWE.
type CVEMatch struct {
	CVEID         string
	Source        Source
	CVSSBaseScore float64
	CVSSSeverity  string
	CVSSVector    string

	Published    time.Time
	LastModified time.Time

	KnownExploited         bool
	ExploitPredictionScore float64
	PatchAvailable         bool

	Description string
	References  []string
}

// Failure records why enrichment for a specific CWE failed.
type Failure struct {
	CWEID     string
	Source    Source
	Reason    string
	Err       error
	Retryable bool
}

// Result is the aggregate output of an enrichment run.
type Result struct {
	Successes      map[string]CWEEnrichment
	Failures       map[string]Failure
	AdapterErrors  []error
	SourcesQueried []Source
	Duration       time.Duration
}

// EnrichRequest is the input to Enricher.Enrich.
type EnrichRequest struct {
	CWEs        []string
	BypassCache bool
	Sources     []Source
	MinSeverity string
}
