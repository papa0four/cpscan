# Enrichment Subsystem

The enrichment subsystem adds external threat context to a completed local audit.
It takes the CWE identifiers surfaced by the finding registry, queries one or more
configured adapter sources, and returns matched CVEs grouped by the CWE that
produced them. Enrichment is opt-in via `--enrich` / `-e` and always runs after
the local audit completes. Enrichment failures never affect local audit results.

---

## Package location

```
internal/security/enrichment/
  errors.go    -- sentinel error values
  types.go     -- all exported types
  validate.go  -- CWE ID normalization and validation
  enricher.go  -- Enricher interface and NewEnricher constructor
```

---

## Types

### `Source`

```go
type Source string
```

Identifies which adapter contributed a field value. Defined constants:

| Constant       | Value        |
|----------------|--------------|
| `SourceNVD`    | `"NVD"`      |
| `SourceKEV`    | `"CISA-KEV"` |
| `SourceEPSS`   | `"EPSS"`     |
| `SourceGHSA`   | `"GHSA"`     |
| `SourceMITRE`  | `"MITRE-CWE"`|

Each field on `CWEEnrichment` that may be populated by different sources carries
a parallel `*Source` field for attribution. Adapters set both the value and the
source field together.

### `Status`

```go
type Status string
```

Terminal state for an enrichment attempt on a single CWE.

| Constant                | Value                  | Meaning                                      |
|-------------------------|------------------------|----------------------------------------------|
| `StatusEnriched`        | `"ENRICHED"`           | At least one CVE match was returned          |
| `StatusFailed`          | `"FAILED"`             | All sources returned errors                  |
| `StatusNoMatches`       | `"NO_MATCHES"`         | Sources responded but found no CVE matches   |
| `StatusNoSourcesQueried`| `"NO_SOURCES_QUERIED"` | Request was valid but no sources were called |

### `CWEEnrichment`

```go
type CWEEnrichment struct {
    CWEID  string
    Status Status

    WeaknessName             string
    WeaknessNameSource       Source

    WeaknessDescription      string
    WeaknessDescriptionSource Source

    MatchedCVEs       []CVEMatch
    MatchedCVEsSource Source

    LastQueried time.Time
}
```

Per-CWE enrichment data. `MatchedCVEs` is empty when `Status` is `NO_MATCHES`.
`LastQueried` is set by the adapter; it informs cache expiry logic.

### `CVEMatch`

```go
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
```

A single CVE returned by an adapter as associated with a queried CWE.
`KnownExploited` is populated from CISA KEV data. `ExploitPredictionScore` is
populated from EPSS data. Adapters populate only the fields their source
provides; zero values are valid for unset fields.

### `Failure`

```go
type Failure struct {
    CWEID     string
    Source    Source
    Reason    string
    Err       error
    Retryable bool
}
```

Records why enrichment for a specific CWE from a specific source failed.
`Retryable` signals that the failure is transient (network timeout, rate limit)
and the caller may retry without changing input.

### `Result`

```go
type Result struct {
    Successes      map[string]CWEEnrichment
    Failures       map[string]Failure
    AdapterErrors  []error
    SourcesQueried []Source
    Duration       time.Duration
}
```

Aggregate output of an enrichment run. Keys in `Successes` and `Failures` are
canonical CWE IDs (`CWE-N`). A CWE key will appear in exactly one of the two
maps. `AdapterErrors` holds errors that affected an entire adapter rather than
a single CWE. `SourcesQueried` lists every source that was attempted regardless
of outcome.

### `EnrichRequest`

```go
type EnrichRequest struct {
    CWEs        []string
    BypassCache bool
    Sources     []Source
    MinSeverity string
}
```

Input to `Enricher.Enrich`. `CWEs` must be canonical IDs (`CWE-N`); the
adapter validates them on receipt. `BypassCache` forces a live fetch regardless
of cached data. `Sources` restricts which adapters are called; an empty slice
uses all configured adapters. `MinSeverity` filters CVE matches below a CVSS
severity threshold.

---

## Errors

All sentinels are in `errors.go` and are wrapped with `fmt.Errorf("%w", ...)` by
callers that add context.

| Sentinel                    | Meaning                                                                 |
|-----------------------------|-------------------------------------------------------------------------|
| `ErrNoEnricherConfigured`   | `NewEnricher` was called but no adapter is registered                   |
| `ErrInvalidCWEID`           | A CWE identifier failed format validation                               |
| `ErrEmptyRequest`           | `EnrichRequest.CWEs` was empty                                          |
| `ErrMissingAPIKey`          | An adapter that requires an API key found none in the environment       |

---

## Validation

`validate.go` exposes three functions. All three accept both canonical (`CWE-N`)
and MITRE URL (`https://cwe.mitre.org/data/definitions/N.html`) forms and
normalize to canonical.

### `NormalizeCWEID(input string) (string, error)`

Returns the canonical `CWE-N` form. Returns an error wrapping `ErrInvalidCWEID`
if the input matches neither accepted form or contains non-digit characters in
the numeric segment.

### `ValidateCWEID(input string) error`

Returns `nil` for valid input. Equivalent to calling `NormalizeCWEID` and
discarding the normalized string. Use when only validity matters.

### `NormalizeCWEIDs(inputs []string) (valid []string, errs []error)`

Bulk normalization. Returns two slices: canonical IDs that passed validation and
errors for those that did not. Rejects input slices larger than 10,000 entries
with a single error. Does not deduplicate.

**Validation rules enforced by all three functions:**

- Input must have the prefix `CWE-` (canonical) or match the MITRE URL pattern.
- The numeric segment following `CWE-` must be one or more ASCII digits only.
- Minimum total length of the canonical form is 5 characters (`CWE-` + one digit).
- No Unicode digits; only bytes `0x30`--`0x39` are accepted.

---

## Interface

### `Enricher`

```go
type Enricher interface {
    Enrich(ctx context.Context, req EnrichRequest) (Result, error)
    Source() Source
}
```

Every adapter implements this interface. Implementations must be safe for
concurrent use. `Source()` returns the `Source` constant for that adapter,
used by the orchestrator for attribution and logging.

### `NewEnricher() (Enricher, error)`

Returns the configured enricher. Until at least one adapter is registered,
`NewEnricher` returns `nil, ErrNoEnricherConfigured`. This is the correct
production state while no adapters exist.

---

## How enrichment is orchestrated

The orchestration path lives in `internal/security/audit/audit.go`. The sequence
is:

1. `RunAudit` or `runAllChecks` completes all local checkers.
2. `finalize` is called on the result.
3. `finalize` calls `aggregateReferences` which calls `AllCWEReferences()` across
   every `AuditResult.Findings` slice and stores the deduplicated extraction in
   `audit.Result.References`.
4. If `Options.Enrich` is false, `finalize` returns.
5. `NewEnricher()` is called. If it returns `ErrNoEnricherConfigured`, the error
   is stored in `audit.Result.EnrichmentError` and `finalize` returns. Local
   results are unaffected.
6. If `References.CWEs` is empty, `finalize` returns without calling the enricher.
7. Otherwise `Enrich` is called with a context scoped to `Options.Timeout`.
8. On success, `*enrichment.Result` is stored in `audit.Result.Enrichment`.
9. On failure, the error is stored in `audit.Result.EnrichmentError`.

`audit.Result.EnrichmentRequested` is always set from `Options.Enrich`
regardless of outcome, so the renderer can distinguish "not requested" from
"requested but failed."

### `audit.Options.Enrich`

```go
type Options struct {
    // ...
    Enrich bool
}
```

Set by `security_audit --enrich` / `-e` and `all --enrich` / `-e`.

### `audit.Result` enrichment fields

```go
type Result struct {
    // ...
    EnrichmentRequested bool
    EnrichmentError     error
    Enrichment          *enrichment.Result
    References          types.ReferenceExtraction
}
```

`References` is always populated after `finalize` regardless of whether
enrichment was requested. It is reused by the renderer to drive the enrichment
output section.

---

## Reference extraction

The bridge between registry findings and enrichment input is in
`internal/security/types/types.go`.

### `Finding.CWEReferences() ReferenceExtraction`

Iterates `Finding.References`, normalizes every entry with `Type == "CWE"` via
`enrichment.NormalizeCWEID`, deduplicates by canonical ID, and separates
non-CWE references into `ReferenceExtraction.Other`. Normalization failures are
collected into `ReferenceExtraction.Errors`.

### `AuditResult.AllCWEReferences() ReferenceExtraction`

Aggregates `CWEReferences()` across all findings in one `AuditResult`.
Deduplication is applied across the full set; order matches first occurrence.
Errors from all findings are concatenated.

### `ReferenceExtraction`

```go
type ReferenceExtraction struct {
    CWEs   []string
    Errors []error
    Other  []ClassifiedReference
}
```

`CWEs` is the input to `EnrichRequest.CWEs`. `Errors` are surfaced in the
rendered output's reference parsing errors section. `Other` is available for
future use.

### `ClassifiedReference`

```go
type ClassifiedReference struct {
    Type  string
    Value string
}
```

A non-CWE reference from a finding, annotated with its `RefType*` classification.

---

## Registry integration

`Finding.References` is populated in every checker via
`registry.FindingDefinition.ToReferences()`. Checkers call `registry.Lookup` to
retrieve the `FindingDefinition` for a key, then assign the return of
`ToReferences()` to the `Finding.References` field.

### `FindingDefinition.ToReferences() []types.Reference`

Converts the flat `[]string` YAML `references` field into `[]types.Reference`.
Each string is classified by `classifyReference` using the following rules (in
priority order):

| Prefix / pattern                                  | Assigned `Type`  |
|---------------------------------------------------|------------------|
| `CWE-` or `https://cwe.mitre.org/`               | `RefTypeCWE`     |
| `CVE-` or `https://nvd.nist.gov/vuln/detail/CVE-`| `RefTypeCVE`     |
| `CIS `                                            | `RefTypeCIS`     |
| `NIST `                                           | `RefTypeNIST`    |
| `MITRE `                                          | `RefTypeMITRE`   |
| `https://` or `http://`                           | `RefTypeURL`     |
| anything else                                     | `RefTypeOther`   |

CWE references get a generated MITRE URL in `Reference.URL`. CVE references get
a generated NVD URL. Other types populate only `Title`.

---

## Rendering

Rendering lives in two places.

**`internal/security/formatter/formatter.go`** handles JSON and YAML output
via `prepareOutput`, which populates the following template keys when
`enrichment_requested` is true:

| Key                   | Source                                          |
|-----------------------|-------------------------------------------------|
| `enrichment_requested`| `audit.Result.EnrichmentRequested`             |
| `enrichment_error`    | `audit.Result.EnrichmentError.Error()` or `""` |
| `reference_cwes`      | `audit.Result.References.CWEs`                 |
| `reference_errors`    | `formatReferenceErrors(result.References.Errors)` |
| `enrichment_entries`  | `buildEnrichmentEntries(result)`               |
| `enrichment_failures` | `buildEnrichmentFailures(result)`              |

**`cmd/commands/security/security.go`** handles plain-text output via
`renderEnrichmentBlock` and `renderReferenceErrors`. These are called from
`formatText` (the text-mode output path) and implement the six rendering states
described in the output design.

### Rendering states (text mode)

| Condition                                          | Output                                              |
|----------------------------------------------------|-----------------------------------------------------|
| `EnrichmentError != nil`                           | `Unavailable: <error>`                              |
| `References.CWEs` empty                            | `No CWE references found in current findings.`      |
| `Enrichment == nil`                                | `No enrichment data returned.`                      |
| CWE present in `Successes`, status `NO_MATCHES`    | `No CVE matches in queried sources.`                |
| CWE present in `Successes` with matches            | CVE list with severity symbol, score, source        |
| `Enrichment.Failures` non-empty                    | Per-CWE failure with retryable indicator            |

`References.Errors` (reference parsing errors) always render when non-empty,
regardless of which enrichment state applies.

---

## Adapter authoring guide

Adapters are not yet implemented. When writing the first adapter, follow these
requirements.

### Location

Each adapter gets its own subdirectory under `internal/security/enrichment/`:

```
internal/security/enrichment/nvd/
    nvd.go
```

The adapter package must not import `types`, `registry`, `audit`, or any other
internal orkowatch package. The enrichment package is a leaf; adapters extend it
as siblings, not dependents.

### Interface

The adapter type must satisfy `enrichment.Enricher`:

```go
func (a *NVDAdapter) Enrich(ctx context.Context, req enrichment.EnrichRequest) (enrichment.Result, error)
func (a *NVDAdapter) Source() enrichment.Source
```

### Validation

Call `enrichment.NormalizeCWEIDs(req.CWEs)` at the start of `Enrich`. Return
`enrichment.ErrEmptyRequest` if the normalized slice is empty after validation.
Record per-CWE normalization errors as `Failure` entries in the result.

### API keys

Read API keys from environment variables only. Never log, serialize, or return
key material. Return `enrichment.ErrMissingAPIKey` when a required key is absent.
Document the expected environment variable name in the adapter's package comment.

### Caching

Implement caching inside the adapter. Cache freshness rules differ per source;
the adapter owns that logic. `EnrichRequest.BypassCache` must skip the cache
when true.

### Rate limiting

Implement rate limiting inside the adapter. Do not rely on callers to throttle.

### Concurrency

Adapters must be safe for concurrent invocation. The orchestrator may call
`Enrich` from multiple goroutines.

### Result population

For each CWE that returns results, populate a `CWEEnrichment` entry in
`Result.Successes` with the canonical CWE ID as the key. Set `Status` to the
appropriate constant. For each failure, populate `Result.Failures` with the
canonical CWE ID as the key. Set `Retryable` accurately -- it is displayed to
the user and used to decide whether a retry is appropriate.

### Registering the adapter

Update `NewEnricher` in `enricher.go` to return the configured adapter once at
least one is available. Multi-adapter orchestration (concurrent fan-out via
`errgroup`) is the planned model; `NewEnricher` will evolve accordingly.

---

## YAML registry -- adding references

The reference strings in each YAML file are the source of all CWE input to the
enrichment subsystem. The classifier in `ToReferences` determines what gets
extracted as a CWE.

To add a CWE reference to an existing finding, add an entry to the `references`
list in the relevant YAML file using canonical form:

```yaml
ssh.weak_algorithms:
  title: Weak SSH Key Exchange Algorithms Enabled
  severity: HIGH
  references:
    - CWE-326
    - CWE-327
    - NIST SP 800-57
```

Both `CWE-N` and the full MITRE URL are accepted. The classifier normalizes
both to canonical form before extraction. Only strings that pass CWE validation
will appear in `EnrichRequest.CWEs`; malformed entries are collected into
`ReferenceExtraction.Errors` and surfaced in the rendered output.

YAML files are embedded at compile time via `go:embed`. Changes take effect on
the next build.
