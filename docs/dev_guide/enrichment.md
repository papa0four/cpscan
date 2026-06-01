# Enrichment Subsystem

## Overview

The enrichment subsystem annotates local audit findings with live data from external CVE intelligence sources. It is invoked when the user
passes the `--enrich` flag to `security_audit` or `all`. Enrichment runs after the local audit completes, leaving baseline audit latency
unaffected when the flag is not set.

The subsystem lives at `internal/security/enrichment/`. Source-specific adapters implement the `Enricher` interface, and the orchestrator in
`internal/security/audit/audit.go` invokes them with the deduplicated list of CVE references collected from local findings.

This document describes the iniital design decisions made for the scaffolding of the enrichment feature. Any future updates to the
implementation design, or feature enhancements will be outlined within this document.

## Design Decisions

### 1. Normalized type with per-field source attribution

`CVEEnrichment` is a normalized structure shared across all enrichment sources. Each field that can carry data from an external source is
paired with a source tag identifying which adapter provided the value.

When multiple sources contribute data for the same CVE, conflicts are visible to the analyst rather than silently resolved by overwrite. This matters for security work — different sources can disagree on CVSS scoring, affected versions, or exploitation status, and an analyst
needs to see those disagreements to make informed decisions.

### 2. Adapter pattern for source pluggability

The `Enricher` interface defines what an enrichment source must do. Each source is an independent implementation of the interface. The
orchestrator does not know which sources are configured — it works against the interface.

Adding a new source requires implementing the interface and registering the implementation in the constructor. No changes to orchestration,
rendering, or audit code are required.

### 3. Batch orchestration model

Local audit checks run first and complete fully before any enrichment is attempted. The full audit result is assembled, the CVE references
across all findings are collected and deduplicated, and the enrichment call is made once with the complete CVE list.

This isolates network-dependent work from local diagnostic work. A network failure cannot affect the local audit result. A slow enrichment
source cannot delay local results from being computed.

### 4. Partial results with typed failures

`EnrichmentResult` carries both `Successes` (a map of successfully enriched CVEs to their data) and `Failures` (a map of CVEs that could
not be enriched along with the reason). The renderer surfaces both.

A future `Retry` operation can re-run enrichment for only the failed CVEs without re-querying ones that already succeeded. The
`EnrichmentFailure` type carries a `Retryable` boolean so the retry operation can skip permanent failures (malformed CVE IDs, sources
declaring the CVE does not exist).

### 5. Adapter-side caching

Each adapter is responsible for its own caching. NVD updates daily, CISA KEV updates weekly, and EPSS updates daily — different sources
have different freshness rules, and a single cache TTL at the orchestrator level cannot honor all of them correctly.

Adapters may cache, must honor explicit cache bypass via `EnrichRequest.BypassCache`, and must treat cache state as a performance optimization rather than a correctness guarantee.
 
### 6. Adapter-side rate limiting

Each adapter is responsible for honoring its source's rate limits. NVD's public API permits 5 requests per 30 seconds without an API
key and 50 requests per 30 seconds with one. CISA KEV is a single bulk download. Each adapter manages its own throttling internally
and respects context cancellation while waiting.

### 7. Concurrency safety expectations

The orchestrator may invoke adapters concurrently when multiple sources are configured. Adapter implementations must therefore be
safe to call concurrently. Adapters that maintain internal state (rate limiters, caches, connection pools) must protect that state.

### 8. CVE ID validation

CVE identifiers are validated against `^CVE-\d{4}-\d{4,}$` at three points: when extracted from registry references, when added to an
`EnrichRequest`, and when an adapter constructs URLs or query strings. Invalid identifiers are rejected before any network call or string
construction occurs.

This belt-and-suspenders validation prevents injection of crafted identifiers into URLs, query strings, or downstream parsing logic.

### 9. API key handling

API keys are read only from environment variables. Keys are never read from configuration files committed to disk, never written to logs,
and never serialized into audit results or rendered output. Adapters that require keys but cannot find them in the environment return an
initialization error.

### 10. Local audit independence

Enrichment failures never affect local audit results. The audit `Result` is fully populated by local checks before enrichment is
invoked. If enrichment fails entirely, the result still contains complete local findings and the failure is surfaced separately to
the user with guidance on how to investigate.

### 11. Error returned when no enricher is configured

In the scaffolding branch, no adapter implementations are shipped. `NewEnricher` returns `ErrNoEnricherConfigured`. The orchestrator
detects this condition and surfaces a clear message to the user explaining that enrichment is not yet available, while still
completing the local audit normally.

A no-op implementation that silently returns empty results was not shipped because it would hide from the user that enrichment did
nothing. Returning a typed error makes the system's current capability honest to the user.

## Implementing a New Enrichment Source

This section is for contributors adding a new adapter.

### Package placement

Each adapter lives in its own file within `internal/security/enrichment/`. The file is named after the source: `nvd.go` for the NVD adapter, `kev.go` for CISA KEV, and so on. The type implementing the `Enricher` interface follows the same convention: `nvdEnricher`, `kevEnricher`.

### Interface conformance

The adapter type must satisfy the `Enricher` interface defined in `enricher.go`. Both `Enrich` and any required initialization functions
must be implemented. The constructor for the adapter returns the interface type, not the concrete type, to keep the orchestrator
decoupled from implementations.

### Validation requirements

CVE identifiers received in an `EnrichRequest` must be re-validated inside the adapter before being used in any network call or string
construction. The orchestrator validates at the boundary, but adapters are responsible for their own input safety.

### Caching expectations

If the adapter caches results, the cache must honor the `BypassCache` field on `EnrichRequest`. Cache invalidation rules must
match the source's freshness guarantees. The cache must not be the sole source of truth — a cache miss must always fall back to the
live source.

### Rate limiting expectations

The adapter must enforce the source's published rate limits internally. Waiting for rate limit windows must respect context
cancellation so the orchestrator can cancel the operation if the overall audit times out.

### Error handling

Errors that affect specific CVEs go into `EnrichmentFailure` entries in the `Failures` map of the result. Errors that prevent the adapter
from functioning at all (initialization failure, missing API key, total network failure) are returned as the function's error value.
Partial success is the normal case — an adapter that successfully enriches some CVEs and fails on others should return both the
successes and the failures.

### Source attribution

When the adapter populates a field on `CVEEnrichment`, it must also populate the corresponding source tag identifying itself. This is
how analysts trace which source provided which data point. Adapter implementations use a stable source identifier (the exported package
constant `SourceNVD`, `SourceKEV`, etc.) rather than free-form strings.

### Testing

Each adapter ships with unit tests covering the success path, partial failure path, total failure path, rate limit behavior under context
cancellation, and validation rejection of malformed input. Network calls in tests are mocked. Integration tests against the live source
live in a build-tagged file and are not run in CI by default.

## Future Enrichment Sources

The following sources are candidates for future adapter implementation, in approximate priority order.

NVD (National Vulnerability Database) provides the foundational CVE data including current CVSS scoring, affected configurations,
references, and publication metadata. The first adapter implementation targets NVD v2 API.

CISA KEV (Known Exploited Vulnerabilities catalog) identifies CVEs with confirmed exploitation in the wild. Adds a critical signal for
prioritization beyond CVSS scoring alone.

EPSS (Exploit Prediction Scoring System) provides probability scores for likelihood of exploitation within 30 days. Complements KEV by
offering forward-looking risk signal for CVEs not yet exploited.

GHSA (GitHub Security Advisories) provides curated advisory data with detailed remediation guidance, often with patch availability and
affected version ranges more precise than NVD.

## Documentation Format for Future Updates

Files under `docs/dev_guide/` follow this structure:

1. **Overview** — what the subsystem does, where it lives, when it runs. Keep to a few paragraphs.

2. **Design Decisions** — numbered list of decisions made during implementation. Each decision gets a brief heading and a few
   paragraphs of rationale. Rationale describes why the decision was made and what it achieves. Decisions that were considered and
   rejected are not documented unless the contrast is necessary to explain the current behavior.

3. **Implementing a New X** — contributor guide for extending the subsystem. Step-by-step instructions for adding new
   implementations, with subsections covering placement, interface conformance, validation, error handling, and testing.

4. **Future X** — candidates discussed for future implementation in approximate priority order. Brief descriptions only; full design
   decisions for each future item are documented when that item is actually implemented.

5. **Documentation Format for Future Updates** — only the first subsystem document includes this section, to establish the
   pattern. Subsequent documents follow the established format without repeating these instructions.

Section headers use `##` for top-level sections and `###` for subsections. Code blocks use language tags when the language is
unambiguous. Line wrapping is at 72 columns to keep diffs readable. File names, type names, and function names use inline code
formatting. Cross-references to other documents in `docs/dev_guide/` use relative paths.