// Package render provides the shared output machinery for owatch commands:
// parameterized text rendering for the blocks that appear in more than one
// command's output (the enrichment six-state block, reference parsing
// errors, finding lines, suppression disclosure, and summaries), the typed
// serialization structures for enrichment data in JSON and YAML output, and
// the single TTY detection helper.
//
// Text rendering functions take data and an io.Writer only; the package has
// no dependency on cobra or on the audit engine. Command output schemas
// remain owned by their commands under the additive-only output contract --
// this package consolidates the logic beneath them, not the schemas
// themselves.
package render
