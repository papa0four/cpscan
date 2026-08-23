// internal/security/checker/finding.go
package checker

import (
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// emitFinding looks up key in the registry for osCtx and, if found, appends
// the resulting types.Finding to result.Findings. It reports whether the
// lookup succeeded, so callers needing per-run deduplication or loop control
// can act on the outcome themselves. This is the single construction path
// for every types.Finding built from a registry definition; the struct
// literal appears nowhere else in the checker package.
func emitFinding(result *types.AuditResult, osCtx registry.OSContext, key registry.FindingKey) bool {
	def, ok := registry.Lookup(osCtx, key)
	if !ok {
		return false
	}
	result.Findings = append(result.Findings, types.Finding{
		Title:       def.Title,
		Severity:    def.Severity,
		Description: def.Description,
		Categories:  def.ToCategories(),
		Impact:      def.Impact,
		Resolution:  def.Resolution,
		References:  def.ToReferences(),
	})
	return true
}

// emitFindingOnce behaves like emitFinding but only emits key once per seen.
// seen is marked only on a successful emission, never on a failed lookup, so
// a registry miss can never permanently suppress a finding that would
// otherwise have fired on a later match within the same run. This is the
// single dedup idiom for once-per-Check findings in the checker package;
// callers do not declare their own bool flags or ad hoc seen maps.
func emitFindingOnce(result *types.AuditResult, osCtx registry.OSContext, key registry.FindingKey, seen map[registry.FindingKey]struct{}) bool {
	if _, dup := seen[key]; dup {
		return false
	}
	if !emitFinding(result, osCtx, key) {
		return false
	}
	seen[key] = struct{}{}
	return true
}
