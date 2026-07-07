# Scan Registry and Composition Model

The scan registry is the single source of truth for every module, audit
check, enrichment adapter, and composing flag `owatch` knows about. It backs
three things: `--skip-modules`/`--skip-checks` validation, the audit runner's
check selection, and the filename convention used by `--report-file`. All
three derive from the same registry so they can never drift from each other.

---

## Package location

```
internal/scan/
  checks.go   -- CheckMask, CheckCategory, registryEntry, registry,
                 validateRegistry, checksByName, Codes, EnabledChecks,
                 MaskFromNames, validNamesFor
```

---

## `CheckMask` layout

`CheckMask` is a 64-bit unsigned integer. Bits are grouped into four fixed,
non-overlapping ranges:

| Range | Category | Purpose |
|---|---|---|
| Bits 0-23 | Modules | Which top-level modules are active (osinfo, software, audit, and future modules) |
| Bits 24-47 | Audit checks | Which individual checks run within the audit module |
| Bits 48-61 | Enrichment adapters | Which external enrichment sources are queried |
| Bits 62-63 | Composing flags | Cross-cutting flags that modify output regardless of module or check (e.g. `--mitre`) |

24 bits per category gives generous headroom for growth without ever needing
to renumber an existing bit. The ranges are fixed for the life of the project;
a bit's position, once assigned, never moves and is never reused even if the
entry it backed is removed.

---

## Registry design

Each entry in the registry is a `registryEntry`:

```go
type registryEntry struct {
    bit      CheckMask
    code     byte
    name     string
    flag     string
    category CheckCategory
}
```

- `bit` is the entry's position in the 64-bit mask.
- `code` is the single-byte letter used in generated filenames (e.g. `f` for
  the firewall check).
- `name` is the canonical name used in JSON/YAML output and internal logic.
- `flag` is the CLI flag name a user types (usually identical to `name`, but
  kept separate so they can diverge if a flag needs a different public name
  than its internal identifier).
- `category` places the entry into one of the four `CheckCategory` values
  (`CategoryModule`, `CategoryCheck`, `CategoryEnrichment`, `CategoryMITRE`).

The `registry` variable is an ordered slice: modules first, then checks, then
enrichment, then MITRE, alphabetical by code within each category. Ordering
matters because `Codes()` walks the registry in order to build each filename
segment deterministically.

### Permanent code assignment

Once a code letter is assigned to a bit within a category, that pairing is
permanent. If a feature is removed, its bit and code are retired, not
reassigned to something new -- a filename generated a year ago should still be
decodable using the same rules as a filename generated today. This is a
one-way door: think through the letter before adding an entry, since renaming
it later is a breaking change to every report ever produced.

### `validateRegistry()`

Called once at package init. It panics -- deliberately, at startup, not at
runtime -- if it finds:

- a duplicate bit
- a duplicate code within a category
- a duplicate name within a category
- a duplicate flag within a category

A duplicate here is a programming error, not a runtime condition a caller
should have to handle. Failing fast at init means a broken registry can never
ship silently; the binary won't even start.

### `checksByName`

Built at init, after `validateRegistry` succeeds. It indexes every entry by
both its canonical `name` and its CLI `flag`, so lookups work regardless of
which one a caller has on hand. `maxKeysPerEntry = 2` documents why the map is
sized the way it is, since each entry contributes at most two keys.

---

## Alphabetical ordering vs. bit assignment

Two different orderings are in play here, and they are not the same thing:

- **Registry slice order** -- entries within a category are sorted
  alphabetically by `code`. This is a presentation convention: it's what
  makes `Codes()`'s output readable and predictable (`c.fpsu`, not
  `c.spfu` or whatever order entries happened to be declared in).
- **Bit assignment** -- a bit is assigned to the next unused position within
  its category's range, in the order entries are introduced. This is
  permanent and is never reordered to match alphabetical position, because
  doing so would change the numeric value of `CheckMask` constants that may
  already be relied upon elsewhere.

These two orderings will diverge the moment a new entry's code sorts earlier
than an existing one. That divergence is expected and correct -- do not
"fix" it by renumbering existing bits to restore alphabetical/numeric
alignment.

### Worked example: adding a hypothetical check

Say a new audit check is added for disk encryption status, with code `d` and
canonical name `diskenc`. Alphabetically, `d` sorts before the existing check
codes (`f`, `p`, `s`, `u`), so it belongs first in the registry slice's check
entries. But bits 24-27 are already permanently assigned to
`CheckFirewall`, `CheckPerms`, `CheckSSH`, and `CheckUsers` -- so the new
check takes the next unused bit in the check range, bit 28, regardless of
where its code sorts.

This example is illustrative only; it does not reflect an actual planned
check.

**1. `internal/scan/checks.go` -- add the constant**

The new constant is declared with the next available bit, not a bit that
would preserve alphabetical/numeric alignment:

```go
CheckDiskEncryption = 1 << 28 // code 'd'
```

The comment noting reserved bits shifts accordingly, e.g. "Bits 29-47
reserved" instead of "Bits 28-47 reserved".

**2. `internal/scan/checks.go` -- insert into the registry slice**

The new `registryEntry` is inserted by alphabetical code position within
`CategoryCheck`, ahead of the firewall entry, even though its bit number
(28) is numerically higher than all of them:

```go
{bit: CheckDiskEncryption, code: 'd', name: "diskenc", flag: "diskenc", category: CategoryCheck},
{bit: CheckFirewall, code: 'f', name: "firewall", flag: "fwall", category: CategoryCheck},
{bit: CheckPerms, code: 'p', name: "permissions", flag: "fperms", category: CategoryCheck},
{bit: CheckSSH, code: 's', name: "ssh", flag: "ssh", category: CategoryCheck},
{bit: CheckUsers, code: 'u', name: "users", flag: "users", category: CategoryCheck},
```

`validateRegistry()` and `checksByName` require no manual changes -- both are
derived automatically from whatever is in `registry`.

**3. `cmd/commands/security/security.go` -- add the CLI flag**

A new boolean flag is declared alongside the existing check flags, and wired
into whatever per-flag mask-building logic `buildMask()` uses:

```go
securityCmd.Flags().BoolVar(&auditDiskEnc, "diskenc", false,
    "Run disk encryption status check")
```

**4. `cmd/commands/all.go` -- include it in `allChecks`**

The default check set `all` runs needs the new bit added:

```go
allChecks := scan.CheckSSH | scan.CheckFirewall | scan.CheckUsers |
    scan.CheckPerms | scan.CheckDiskEncryption
```

**5. Dispatch -- wire the actual checker**

Wherever `EnabledChecks()`'s output is consumed to invoke real checker
implementations (the audit runner's dispatch logic), a case mapping
`"diskenc"` to the new checker function is required. The registry entry
alone does not run anything; it only makes the name/flag/code known and
selectable.

**6. `--skip-checks` help text**

Every place the comma-separated check list is spelled out in a flag
description (both `all.go` and `security.go`) needs `diskenc` added in
alphabetical position: `diskenc, firewall, permissions, ssh, users`.

**7. `README.md`**

Four places need the new entry, each in alphabetical position:

- Audit Flags table (`owatch audit` section) -- new `--diskenc` row
- `all` Flags table -- the `--skip-checks` description
- `audit` Flags table -- the `--skip-checks` description
- Report Output's `c.` -- Audit checks table -- new `d` row

**8. YAML finding registry**

If the check produces findings, the corresponding `internal/security/registry`
YAML file needs entries with real, verified CIS/NIST citations before the
check can ship -- per the registry citation policy in `CONTRIBUTING.md`. No
placeholder or fabricated citation is acceptable, even temporarily.

### Checklist for any new registry entry (module, check, enrichment, or flag)

- [ ] Confirm the code letter doesn't collide within its category (cross-category collisions, like `c.s` and `m.s` sharing `s`, are fine)
- [ ] Assign the next unused bit within the category's range -- never an earlier one, even if the code sorts earlier
- [ ] Insert the registry entry in alphabetical-by-code position within its category
- [ ] Update the "reserved bits" comment range if it shifted
- [ ] Wire the CLI flag and any per-flag mask logic
- [ ] Update `all.go`'s default check/module set if the entry should run by default
- [ ] Wire actual dispatch/execution logic -- the registry entry alone selects nothing
- [ ] Update every `--skip-checks`/`--skip-modules` help string that spells out the list
- [ ] Update README (flags table, Report Output segment table)
- [ ] Add YAML registry entries with real citations, if the entry produces findings
- [ ] Run the full pipeline gate, including `GOOS=windows go build ./...`

---

## Deriving filenames: `Codes()`

`Codes(mask CheckMask) string` walks the registry once and groups matching
entries into their category's segment. Each populated segment gets a
single-byte prefix (`m.`, `c.`, `e.`) followed by its codes concatenated in
registry order; the composing-flag segment is unprefixed and always sits
last. Empty segments are omitted entirely -- there are never double hyphens in
a generated filename, because a missing segment simply contributes nothing to
`strings.Join`.

### Worked example: why a bit doesn't have to appear in `Codes()`

`ModuleAudit`'s bit exists in the registry (it has to, since
`--skip-modules audit` needs a valid name to validate against), but the `all`
command deliberately never sets that bit when building its mask. The reason:
skipping every check under `--skip-checks` is a validation error, so there is
no code path where the audit module ran and produced zero check bits. That
means the presence or absence of the `c.` segment already tells you
unambiguously whether the audit module ran -- an `m.a` code would be
redundant with information the `c.` segment already carries. This is worth
internalizing as a general principle before adding a new module: ask whether
the module's own bit is actually needed in `Codes()`'s output, or whether
some other segment already implies it.

### `EnabledChecks()`

Returns check *names* (not codes) for every `CategoryCheck` bit set in a
mask. This is what the audit runner actually consumes to decide which
checkers to invoke -- `Codes()` is presentation-only and is never used to
drive execution logic.

### `MaskFromNames()`

Resolves a slice of user-supplied names (from `--skip-modules` or
`--skip-checks`) into a mask, restricted to a single category. Passing a name
from the wrong category is rejected, which prevents a typo like putting a
check name into `--skip-modules` from silently doing nothing or, worse,
silently skipping the wrong thing. The valid-name list in the resulting error
is generated from the registry at call time via `validNamesFor`, so the error
message can never drift out of sync with what's actually registered.

---

## Composition model: `all` and `audit`

`owatch all` is the only entry point that runs every module in one
consolidated report. There is currently no way to explicitly invoke more than
one module by name and select which run -- the CLI framework's dispatch model
doesn't support chained subcommand invocation the way `all --skip-*` needs
it to compose. Instead, composition happens by subtraction: `all` runs
everything by default, and `--skip-modules` / `--skip-checks` narrow that
down, in either direction, together.

This is a deliberate stopgap, not the long-term design. A custom CLI parser
package (a separate, future open-source project) is the planned replacement
once the full module and enrichment registry is stable -- it would allow
explicit multi-module invocation and eventually nmap-style remote scanning
syntax. Until that lands, `all --skip-*` is the canonical way to compose a
partial scan, and any new module added to the registry should be skippable
the same way the existing ones are.

`owatch audit` (alias `security_audit`) is the single-module counterpart:
it runs one or more checks directly via boolean flags (`--ssh`, `--fwall`,
etc.), defaulting to all checks when none are given. It shares the same
registry and the same `MaskFromNames`/`Codes` machinery as `all`, so a check
added to the registry is automatically available to both commands without
either one needing its own parallel bookkeeping.

---

## Package boundaries

- **`internal/scan`** defines the mask type, the bit layout, and the
  registry. It has no concept of what an "audit" or a "report" is beyond the
  category label -- it never imports `internal/security/audit` or
  `internal/report`.
- **`internal/report`** owns filename generation mechanics (`DefaultPath`,
  hostname resolution, write-safety guards) but is agnostic of check
  vocabulary. It accepts an already-computed `codes` string; it has no idea
  what an `m.` or `c.` segment means, only that it's a string to embed in a
  filename.
- **`cmd/commands/all.go`** and **`cmd/commands/security/security.go`** are
  where mask-building (`buildAllMask`, `buildMask`) and command-specific
  concepts like `scanLabel` actually live. Neither `internal/scan` nor
  `internal/report` should ever need to know about command-line flag names.

Keeping these boundaries intact is what lets the registry serve `all`,
`audit`, and eventually new commands without any of them needing bespoke
logic to reimplement composition, validation, or filename derivation.

---

## TTY suppression pattern

Both `all.go` and `security.go` follow the same convention: verbose and
progress output is gated on whether a report file destination was given.

```go
Verbose: allVerbose && isTerminal() && allReportFile == "",
```

The intent is that a human running the tool interactively sees progress
output, but a run that's writing a report to disk -- likely scripted or
scheduled -- doesn't have that output competing with or corrupting the
generated file, and doesn't spam a log capturing stdout. Any new command that
supports `--report-file` should gate its own verbose/progress output the
same way, using its own report-file flag as the condition.

---

## Pipeline requirements

Any change to `checks.go` requires the full local pipeline gate described in
`CONTRIBUTING.md`'s Pipeline gate section before merge. `GOOS=windows go
build ./...` is non-negotiable for any registry change specifically, since
`checks.go` is imported by every platform-tagged checker package -- a change
that compiles on Linux but breaks the Windows build here fails silently until
someone builds on Windows, which is exactly the class of bug this project's
cross-platform gate exists to catch early.