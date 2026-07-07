# owatch User Guide

This guide is the comprehensive reference for using `owatch` day to day: every
command, every flag, what each audit check actually evaluates, how output and
report filenames are structured, and what to expect from the tool at its
current stage of development. For a quick-start version and installation
instructions, see the project [README](../README.md); this guide goes deeper
and is intended to remain accurate even if read on its own, since it is a
candidate for future in-binary access (see Roadmap at the end).

---

## Who this guide is for

Security analysts, engineers, and system administrators running `owatch`
against a host to audit its configuration, inventory its software, or
fingerprint its OS. It assumes `owatch` is already installed and on `PATH`;
see the README's Installation section if it is not.

---

## Command reference

### `owatch osinfo`

Gathers OS fingerprint information: OS name, kernel version, and
architecture. No flags beyond the global `-h`/`--help`.

```bash
owatch osinfo
```

### `owatch software`

Lists installed software packages. On Linux, this reads the distribution's
package database; on Windows, it reads the registry uninstall keys across
both 64-bit and 32-bit locations for both machine-wide and per-user installs,
falling back to `wmic` if the registry read returns nothing (a warning is
printed when this fallback triggers, since `wmic` is deprecated as of Windows
10 21H1).

```bash
owatch software
```

### `owatch audit` (alias: `owatch security_audit`)

Runs one or more security checks directly, selected via boolean flags. With
no check flags given, all four checks run.

| Flag | Description | Default |
|---|---|---|
| `--ssh` | Run SSH configuration check | false |
| `--fwall` | Run firewall configuration check | false |
| `--users` | Run user accounts check | false |
| `--fperms` | Check permissions of specified path | — |
| `--skip-checks` | Comma-separated checks to skip (firewall, permissions, ssh, users) | — |
| `-o, --output` | Output format: text, json, yaml | text |
| `--report-file` | Save report to directory; filename is generated automatically | — |
| `--min-severity` | Minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL | LOW |
| `--timeout` | Maximum audit duration | 10m |
| `--enrich, -e` | Query external sources to annotate findings with CVEs mapped to referenced CWEs (currently has no effect -- see Known Limitations) | false |
| `--allow-elevated-write` | Permit an elevated write outside the allowlisted directories | false |
| `-v, --verbose` | Enable verbose output | false |

```bash
owatch audit -v
owatch audit --ssh --fwall
owatch audit --min-severity HIGH -o json --report-file /path/to/reports
```

#### What each check evaluates

**Firewall (`--fwall`, code `f`).** Detects whether a recognized firewall
manager -- `iptables`, `ufw`, `firewalld`, or `pfctl` -- is active. If none
are active, every listening service on the host is reachable on all
interfaces with no host-based packet filtering as a defense-in-depth layer.

**Permissions (`--fperms`, code `p`).** Checks a fixed set of
security-critical paths against CIS-benchmark expected modes: `/etc/passwd`,
`/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/ssh/sshd_config`,
`/var/log`, `/home`, plus OS-specific paths (`/boot`, `/root`, `/proc`,
`/sys` on Linux; equivalents on macOS/BSD). It also scans for world-writable
files, SUID/SGID binaries, and unowned files. On Windows, it walks ACLs via
`icacls` looking for `Everyone`/`Users` groups granted full control. This is
the slowest check by a wide margin due to filesystem traversal -- see Known
Limitations.

**SSH (`--ssh`, code `s`).** Reads `sshd_config` and flags `PermitRootLogin`
and `PasswordAuthentication` if either is enabled or unset (unset settings
fall back to platform defaults, which vary and are called out explicitly
rather than assumed safe).

**Users (`--users`, code `u`).** Reads local account data (`/etc/passwd` and
`/etc/shadow` on Unix; Windows local accounts via the equivalent APIs) and
flags: any non-root account with UID 0 (root-equivalent), accounts with no
password set combined with an interactive shell, regular (non-system)
accounts with administrative group membership (`sudo`/`wheel` on Unix), and
any account with an interactive login shell at all (informational --
context determines whether this is expected).

### `owatch all`

Runs every module (osinfo, software, audit) in one consolidated report.
There is no way to explicitly invoke multiple modules and select which run --
composition happens by skipping what you don't want, in either direction:
skip whole modules, skip individual audit checks, or both together.

| Flag | Description | Default |
|---|---|---|
| `--skip-modules` | Comma-separated modules to skip (osinfo, software, audit) | — |
| `--skip-checks` | Comma-separated audit checks to skip; composes with `--skip-modules` | — |
| `-o, --output` | Output format: text, json, yaml, csv (csv not yet implemented) | text |
| `--report-file` | Save report to directory; filename is generated automatically | — |
| `--min-severity` | Minimum severity to report | LOW |
| `--timeout` | Maximum time to run all scans | 30m |
| `--enrich, -e` | Currently has no effect -- see Known Limitations | false |
| `--allow-elevated-write` | Permit an elevated write outside the allowlisted directories | false |
| `-v, --verbose` | Enable verbose output for all scans | false |

There is no per-check flag (`--ssh`, `--fwall`, etc.) on `all`. To run only
specific checks as part of a full scan, skip the others:

```bash
owatch all --skip-checks firewall,users,permissions
```

### `owatch completion`

Generates shell completion scripts for bash, zsh, fish, and PowerShell.
Requires `owatch` to be installed and on `PATH`; does not work with
`go run` during development.

```bash
source <(owatch completion bash)
```

### `owatch version`

Prints the current version. Equivalent to `-V`/`--version` on any
invocation.

### `owatch help`

Prints the full command menu. Equivalent to `-h`/`--help`. `owatch help
<command>` (e.g. `owatch help audit`) is equivalent to `owatch <command>
--help`.

---

## Output formats and resolution rules

`owatch` supports `text`, `json`, and `yaml` (`csv` is accepted on `all` but
not yet implemented). Format resolution follows this order:

1. An explicit `-o`/`--output` value always wins.
2. If `--report-file` is given without `-o`, JSON is used.
3. If neither is given, output goes to stdout as text.

Text output to a terminal includes progress messages (`[*] Running firewall
check...`) and verbose configuration details when `-v` is passed. This
output is automatically suppressed whenever `--report-file` is set, so a
scripted or scheduled run writing to disk doesn't have progress output
competing with the generated file.

---

## Report filenames

`--report-file` accepts a destination **directory**, not a file path.
`owatch` generates the filename automatically:

```
owatch-<hostname>-m.<module_codes>-c.<check_codes>-e.<enrichment_codes>-<flag_codes>-<timestamp>.<ext>
```

Segments are omitted entirely when empty -- there are never double hyphens.
Each populated segment is ordered alphabetically by its letter codes.

### `m.` — Modules

| Letter | Module | Status |
|---|---|---|
| `h` | Shell/terminal history | reserved, not yet implemented |
| `l` | Log capture (syslog, Event Log, unified logging) | reserved, not yet implemented |
| `n` | Local listener enumeration | reserved, not yet implemented |
| `o` | OS fingerprint | implemented |
| `r` | Remote network scanning | reserved, not yet implemented |
| `s` | Software inventory | implemented |

The audit module has a reserved letter (`a`) that never appears in a
filename -- whether the audit module ran is shown entirely through the
presence or absence of the `c.` segment below, since a module code there
would be redundant with that information.

### `c.` — Audit checks

| Letter | Check | Status |
|---|---|---|
| `f` | Firewall configuration | implemented |
| `p` | File permissions | implemented |
| `s` | SSH configuration | implemented |
| `u` | User accounts | implemented |

### `e.` — Enrichment adapters

| Letter | Adapter | Status |
|---|---|---|
| `g` | GHSA advisories | reserved, not yet implemented |
| `k` | CISA KEV | reserved, not yet implemented |
| `n` | NVD (CVE lookup) | reserved, not yet implemented |
| `p` | EPSS scoring | reserved, not yet implemented |

**NOTE**: No `e.` segment appears in any filename yet, since no adapter is wired.

### Composing flags

| Letter | Flag | Status |
|---|---|---|
| `m` | `--mitre` (MITRE ATT&CK mapping) | reserved, not yet implemented |

Unprefixed, always terminal when present. Does not appear in any filename
until `--mitre` lands.

### Worked example

`owatch-defender-m.os-c.fpsu-20260705T094307Z.json` decodes as: hostname
`defender`, OS fingerprint and software modules ran (`o`, `s`), all four
audit checks ran (`f`, `p`, `s`, `u`), no enrichment or composing flags,
generated at `2026-07-05T09:43:07Z`, JSON format.

Note that `c.s` (SSH check) and `m.s` (software module) sharing the letter
`s` is intentional and safe -- each category is its own namespace, and
uniqueness is enforced only within a category, not across all four.

---

## Severity levels

Severity is currently a static value assigned per finding in the registry at
authoring time, derived from CVSS v3.1 score ranges:

| Range | Severity |
|---|---|
| 0.1 – 3.9 | LOW |
| 4.0 – 6.9 | MEDIUM |
| 7.0 – 8.9 | HIGH |
| 9.0 – 10.0 | CRITICAL |

`--min-severity` filters the findings list to that threshold and above.
Summary counts (total findings, and the per-severity breakdown) are **not**
filtered -- they always reflect every finding the audit actually produced,
regardless of `--min-severity`. When filtering removes at least one
finding, this is disclosed rather than left implicit: text output prints a
line stating how many findings were suppressed and by which threshold, plus
an expanded Summary line showing total/present/suppressed counts; JSON and
YAML output gain `findings_suppressed` and `min_severity_applied` fields on
the security block. At the default threshold (`LOW`), nothing is
suppressed and output is unchanged in every format.

Severity sourcing has a single point of change (`effectiveSeverity` in
`all.go`) for when per-finding CVE/CVSS enrichment lands, at which point a
live CVSS-derived score could override the static registry value for
findings with a confirmed CVE match. Until then, every severity value is the
static registry assignment.

---

## Known limitations

`owatch` is currently pre-MVP. The following gaps exist today and will likely 
close as development continues:

- **Windows audit findings may be incomplete or inaccurate.** Permissions
  checking doesn't yet default to `C:\` with full recursive traversal, the
  users check has known false negatives on Microsoft accounts, some scans
  return zero findings when findings are expected, and some failures fail
  silently instead of surfacing an error. Tracked as a single fix (#111).
  Linux/Unix audit checks are not affected.
- **`--enrich` has no enrichment adapter to query yet.** No CVE/CWE
  enrichment source (NVD, CISA KEV, EPSS, GHSA) is wired yet, so no CVE data
  is ever added to a finding. The flag is fully wired end to end otherwise --
  passing it correctly reports that no source is configured, in both text
  and JSON/YAML output, rather than silently doing nothing.
- **`--mitre` does not exist yet.** Passing it fails as an unknown flag.
- **macOS and BSD are not supported yet.** Audit checkers exist for Windows
  and Linux/Unix only.
- **The default permissions check can be slow.** It performs a full filesystem
  traversal for SUID/SGID and world-writable file discovery; this is a
  known, tracked optimization item, not a bug.
- **No log capture, listener enumeration, or history modules yet.** Only OS
  fingerprinting, software inventory, and the four audit checks exist today.

---

## Troubleshooting

See the README's Troubleshooting section for platform-specific install and
PATH issues.

## Getting help

Open a [GitHub Issue](https://github.com/papa0four/orkowatch/issues) for
bugs or questions.

---

## Roadmap note

This guide currently ships only in the repository under `docs/user_guide.md`.
Bundling it (and the README) with the compiled binary -- for example via a
future `owatch docs` or `owatch user-guide` command backed by `go:embed` --
is a planned enhancement, tracked separately from the content of this guide
itself.