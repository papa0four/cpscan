# Contributing to orkowatch

orkowatch is a cross-platform host security auditing CLI. These conventions
keep `dev` known-good and make intent explicit for anyone picking up the work.

## Priorities

Every decision is weighed in this order, and none is compromised for
short-term ease:

1. Scalable
2. Optimal
3. Thorough
4. Safe
5. Modular

## Branch naming

`<type>/<issue#>-<short-description>`

- Types: `bug`, `enhancement`, `chore`, `docs`, `infrastructure`
- Issue number is the GitHub issue this branch resolves
- Description is lowercase, hyphen-separated, short enough to read at a glance

Example: `chore/77-add-issue-pr-and-branch-templates`

## Workflow

- One problem at a time. Cut sub-branches one at a time to avoid rebase debt.
- Sub-branches merge into their parent before the parent merges up.
- `dev` is always known-good. `main` holds tagged releases only.
- Open the matching GitHub issue before cutting the branch.

## Pipeline gate

The full local pipeline must pass before any merge:

- `gofmt -w .`
- `go build ./...`
- `go vet ./...`
- `gosec ./...`
- `govulncheck ./...`
- `golangci-lint run --timeout=5m`
- `GOOS=windows go build ./...` for any cross-platform change

## Pull requests

- Follow the PR template. Fill the `Closes #` line with the issue number so
  the linked issue auto-closes on merge.
- Keep the `## Summary` / `## Changes` / `## Verified` structure.

## Registry citations

YAML registry entries require verified citable sources (CIS, NIST, or
equivalent). Fabricated or stretched citations are not accepted. A check idea
taken from a reference manual still needs a primary citation behind the entry.

## Code conventions

- Comments explain why, briefly. Naming carries meaning. Verbose explanation
  lives in docs, not code.
- Exported types and functions get doc comments in the `Name ...` form.
- Named constants for domain values; structural indices may stay literal.
- Use merge/merged/merging, not promote.