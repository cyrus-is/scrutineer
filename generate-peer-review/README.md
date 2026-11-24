# generate-peer-review

Scans a repository (and optionally a `servicemap.json`) to generate a tailored
`.claude/commands/vld8-review.md` — a Principal Engineer-level code review skill
with platform-specific pre-flight checks, focus areas, and 8 evaluation lenses.

> **Most users don't run this directly.** The top-level installer does it for you —
> `vld8 install <repo>` (or the `/vld8-setup` skill); see the
> [main README](../README.md). Run the generator directly when you want control over
> the output path, guidance file, or service-map wiring.

## Quick Start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Basic (file scanning only):
.venv/bin/python generate.py /path/to/repo

# With a service map (richer context, enables component review mode). A servicemap.json
# at the repo root is auto-discovered; pass --service-map only for a non-standard path:
.venv/bin/python generate.py /path/to/repo --service-map servicemap.json

# Dry run:
.venv/bin/python generate.py /path/to/repo --dry-run
```

## What It Does

1. **Scans** the repo for languages, frameworks, and infrastructure
2. **Loads** platform-specific pre-flight checks and focus areas from `peer_review_guidance.yaml`
3. **Optionally reads** `servicemap.json` to discover reviewable components (services + apps)
4. **Generates** a `/vld8-review` skill with four invocation modes:
   - `/vld8-review` — review current branch diff vs main
   - `/vld8-review 123` — review PR #123 (fetches, diffs, posts findings as comment)
   - `/vld8-review <component-name>` — full review of a service/app directory (requires service map)
   - `/vld8-review --deep` — deep repo-wide review tracing cross-service flows and systemic issues
5. **Embeds a verification ladder** (`verification:` in the guidance YAML) — a Phase 0 that runs
   the repo's own gate or the platform's cheap subset *before* judging anything
6. **Embeds self-healing** — flags unknown platforms and offers to enrich itself

## Cross-cutting: universal, service, client

The cross-cutting block is split three ways. It used to be one list introduced as "the
highest-value focus areas, apply to EVERY review" — and four of its six items assumed an HTTP
service with endpoints, response envelopes, billing tiers and other users. On a local-first
single-user app they were not merely unhelpful, they were literally false, which teaches a
reviewer to skim the section that claims to matter most.

`universal` is emitted always; `service` and `client` carry an `applies_when` gate that the
generated skill prints, so a reviewer skips an inapplicable set rather than forcing findings
out of it.

Two live reviews showed that **the wording, not the question, is what fails to travel**:
"guard consistency" was the best-performing item in both runs, but only once re-read from
"endpoint" to "any code path reaching the same resource". The universal set is phrased in
terms of code paths and resources for that reason; the service set keeps HTTP vocabulary
where it is genuinely apt.

## Phase 0: verify before you judge

The generated skill opens by establishing what the toolchain already proves, and converts that into
an **exclusion list** the rest of the review must honour. A review that reports a missing `Sendable`
conformance in code `swift build` accepted under Swift 6 language mode is not merely unhelpful — it
is confidently wrong, and it spends the reader's trust on the findings that are real.

Phase 0 prefers the **repo's own gate script** (`run-gate.sh`, `scripts/ci.sh`, a `Makefile`
`check:` target, the merge-gating workflow) over anything inferred: it is the most accurate
available description of what "correct" means in that repo, and it usually explains why each stage
exists. If the code under review is red, the skill stops — reviewing code that does not build is
guesswork, and the build failure is the finding. A failure the environment causes counts as a stage
not run. In PR mode, Phase 0 runs on the PR's head in a temporary worktree. Without the user's
go-ahead it runs nothing on a fork's code, and it treats a bot's PR (Dependabot's, say) as a fork.

Ladders live under `verification.platforms.<platform_key>` and carry four things: the commands
(split into per-diff and per-repo), what each proves (`proves` → the exclusion list), what remains
unproven (which is where the review's value actually is), and what never to run.

A `proves` entry for a linter, whose green run depends on configuration, lists `rules` instead of
`excludes`: each with `pattern`, `rule` (the rule ID, or several separated by commas) and `default`
(whether the rule is on without configuration), plus a `config` note that says where the config lives.
The skill renders them as a table and tells the reviewer to exclude only the rules the config enables.

## Detection: `detect_files`, `detect_content`, `detect_mode`

`detect_mode` controls how a platform block's two detection signals combine:

| Mode | Behaviour |
|---|---|
| `files` *(default)* | `detect_files` decides. `detect_content` is consulted only when a block declares no `detect_files`. |
| `all` | **Both** must match — "Swift files AND they import CloudKit". This is what a capability sub-platform needs; without it such a block fires on every repo in the language. |
| `any` | Either signal detects the platform. Opt-in, and only after validating the patterns. |

`files` is the default deliberately. Under the previous implementation `detect_content` could never
be reached for a block that declared `detect_files` — which is every block in both guidance files —
so those patterns have never been evaluated and several are wrong: `go`'s `^module\s+` and `java`'s
`^package\s+[a-z]` both match modern Swift (`package` is a Swift 5.9 access modifier), and
promoting them to a fallback detects Go and Java in a pure Swift repo.

Two matching gotchas worth knowing before adding a block:

- **Matching is `fnmatch`, not globstar.** `*` matches `/`, and `**/x` compiles to `.*/x` — "x
  preceded by at least one slash". A root-level `Package.swift` therefore never matches
  `**/Package.swift`. **Pair every `**/foo` with a bare `foo`.**
- **`component_globs`** (optional) sets which paths get named in the generated skill, for blocks
  whose `detect_files` include single manifest files rather than review surfaces. Paths are ranked
  by how much code each contributes, so the ones the skill names are the ones that matter.

## The 8 Evaluation Lenses

1. **Production Reliability** — crash paths, timeouts, degraded-mode behavior
2. **Correctness** — race conditions, lifecycle bugs, memory leaks, nil handling
3. **Data Integrity** — transactions, migration safety, cache/DB consistency
4. **Error Handling** — swallowed errors, retry storms, idempotency gaps
5. **Architecture** — layering violations, coupling, pattern consistency
6. **Operability** — logging gaps, metrics, tracing, rollback story
7. **Performance** — N+1 queries, blocking, re-renders, unbounded allocations
8. **Maintainability** — clarity, implicit assumptions, test coverage of failure modes

## Supported Platforms

**Backend:** Go, Python, Java, Node.js, Rust, C#, Ruby, PHP
**Web:** React/Next.js, Vue/Nuxt
**Mobile:** Android (Kotlin)
**Apple:** Swift (language & concurrency), SwiftUI, CloudKit, Foundation Models (on-device AI),
Swift Package Manager, Apple app target, macOS app, Swift Testing

The Apple blocks replaced a single `ios` block whose six checks were written for a UIKit app talking
to a REST API. Three were cut rather than ported: `DispatchQueue.main` misuse is a compile error
under Swift 6 main-actor isolation, retain cycles are rare in value- and actor-oriented code, and one
check hardcoded a foreign API's pagination default. The capability blocks use `detect_mode: all`, so
`cloudkit` means "Swift files **and** they import CloudKit" rather than firing on every Swift repo.
**Infra:** Terraform, Docker, GitHub Actions
**API:** OpenAPI/REST, GraphQL
**Database:** SQL (general)

## Service Map Integration

When `--service-map` is provided, the generated skill includes a component lookup table
enabling Mode 3 (full service/app review). Without it, only Mode 1 and 2 are available.

Generate a service map first: see `../generate-servicemap/`.

## Options

```
--output, -o        Output path (default: .claude/commands/vld8-review.md)
--service-map, -s   Path to servicemap.json for richer context
--guidance, -g      Custom guidance YAML path
--dry-run, -n       Preview without writing
--force, -f         Overwrite without prompting
```

## How It Differs from Security Review

| Dimension | Security Review | Peer Review |
|---|---|---|
| **Question** | "Can this be exploited?" | "Will this break? Is this right?" |
| **Findings** | Vulnerability + OWASP category | Bug/risk + failure mode + lens |
| **Severity** | CRITICAL/HIGH/MEDIUM/LOW | ISSUE/CONCERN/PASS per lens |
| **Verdict** | PASS/BLOCK | APPROVE/REQUEST CHANGES/DISCUSS |
| **Invocation** | Diff, PR, component, or `--deep` (PR findings to terminal) | Diff, PR, component, or `--deep` (PR findings posted) |
