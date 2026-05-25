# generate-peer-review

Scans a repository (and optionally a `servicemap.json`) to generate a tailored
`.claude/commands/scrutineer-code.md` — a Principal Engineer-level code review skill
with platform-specific pre-flight checks, focus areas, and 8 evaluation lenses.

> **Most users don't run this directly.** The top-level installer does it for you —
> `scrutineer install <repo>` (or the `/scrutineer-setup` skill); see the
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
4. **Generates** a `/scrutineer-code` skill with four invocation modes:
   - `/scrutineer-code` — review current branch diff vs main
   - `/scrutineer-code 123` — review PR #123 (fetches, diffs, posts findings as comment)
   - `/scrutineer-code <component-name>` — full review of a service/app directory (requires service map)
   - `/scrutineer-code --deep` — deep repo-wide review tracing cross-service flows and systemic issues
5. **Embeds self-healing** — flags unknown platforms and offers to enrich itself

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
**Mobile:** iOS (Swift), Android (Kotlin)
**Infra:** Terraform, Docker, GitHub Actions
**API:** OpenAPI/REST, GraphQL
**Database:** SQL (general)

## Service Map Integration

When `--service-map` is provided, the generated skill includes a component lookup table
enabling Mode 3 (full service/app review). Without it, only Mode 1 and 2 are available.

Generate a service map first: see `../generate-servicemap/`.

## Options

```
--output, -o        Output path (default: .claude/commands/scrutineer-code.md)
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
