# Scrutineer

[![Release](https://img.shields.io/github/v/release/cyrus-is/scrutineer?label=release)](https://github.com/cyrus-is/scrutineer/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/scrutineer?label=pypi)](https://pypi.org/project/scrutineer/)

Agentic code review toolkit for [Claude Code](https://claude.ai/code). Three generators that scan your repo and produce tailored review skills — a principal engineer peer review, a security audit, and a service topology map that makes both smarter — plus `/scrutineer-mcp`, a standalone auditor for the MCP servers you're about to trust.

```bash
pip install scrutineer && scrutineer install .   # adds /scrutineer-code, -security, -servicemap, -mcp to .claude/commands/
```

> **New in 1.6 — [`/scrutineer-mcp`](#mcp-review): an "npm audit" for MCP servers.** Installing an MCP server hands it tool access, data access, and usually a live credential. `/scrutineer-mcp` audits one *before* it runs — verdict (`SAFE`/`CAUTION`/`BLOCK`) + a separate data-sensitivity rating — catching unpinned installs, creds-in-URLs, read-then-send exfil paths, and tool-poisoning. Motivated by real 2025 incidents (the postmark-mcp backdoor, CVE-2025-6514).

## What's in the box

### generate-servicemap

Deep agentic crawl of your repository that produces `servicemap.json` — a machine-readable topology of all services, apps, libraries, datastores, infrastructure, and their connections.

The service map is useful on its own (architecture docs that stay current), but it also feeds into the other two tools. With a service map, peer review can trace cross-service impacts and the security review can flag unauthenticated endpoints and shared datastores.

**Four-phase crawl:**
1. **Discovery** — identify all components (services, apps, libraries, infra, datastores)
2. **Deep dive** — analyze each component's endpoints, auth, config, dependencies
3. **Trace connections** — map how components talk to each other (HTTP, gRPC, queues, DB)
4. **Assemble** — validate and output `servicemap.json` with confidence scores

Supports incremental updates — re-run it as your codebase evolves and it merges new findings with existing data, preserving manual overrides.

### generate-peer-review

Scans your repo and generates a Claude Code skill (`.claude/commands/scrutineer-code.md`) that performs principal engineer-level code review across **8 evaluation lenses**:

| Lens | What it checks |
|------|---------------|
| Production Reliability | Will this survive real traffic, failures, and edge cases? |
| Correctness | Does the logic do what it claims? |
| Data Integrity | Can data be lost, corrupted, or desynchronized? |
| Error Handling | Are errors caught, surfaced, and recoverable? |
| Architecture | Does this fit the system's patterns and boundaries? |
| Operability | Can you debug, monitor, and deploy this safely? |
| Performance | Will this scale? Any hidden N+1s, unbounded queries, or hot paths? |
| Maintainability | Will someone understand this in 6 months? |

**Four review modes:**
- **Branch diff** — review your current branch vs main
- **PR review** — review a pull request by number, optionally post findings as a PR comment
- **Component review** — full review of an entire service or app directory (requires service map)
- **Deep repo review** (`--deep`) — trace cross-service flows and surface systemic issues

The generated skill is customized to your repo's tech stack — it detects which platforms you use (Go, Python, TypeScript, Swift, Kotlin, Terraform, etc.) and includes platform-specific pre-flight checks, focus areas, and change-type signals. 15+ platforms supported via `peer_review_guidance.yaml`.

### generate-security-review

Same scan-and-generate approach, producing `.claude/commands/scrutineer-security.md` — a security auditor skill that hunts for vulnerabilities.

**Analysis flow:**
1. **Threat model** — attack surface, trust boundaries, blast radius, auth model
2. **Universal checklist** — 11 areas including auth, injection, secrets, crypto, rate limiting, dependencies
3. **Platform-specific checklists** — vulnerability patterns for 25+ platforms with OWASP mapping
4. **Agentic analysis** — input tracing from entry to storage, auth boundary auditing, attack chain reasoning

Findings are rated CRITICAL / HIGH / MEDIUM / LOW. Security review output stays in your terminal — it does not auto-post to PRs, because security findings may be sensitive.

### mcp-review

A standalone auditor for MCP servers — the `npm audit` equivalent for the [Model Context Protocol](https://modelcontextprotocol.io). Installing an MCP server grants it tool access, data access, and usually a live credential; `/scrutineer-mcp` makes that trust decision inspectable **before** the server runs. Unlike the generators, it reviews an *external* server rather than your repo, so there's no generate step — it's a static skill plus a runtime analyzer (`analyze_mcp.py`), evidence in Python and judgment in the skill.

It reports **two independent axes** — a server can be perfectly secure and still want to read every message you've ever sent:

- **Security verdict** — `SAFE / CAUTION / BLOCK`
- **Data-sensitivity rating** — `MINIMAL / LIMITED / SENSITIVE / HIGHLY_SENSITIVE` (or `UNKNOWN` when no tool surface was captured — so a server whose tools couldn't be enumerated never silently reads as low-risk)

**Static-first passes (never starts the server, calls a tool, or fetches a URL):**
1. **Config review** — install/transport/secret/scope smells (including a credential or cleartext URL hidden in a command arg, e.g. `mcp-remote http://…`), plus *provenance* (can the reviewed code be tied to what actually runs?) and *containment*
2. **Tool-surface review** — capability classification (allow/ask/deny), each hit carrying the matched-token *evidence* and a *confidence* (a name/param match outweighs one buried in prose); the data categories each tool touches; schema-intent signals that expose the benign-name/powerful-schema evasion shape; and a **tool-poisoning scan** for hidden instructions in tool descriptions (`<IMPORTANT>`-style directives, "read `~/.ssh`", covert exfil)
3. **Source review** — handler injection, secret handling, exfil paths, and obfuscation, with source safely acquired by `fetch_source.py` (resolves via registry APIs, integrity-verified, path-sanitized extraction — never runs a package manager or executes fetched code)
4. **Finding self-review** — an optional agentic false-positive sweep (`validate_findings.py`) that re-examines each candidate against its own evidence and suppresses clear mismatches *auditably* (suppress-only, with a recorded reason)

Plus **toxic combinations** (individually-tolerable capabilities that together form an attack primitive — e.g. secrets-access + network-egress = read-then-send exfil), severity- and confidence-gated so a single weak signal can't mint a false HIGH, and **approval drift** (what your client has already auto-authorized vs. what review recommends). Findings bind to a SHA-256 digest so false-positive suppressions auto-expire the moment the server's config or tool surface changes.

See [`mcp-review/README.md`](mcp-review/README.md) for the full design.

## How the tools relate

```
generate-servicemap ──→ servicemap.json
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
         generate-peer-review   generate-security-review
                    │                   │
                    ▼                   ▼
         .claude/commands/      .claude/commands/
         scrutineer-code.md      scrutineer-security.md

mcp-review ──────────→ .claude/commands/scrutineer-mcp.md
   (standalone — audits external MCP servers, no service map needed)
```

The service map is optional but recommended. Without it, peer review and security review still work — they just can't do cross-service analysis or component-level reviews. `mcp-review` stands apart from this pipeline entirely: it audits an *external* MCP server rather than your repo, so it needs neither a service map nor a generate step.

## Agent support

Scrutineer targets **Claude Code** today — the generators emit `.claude/commands/*.md` and the skills install there. Support for **Cursor**, **Gemini CLI**, and **OpenAI Codex CLI** is in progress via a shared emitter / `--target` foundation; see the [Multi-tool support milestone](https://github.com/cyrus-is/scrutineer/milestone/1).

## Quick start

The fastest path installs all four skills — correctly named and generated from a fresh service map — in one step. There are two front doors over the same shared installer; pick whichever fits where you are.

### Option A — one command (recommended)

**From Claude Code, inside your repo** — Claude crawls the service map, then installs everything:

```
/scrutineer-setup
```

(Copy `scrutineer-setup/SKILL.md` into your repo's `.claude/commands/` once to make `/scrutineer-setup` available, or just run the CLI below.)

**From the shell** — install the `scrutineer` CLI and run the installer:

```bash
pip install scrutineer                           # from PyPI
# (or from a clone: `pip install -e .`)

scrutineer install /path/to/your-repo            # map-less (fast)
scrutineer install /path/to/your-repo --crawl    # also run the servicemap crawl via `claude -p`
```

Both produce the same result in `your-repo/.claude/commands/`:

```
/scrutineer-servicemap   /scrutineer-code   /scrutineer-security   /scrutineer-mcp
```

The only difference between the front doors is **how the service map is produced**: `/scrutineer-setup` lets Claude crawl it inline; `scrutineer install` reuses an existing `servicemap.json`, runs a headless `claude -p` crawl with `--crawl`, or skips it (re-run with `--force` after you generate a map to make the skills map-aware). The deterministic copy-and-generate work is identical and lives in `scrutineer/installer.py`.

> Note: the wheel bundles the generators, guidance YAMLs, and skills under `scrutineer/_assets/`, so `pip install scrutineer` works with no clone present — `scrutineer/paths.py` resolves the bundled assets when installed and the repo-root copies when run from a clone.

### Option B — manual, step by step

The steps below are what the installer automates; use them if you want to run each tool individually.

#### 1. Generate a service map (optional, recommended)

Copy `generate-servicemap/SKILL.md` to `.claude/commands/scrutineer-servicemap.md` in your target repo:

```bash
cp generate-servicemap/SKILL.md /path/to/your-repo/.claude/commands/scrutineer-servicemap.md
```

Then in Claude Code, inside your repo:

```
/scrutineer-servicemap --path servicemap.json
```

Validate the output:

```bash
python generate-servicemap/validate_servicemap.py servicemap.json
```

#### 2. Generate review skills

```bash
# Peer review skill
python generate-peer-review/generate.py /path/to/your-repo \
  --output .claude/commands/scrutineer-code.md

# Security review skill
python generate-security-review/generate.py /path/to/your-repo \
  --output .claude/commands/scrutineer-security.md
```

Both generators **auto-discover `servicemap.json` at the repo root** when present, producing the richer cross-service-aware skill. Pass `--service-map /path/to/servicemap.json` for a non-standard location, or `--no-service-map` to deliberately skip it.

#### 3. Use the skills

In Claude Code, inside your repo:

```
/scrutineer-code                       # Review current branch diff
/scrutineer-code 123                   # Review PR #123
/scrutineer-code <component-name>      # Full review of a service/app (requires service map)
/scrutineer-code --deep                # Deep repo-wide review across services

/scrutineer-security                   # Security audit of current branch diff
/scrutineer-security 123               # Audit PR #123 (findings to terminal, not posted)
/scrutineer-security <component-name>  # Full audit of a service/app (requires service map)
/scrutineer-security --deep            # Deep repo-wide audit across services
```

#### 4. Audit an MCP server (standalone)

`mcp-review` ships its own analyzer, so set up its venv once:

```bash
cd mcp-review
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Install the skill into your repo, then run it in Claude Code:

```bash
cp mcp-review/SKILL.md /path/to/your-repo/.claude/commands/scrutineer-mcp.md
```

```
/scrutineer-mcp                                        # review every server in the auto-discovered config
/scrutineer-mcp github                                 # review one named server
/scrutineer-mcp --config .mcp.json --tools tools.json  # add a captured tools/list for the tool-surface pass
```

## Requirements

- Python 3.10+ (the tools use `X | None` type syntax)
- `pyyaml>=6.0` (`pip install pyyaml`)
- [Claude Code](https://claude.ai/code) to run the skills

## Customizing

The review tools are driven by YAML guidance files:

- **`generate-peer-review/peer_review_guidance.yaml`** — platform detection rules, pre-flight checks, focus areas, and change-type signals for peer review
- **`generate-security-review/security_guidance.yaml`** — platform detection rules, vulnerability checklists with OWASP mapping, and secure alternatives
- **`mcp-review/mcp_risk_guidance.yaml`** — config-smell definitions, sensitive-env-key patterns, the dangerous-capability taxonomy, the data-sensitivity taxonomy, and the tool-poisoning / hidden-instruction patterns for MCP review

To add a new platform or customize checks for your stack, add entries to these files. The two generators pick them up automatically and self-heal — if they detect a platform in your repo that isn't in the guidance file, they'll flag it and offer to enrich the guidance. (`mcp_risk_guidance.yaml` is read by `analyze_mcp.py`; add a pattern and open a PR.)

The service map schema is documented in `references/schema.md`.

## Supported platforms

**Backend:** Go, Python, Java, Node.js / JavaScript, Rust, C# / .NET, Ruby, PHP
**Web:** React / Next.js, Vue.js, Angular
**Mobile:** iOS (Swift), Android (Kotlin/Java), React Native, Flutter
**Infrastructure:** Terraform, Docker, Kubernetes, GitHub Actions, GitLab CI
**API:** OpenAPI / REST, GraphQL, gRPC
**Database:** SQL, MongoDB
**Auth:** JWT, OAuth 2.0

Peer review covers a subset; the security review covers the full set above.

Missing your stack? Add it to the guidance YAML and open a PR.

## License

MIT
