# MCP Review

Audit an MCP (Model Context Protocol) server **before you trust it** — the `npm audit` equivalent for MCP
servers. Reviews an MCP server's install/config, its exposed tool surface, and its source (when obtainable),
then reports two independent things:

- **Security verdict** — `SAFE / CAUTION / BLOCK`
- **Data-sensitivity rating** — `MINIMAL / LIMITED / SENSITIVE / HIGHLY_SENSITIVE`

A server can be perfectly secure and still want to read every message you've ever sent. Those are different
questions, so they get separate answers.

## Architecture — a runtime split, not a generator

Unlike `generate-peer-review` and `generate-security-review` (which scan the **host repo** at generate time
and emit a tailored skill), `/mcp-review` reviews an **external** MCP server — independent of whatever repo
you're in. There's no per-repo tailoring axis, so there's no generation step. The closer analog in this repo
is `generate-servicemap`: a static skill plus a runtime Python helper.

| Piece | Role |
|---|---|
| `analyze_mcp.py` | **Deterministic half.** Parses config + `tools/list`, flags known patterns reproducibly, tags data categories, computes stable digests. Produces *evidence, never verdicts*. |
| `fetch_source.py` | **Safe-acquisition half of Pass 3.** Resolves + downloads source via registry HTTP APIs (or a commit-pinned GitHub tarball), verifies integrity, and extracts with a path-sanitizing extractor. Never invokes npm/pip/git; never executes fetched code. Emits a manifest with `source_artifact_match`. |
| `SKILL.md` | **Judgment half.** Reads the analyzer's JSON, reviews source when available, reasons about risk and chains, assigns the verdict. Copied to `.claude/commands/mcp-review.md`. |
| `mcp_risk_guidance.yaml` | Tunable catalog: config-smell definitions, sensitive-env-key patterns, package-runner/shell lists, the dangerous-capability taxonomy, and the data-sensitivity taxonomy. |

Detection stays deterministic in Python for reproducibility, and because **digest-bound suppression needs
real hashing** a prompt can't do reliably.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Install the skill into your target repo (or use Claude Desktop's commands dir):

```bash
cp SKILL.md /path/to/your-repo/.claude/commands/mcp-review.md
```

Then in Claude Code:

```
/mcp-review                    # review every server in the auto-discovered config
/mcp-review github             # review one named server
/mcp-review --config .mcp.json --tools github-tools.json
```

Or run the analyzer directly:

```bash
# Config review (Pass 1)
.venv/bin/python analyze_mcp.py --config claude_desktop_config.json

# Config + tool surface (Pass 1 + 2)
.venv/bin/python analyze_mcp.py --config .mcp.json --server github --tools tools.json

# With suppressions reconciled
.venv/bin/python analyze_mcp.py --config .mcp.json --tools tools.json \
  --suppressions .claude/mcp-review-suppressions.json
```

Safely fetch a server's source for Pass 3 (never runs npm/pip/git, never executes fetched code):

```bash
# Offline plan — what it would fetch + the predicted source_artifact_match
.venv/bin/python fetch_source.py --npm "@scope/pkg@1.2.3"

# Actually download + extract into a throwaway dir (gated behind --fetch)
.venv/bin/python fetch_source.py --analysis analysis.json --server github --fetch
.venv/bin/python fetch_source.py --github owner/repo --ref <40-hex-sha> --fetch
```

## The three passes (static-first)

It never starts the server, calls a tool, or fetches a URL. Requiring the server to run would mean you
already executed the thing you're trying to evaluate.

1. **Config review** — parse the `mcpServers` map; flag shell wrappers, on-the-fly package-runner installs,
   unpinned/mutable sources, non-HTTPS remotes, credentials-in-URL, sensitive-credential requirements, and
   broad filesystem scope. Detects — but **never echoes** — live secret values, so the report stays
   shareable.
2. **Tool-surface review** — consume a captured `tools/list` response. Tag each tool's *candidate
   capabilities* (a recall-oriented prefilter, `basis: declared`), the *data categories* it touches, and
   *schema-intent signals* (power params, destructive flags, arbitrary input) that expose the
   benign-name/powerful-schema evasion shape. The skill refines candidates against schema semantics and
   handler source, weighting implementation over naming.
3. **Source review** — whenever source is obtainable, review the handlers for injection, secret handling,
   exfil paths, supply-chain risk, and **obfuscation** (a BLOCK signal). Acquisition is handled by
   `fetch_source.py`, not a package manager: it resolves the artifact via the registry HTTP APIs (or a
   commit-pinned GitHub tarball), verifies the integrity digest, and extracts with a path-sanitizing
   extractor that rejects zip-slip, symlinks, hardlinks, absolute paths, and special files — never invoking
   npm/pip/git and never executing fetched code. Its manifest reports `source_artifact_match`
   (verified/unverifiable/unfetchable), turning the Phantom-Artifact check ("is the reviewed source the code
   that runs?") into a checked fact instead of a manual judgment. Closed-source/binary servers degrade
   gracefully: config + tools only, capped at `CAUTION`, clearly labeled.

Two cross-cutting evidence layers feed the verdict:

- **Provenance** — `pin_strength` (commit_sha/exact › version_tag › range › latest/none) and
  `runtime_binding_confidence` answer "can I tie reviewed code to what runs?" An unbindable artifact
  (`npx`/`@latest`, floating git ref, remote endpoint, closed-source) **cannot be SAFE** — it caps at
  CAUTION.
- **Containment** — transport, localhost/network exposure, filesystem scope, sandbox evidence, privilege
  notes.
- **Toxic combinations** — individually-tolerable capabilities that together form an attack primitive
  (read-then-send exfil, exec+secrets, fs-mutation+egress, broad-read+egress), emitted as first-class HIGH
  findings.

The verdict is **hard blockers first, then a two-axis judgment** (capability severity × inspection
confidence) — not a weighted sum of smells. `SAFE` always means "no material issues *within the inspected
scope*," paired with coverage and binding language; it is never presented as absolute.

**Approval drift** (`--allowlist`) — the trust picture includes what the client has *already authorized*.
The analyzer parses a `settings.json` / `.mcp.json` `permissions` block and flags tools sitting in the
allow-list whose capabilities warrant ask/deny, server-level wildcard grants (auto-approve current + future
tools), blanket approval (`enableAllProjectMcpServers`), and the egress-tool-plus-sensitive-filesystem
escalation (a complete read-then-send path → BLOCK).

## Digest-bound suppression

Every finding binds to a SHA-256 digest of the fields that change the trust decision (server:
transport/command/args/env-key-names/url — **secret values excluded**; tool: name/description/schema). A
suppression matches only while its digest is unchanged, so editing a server's args or a tool's schema makes
the finding **re-enter review automatically**. Stale suppressions (bound to a digest no longer present) are
surfaced for pruning.

```json
{
  "suppressions": [
    {"scope": "server", "code": "broad_filesystem_scope", "digest": "sha256:…", "reason": "dev box"},
    {"scope": "tool",   "code": "network_egress",         "digest": "sha256:…", "reason": "reviewed"}
  ]
}
```

## Customizing

Edit `mcp_risk_guidance.yaml`:

- **`config_smells`** — finding definitions (severity, category, rationale, recommendation).
- **`lists`** — shell binaries, package runners, placeholder markers, broad filesystem paths.
- **`sensitive_env_key_patterns`** — regexes for credential-like env-key names.
- **`dangerous_capabilities`** — tool capability taxonomy (patterns + default allow/ask/deny).
- **`data_sensitivity`** — data-category taxonomy (patterns + sensitivity tier).

Detection logic lives in `analyze_mcp.py`; this YAML is the data it keys off. Add a pattern, open a PR.

## Tests

A dependency-free smoke + regression suite guards the guarantees that matter (secret no-echo,
redaction-stable digests, pin heuristics, schema-intent, toxic combinations, approval drift):

```bash
.venv/bin/python tests/test_analyze_mcp.py
.venv/bin/python tests/test_fetch_source.py   # extractor safety: zip-slip, symlink, bombs, no-exec
```

`test_fetch_source.py` builds hostile archives **in memory** (no network) and asserts the extractor refuses
zip-slip, symlinks, hardlinks, absolute paths, and special files, caps tar/zip bombs, never executes a
fetched `postinstall`, and that `source_artifact_match` tracks the pin (and is disqualified by tampering).

Fixtures live in `tests/fixtures/` (a 5-server config, a tool surface, and an over-granting allowlist) and
contain only placeholders — no live-looking secrets are committed.

## Requirements

- Python 3.10+ (uses `X | None` type syntax)
- `pyyaml>=6.0`
- [Claude Code](https://claude.ai/code) to run the `/mcp-review` skill

## Status

Built and tested (`tests/test_analyze_mcp.py`, 50 checks; `tests/test_fetch_source.py`, 54 checks):
`analyze_mcp.py`, `fetch_source.py`, `mcp_risk_guidance.yaml`, `SKILL.md`. Originated from issue #2, shaped
by the two-pass / static-first / digest-bound-suppression design discussion there and external review rounds
that added the provenance, containment, toxic-combination, schema-intent, explicit-rubric, and approval-drift
layers, plus a security review that closed secret-leak / digest-stability gaps (URL & CLI-arg redaction).

Pass 3 source acquisition is now a deterministic, sandboxed step (`fetch_source.py`, issue #22) rather than
prose rules in `SKILL.md`: registry-HTTP resolution, integrity-verified download, a path-sanitizing
extractor, and a `source_artifact_match` manifest — closing the Phantom-Artifact gap as a checked fact. It
never invokes a package manager and never executes fetched code.
