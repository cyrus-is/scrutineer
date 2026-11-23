---
name: scrutineer-setup
description: >
  One-shot setup of the full Scrutineer skill set for the current repository. Use this skill whenever the user
  says /scrutineer-setup, asks to "install scrutineer", "set up the review skills", "bootstrap scrutineer here",
  or wants all four scrutineer-* skills (servicemap, code, security, mcp) installed at once. This skill is the
  Claude-driven front door: it produces a service map by running the agentic crawl itself, then calls the shared
  installer to copy the static skills and generate the review skills — so the result is a correct, map-aware
  skill set with the right names. The equivalent non-agentic path is the `scrutineer install` CLI.
---

# /scrutineer-setup

Install the complete Scrutineer toolkit into the current repository in one step. The end state is five
commands in `.claude/commands/`, all correctly named, with the review skills generated from a fresh
service map:

| Command | Source | How it gets there |
|---|---|---|
| `/scrutineer-servicemap` | `generate-servicemap/SKILL.md` | copied |
| `/scrutineer-mcp` | `mcp-review/SKILL.md` | copied |
| `/scrutineer-setup` | `scrutineer-setup/SKILL.md` | copied (so this skill can be re-run later) |
| `/scrutineer-code` | `generate-peer-review/generate.py` | generated, map-aware |
| `/scrutineer-security` | `generate-security-review/generate.py` | generated, map-aware |

The one thing only you (Claude) can do that the CLI cannot is the **agentic service-map crawl**. So this skill
does the crawl, then hands the resulting `servicemap.json` to the shared installer for the deterministic work.

## Invocation

```
/scrutineer-setup [--no-servicemap] [--force]
```

- `--no-servicemap`: skip the crawl and generate map-less skills (faster; no cross-service analysis).
- `--force`: overwrite existing command files / service map without prompting.

## Steps

### 1. Locate the toolkit and confirm the target

- The **target repo** is the current working directory unless the user names another path.
- Find the Scrutineer **toolkit** (the clone holding the generators). In order:
  1. If the `scrutineer` CLI is on PATH (`which scrutineer`), use it — it embeds everything.
  2. Else look for a clone (e.g. `~/Projects/scrutineer`); if you cannot find one, ask the user for its path.
- Confirm target and toolkit paths with the user before writing anything outside the target's
  `.claude/commands/`.

### 2. Produce the service map (the agentic part)

Unless `--no-servicemap` was passed:

- If `servicemap.json` already exists at the target root and the user did not pass `--force`, reuse it.
- Otherwise **perform the service-map crawl yourself**, following the full process in the
  `scrutineer-servicemap` skill (`.claude/commands/scrutineer-servicemap.md` once installed, or
  `generate-servicemap/SKILL.md` in a clone): the four-phase deep crawl
  (discovery → deep dive → trace connections → assemble) writing `servicemap.json` to the target root.
- Validate it: `scrutineer servicemap validate servicemap.json` (from a clone without the CLI:
  `python <toolkit>/generate-servicemap/validate_servicemap.py servicemap.json`).

Do not shell out to `claude -p` for this — you are already Claude. Run the crawl inline.

### 3. Run the shared installer for the deterministic steps

Hand your freshly crawled map to the installer, which copies the static skills and runs the two
generators. Use whichever entry point is available:

```bash
# Preferred — installed CLI:
scrutineer install <target> --service-map servicemap.json --force

# From a clone, no install needed:
python -m scrutineer install <target> --service-map servicemap.json --force
```

If `--no-servicemap` was requested, omit `--service-map` and the installer runs the generators with
`--no-service-map`. The installer is idempotent; pass `--force` to overwrite.

### 4. Report

Summarize what landed in `<target>/.claude/commands/`:

- `/scrutineer-servicemap`, `/scrutineer-mcp`, `/scrutineer-setup` (copied)
- `/scrutineer-code`, `/scrutineer-security` (generated; note whether they are map-aware)

Then tell the user they can run `/scrutineer-code` and `/scrutineer-security` for reviews, and
`/scrutineer-mcp <server>` to audit an MCP server.

## Notes

- This skill and the `scrutineer install` CLI share one core (`scrutineer.installer`). The only difference is
  who produces the service map: this skill crawls inline; the CLI reuses an existing map, runs `claude -p`
  with `--crawl`, or skips it.
- `/scrutineer-mcp` is standalone — it audits *external* MCP servers, not this repo, and needs no service map.
