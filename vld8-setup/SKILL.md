---
name: vld8-setup
description: >
  One-shot setup of the full vld8 skill set for the current repository. Use this skill whenever the user
  says /vld8-setup, asks to "install vld8", "set up the review skills", "bootstrap vld8 here",
  or wants all the vld8-* skills (map, review, security, mcp) installed at once. This skill is the
  Claude-driven front door: it produces a service map by running the agentic crawl itself, then calls the shared
  installer to copy the static skills and generate the review skills — so the result is a correct, map-aware
  skill set with the right names. The equivalent non-agentic path is the `vld8 install` CLI.
---

# /vld8-setup

Install the complete vld8 toolkit into the current repository in one step. The end state is five
commands in `.claude/commands/`, all correctly named, with the review skills generated from a fresh
service map:

| Command | Source | How it gets there |
|---|---|---|
| `/vld8-map` | `generate-servicemap/SKILL.md` | copied |
| `/vld8-mcp` | `mcp-review/SKILL.md` | copied |
| `/vld8-setup` | `vld8-setup/SKILL.md` | copied (so this skill can be re-run later) |
| `/vld8-review` | `generate-peer-review/generate.py` | generated, map-aware |
| `/vld8-security` | `generate-security-review/generate.py` | generated, map-aware |

The one thing only you (Claude) can do that the CLI cannot is the **agentic service-map crawl**. So this skill
does the crawl, then hands the resulting `servicemap.json` to the shared installer for the deterministic work.

## Invocation

```
/vld8-setup [--no-servicemap] [--force] [--preview <milestone>]
```

- `--no-servicemap`: skip the crawl and generate map-less skills (faster; no cross-service analysis).
- `--force`: overwrite existing command files / service map without prompting.
- `--preview <milestone>`: include review output still behind that milestone's preview flag, e.g. `2.1`.
  Repeatable. `vld8 install --help` lists the milestones that have one.

## Steps

### 1. Locate the toolkit and confirm the target

- The **target repo** is the current working directory unless the user names another path.
- Find the vld8 **toolkit** (the clone holding the generators). In order:
  1. If the `vld8` CLI is on PATH (`which vld8`), use it — it embeds everything.
  2. Else look for a local clone of the vld8 repo; if you cannot find one, ask the user for its path.
- Confirm target and toolkit paths with the user before writing anything outside the target's
  `.claude/commands/`.

### 2. Produce the service map (the agentic part)

Unless `--no-servicemap` was passed:

- If `servicemap.json` already exists at the target root and the user did not pass `--force`, reuse it.
- Otherwise **perform the service-map crawl yourself**, following the full process in the
  `vld8-map` skill (`.claude/commands/vld8-map.md` once installed, or
  `generate-servicemap/SKILL.md` in a clone): the four-phase deep crawl
  (discovery → deep dive → trace connections → assemble) writing `servicemap.json` to the target root.
- Validate it: `vld8 map validate servicemap.json` (from a clone without the CLI:
  `python <toolkit>/generate-servicemap/validate_servicemap.py servicemap.json`).

Do not shell out to `claude -p` for this — you are already Claude. Run the crawl inline.

### 3. Run the shared installer for the deterministic steps

Hand your freshly crawled map to the installer, which copies the static skills and runs the two
generators. Use whichever entry point is available:

```bash
# Preferred — installed CLI:
vld8 install <target> --service-map servicemap.json --force

# From a clone, no install needed:
python -m vld8 install <target> --service-map servicemap.json --force
```

If `--no-servicemap` was requested, omit `--service-map` and the installer runs the generators with
`--no-service-map`. The installer is idempotent; pass `--force` to overwrite. Pass each
`--preview <milestone>` the user gave on to the installer unchanged. Without one, the review skills are
regenerated with the default output, which also undoes an earlier preview.

### 4. Report

Summarize what landed in `<target>/.claude/commands/`:

- `/vld8-map`, `/vld8-mcp`, `/vld8-setup` (copied)
- `/vld8-review`, `/vld8-security` (generated; note whether they are map-aware)
- Any preview line the installer printed, word for word: preview applied, preview NOT applied, or
  skills that held an earlier preview and are now back to the default.

Then tell the user they can run `/vld8-review` and `/vld8-security` for reviews, and
`/vld8-mcp <server>` to audit an MCP server.

## Notes

- This skill and the `vld8 install` CLI share one core (`vld8.installer`). The only difference is
  who produces the service map: this skill crawls inline; the CLI reuses an existing map, runs `claude -p`
  with `--crawl`, or skips it.
- `/vld8-mcp` is standalone — it audits *external* MCP servers, not this repo, and needs no service map.
