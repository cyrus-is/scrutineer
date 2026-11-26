# vld8

[![Release](https://img.shields.io/github/v/release/cyrus-is/vld8?label=release)](https://github.com/cyrus-is/vld8/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/vld8?label=pypi)](https://pypi.org/project/vld8/)

Dev tooling for [Claude Code](https://claude.ai/code): Cyrus's toolbox. vld8 installs three tools into your repo as Claude Code commands:

- **Map** (`/vld8-map`) crawls your repo into `servicemap.json`, a topology of its services, datastores and connections. The reviews use it as context.
- **Review** is two commands generated for the platforms your repo actually uses: a principal-engineer code review (`/vld8-review`) and a security review (`/vld8-security`).
- **MCP review** (`/vld8-mcp`) audits an MCP server before you trust it with tools, data and credentials.

```bash
pip install vld8
vld8 install .    # adds /vld8-map, /vld8-review, /vld8-security, /vld8-mcp and /vld8-setup to .claude/commands/
```

> **Upgrading from Scrutineer?** vld8 is the same toolkit under a new name, and the `scrutineer` package is no longer maintained.
>
> 1. Install vld8 the way you installed scrutineer: `pip install vld8`, `pipx install vld8` or `uv tool install vld8`.
> 2. Run `vld8 install` in each repo. It replaces the `/scrutineer-*` commands with `/vld8-*` ones and moves the old files to `.claude/scrutineer-backup/`. It only moves files scrutineer wrote, so your edits aren't lost. It also renames `.claude/scrutineer-mcp-suppressions.json` to `.claude/vld8-mcp-suppressions.json`.
> 3. On the command line, `scrutineer servicemap …` is now `vld8 map …`.
>
> Until you switch, `pip install -U scrutineer` gets a final release that installs vld8 and forwards the old `scrutineer` command to it.

## The tools

### Map: `/vld8-map`

An agentic crawl of your repository that writes `servicemap.json`. The file is a machine-readable topology of the repo's services, apps, libraries, datastores and infrastructure, and how they connect.

The crawl has four phases:
1. **Discovery:** find every component (services, apps, libraries, infrastructure, datastores).
2. **Deep dive:** each component's endpoints, auth, config and dependencies.
3. **Trace connections:** how the components talk to each other (HTTP, gRPC, queues, databases, plus `process`, `ipc`, and `file` boundaries, CLI-mediated `http` calls with `via`, and container `mounts`), with `evidence[]` line hashes.
4. **Assemble:** validate and write `servicemap.json` (schema 1.2.0), with a confidence score on each entry. Findings and security observations are reported separately and never written into the map.

Re-running it updates the map in place. Fields marked `"manual_override": true` are kept, and connections that belong to other repos are preserved. The schema is in [`references/schema.md`](references/schema.md), and `vld8 map validate servicemap.json` checks a map against it (`--check-evidence [--repo PATH] [--strict]` recomputes `evidence[]` SHA-256 line hashes offline to detect moved or drifted citations).

The map is useful on its own as architecture documentation, and it feeds the reviews:
- the code review uses its components to scope component reviews and to split large diffs;
- the security review lists the map's intentionally unauthenticated endpoints and shared datastores, and uses its components to scope component reviews.

### Review: `/vld8-review` and `/vld8-security`

`vld8 install` generates both commands from your repo. Detection decides which platform guidance each command carries, and it looks only at files git would commit, so build output and gitignored files don't count. After your stack changes, or once you have a service map, regenerate with `vld8 install --force`.

Both commands take the same four modes:

```
/vld8-review                     # the current branch's diff against main
/vld8-review 123                 # pull request #123
/vld8-review <component-name>    # a whole service or app (from the service map, or a directory you name)
/vld8-review --deep              # repo-wide, tracing flows across services
```

`/vld8-security` takes the same arguments.

**Code review** (`/vld8-review`) reviews like a principal engineer, across 8 lenses:

| Lens | What it asks |
|------|---------------|
| Production Reliability | Will this survive real traffic, failures and edge cases? |
| Correctness | Does the logic do what it claims? |
| Data Integrity | Can data be lost, corrupted or desynchronized? |
| Error Handling | Are errors caught, surfaced and recoverable? |
| Architecture | Does this fit the system's patterns and boundaries? |
| Operability | Can you debug, monitor and deploy this safely? |
| Performance | Will this scale? Any hidden N+1s, unbounded queries or hot paths? |
| Maintainability | Will someone understand this in 6 months? |

- **Verify before judging.** It starts by finding your repo's own gate. That can be a gate script (`run-gate.sh`, `scripts/gate.sh`, `scripts/ci.sh` or `bin/ci`), a Makefile `check` or `ci` target, a justfile `check` recipe, or the CI workflow that gates merge. It runs that gate and stops if the build is red. On a green build, it doesn't report anything the toolchain already proved. Platform-specific cheap checks exist so far for Swift and Python.
- **Size the diff first.** Past about 150 files or 20 commits, it splits the review into parts, along the service map when there is one, and it checks that the base branch isn't stale.
- **Platform guidance** for each detected platform: pre-flight checks, focus areas and change-type signals.
- **It reports on itself.** Every finding names the check behind it. A closing Check Performance section lists:
  - checks that fired wrongly;
  - checks that had nothing to match;
  - findings no check covered.
- **In PR mode** it posts its findings as a single PR comment with `gh pr comment`. The other modes print to the terminal.

**Security review** (`/vld8-security`) hunts for exploitable vulnerabilities, in four stages:
1. **Threat model:** attack surface, trust boundaries, blast radius and the auth model.
2. **Universal checklist:** 9 areas, including auth, injection, secrets, crypto, rate limiting and dependencies.
3. **Platform checklists:** each item comes with a secure alternative and an OWASP reference. Mobile items use the Mobile Top 10 (2024) and MASVS.
4. **Agentic analysis:** tracing input from entry to storage, auditing auth boundaries, and reasoning about attack chains.

Findings are rated CRITICAL, HIGH, MEDIUM or LOW. Security findings always stay in your terminal, PR mode included, because they may be sensitive.

**Platform coverage.** The two reviews share most of their platform guidance. The security review carries more blocks.

| Area | Code review | Security review |
|---|---|---|
| Backend | Go, Python, Java, Node.js / JavaScript / TypeScript, Rust, C# / .NET, Ruby, PHP | same |
| Web | React / Next.js, Vue.js | adds Angular |
| Mobile | Android (Kotlin/Java) | adds React Native, Flutter (Dart) |
| Apple | Swift (language and concurrency), SwiftUI, Swift Package Manager, Apple app targets, macOS apps, CloudKit sync, Apple on-device AI (Foundation Models), Swift Testing | same, except Swift Testing |
| Infrastructure | Terraform, Docker, GitHub Actions | adds Kubernetes, GitLab CI |
| API | OpenAPI / REST, GraphQL | adds gRPC / Protocol Buffers |
| Database | SQL | adds MongoDB |
| Auth | — | JWT, OAuth 2.0 |
| **Blocks** | **25** | **33** |

When a review meets code that no checklist covers, it flags the gap and drafts candidate checks in its output. See [Customizing](#customizing) to keep them.

### MCP review: `/vld8-mcp`

A standalone auditor for MCP servers, the `npm audit` equivalent for the [Model Context Protocol](https://modelcontextprotocol.io). Installing an MCP server grants it tool access, data access, and usually a live credential. `/vld8-mcp` lets you inspect that trust decision **before** the server runs. It reviews an *external* server, not your repo, so it needs no generate step and no service map. The evidence comes from a Python analyzer (`vld8 mcp analyze`), and the judgment comes from the skill.

It reports **two independent ratings**, because a server can be perfectly secure and still want to read every message you've ever sent:

- **Security verdict:** `SAFE / CAUTION / BLOCK`.
- **Data-sensitivity rating:** `MINIMAL / LIMITED / SENSITIVE / HIGHLY_SENSITIVE`, or `UNKNOWN` when no tool surface was captured. A server whose tools couldn't be enumerated therefore never reads as low-risk by default.

**Static passes.** These never start the server, call a tool or fetch a URL:
1. **Config review:** install, transport, secret and scope problems, including a credential or cleartext URL hidden in a command argument (for example `mcp-remote http://…`). It also covers *provenance* (can the reviewed code be tied to what actually runs?) and *containment*.
2. **Tool-surface review:**
   - each tool is classified allow, ask or deny, and each hit carries the matched *evidence* and a *confidence*;
   - it records the data categories each tool touches;
   - schema-intent signals expose a tool with a benign name but a powerful schema;
   - a **tool-poisoning scan** looks for hidden instructions in tool descriptions.
3. **Source review:** handler injection, secret handling, exfiltration paths and obfuscation. Source is fetched safely by `vld8 mcp fetch`: it resolves through registry APIs, verifies integrity and extracts with sanitized paths. It never runs a package manager or executes fetched code.
4. **Finding self-review:** an optional false-positive sweep (`vld8 mcp validate`) re-examines each candidate against its own evidence. It can only suppress, and every suppression records its reason.

**Behavioral pass.** This one is opt-in, and it *does* run the server:

5. **Behavioral capture** (`vld8 mcp capture`, gated behind `--run`) answers *what does it actually do?* rather than *what does it claim?*
   - It compares the `tools/list` the server really serves with the one you reviewed, and reports any difference as `manifest_drift`.
   - It scans tool return values for prompt injection.
   - With `--probe`, it gives every credential-shaped environment variable a unique canary value, and gives the server a throwaway `HOME` full of decoy credential files. It then calls each tool, with network traffic routed to a sink that records it and never forwards it.
   - A canary that turns up in a tool result shows secrets access the tools never declared. A canary in an outbound request is `secret_in_egress`, which proves exfiltration.
   - The server never inherits your environment or receives a real credential. Every record states its own coverage, so finding nothing is never reported as clean.

On top of these passes:
- **Toxic combinations:** capabilities that are tolerable alone but together form an attack, such as secrets access plus network egress. They're gated on severity and confidence, so one weak signal can't produce a false HIGH.
- **Approval drift:** what your client already auto-approves compared with what the review recommends.
- **Suppressions that expire:** findings bind to a SHA-256 digest, so a false-positive suppression in `.claude/vld8-mcp-suppressions.json` expires as soon as the server's config or tool surface changes.

See [`mcp-review/README.md`](mcp-review/README.md) for the full design.

## How the tools fit together

```
/vld8-map ──→ servicemap.json ──┬──→ /vld8-review     (generated by vld8 install)
                                └──→ /vld8-security   (generated by vld8 install)

/vld8-mcp    standalone: audits an external MCP server; no map, no generate step
/vld8-setup  crawls the map, then runs the installer from inside Claude Code
```

The service map is optional. Without it, both reviews still work, but they can't do component reviews or trace flows across services.

## Install

### From the shell

```bash
pip install vld8                                     # or pipx install vld8 / uv tool install vld8
vld8 install /path/to/your-repo                      # without a service map (fast)
vld8 install /path/to/your-repo --crawl              # also crawl a service map with a headless `claude -p`
vld8 install /path/to/your-repo --service-map m.json # use an existing map
vld8 install /path/to/your-repo --force              # overwrite existing commands (e.g. to regenerate)
```

`vld8 install` uses `servicemap.json` at the repo root if there is one.

### Preview output

A change to what the reviews look for, how they rate it, or how they report it ships behind a preview flag until it has been measured (see the [roadmap](docs/ROADMAP.md)). To try a milestone's changes early:

```bash
vld8 install /path/to/your-repo --force --preview 2.1
```

The regenerated commands end with a comment that names the preview, and the installer says whether it took effect. To go back to the default, reinstall with `--force` and without `--preview`. `vld8 install --help` lists the milestones that have a preview. 2.1's changes land behind its flag one at a time, so until the first one ships, the flag only adds that comment.

### From Claude Code

`/vld8-setup`, which `vld8 install` also installs, does the same job from inside Claude Code: Claude crawls the service map itself, then runs the installer, so the review commands come out map-aware. Re-run it whenever you want a fresh map and regenerated reviews. It takes `--preview MILESTONE` too.

### Commands the skills use

The installed skills reach vld8's bundled scripts through the CLI, so they work in any repo:

```bash
vld8 mcp analyze|fetch|validate|capture [args]             # the MCP review scripts
vld8 map validate servicemap.json [--check-evidence]       # check a map (and optional evidence hashes)
vld8 map schema                                            # print the schema's path
vld8 checks (--changed PATH... | --diff RANGE) [--lens code|security|both] [--repo PATH]  # select guidance checks
vld8 review prepare (--diff RANGE | --pr NUMBER | --component NAME | --deep) [--lens code|security] [--tier fast|deep] [--base-ref REF] [--config FILE] [--service-map FILE] [--spec FILE] [--evidence FILE]... [--fetch-issues] [--budget CHARS] [--untrusted] [--state-dir DIR] [--run-id ID] [--repo PATH]  # write prepare.json and prompt.md
vld8 review size (--diff RANGE | --pr NUMBER) [--repo PATH] [--service-map PATH]          # size a diff or PR
vld8 review report --findings m.json [--prepare p.json] [--prior old.json] [--repo PATH] [--format md|json|sarif] [--out FILE]  # verify, merge, and render findings
```

`vld8 review prepare` writes `prepare.json`, and `prompt.md` for `--tier deep`, to a new directory under `<git-common-dir>/vld8/runs/<tree-id>/<run-id>/` (or under `--state-dir`). It refuses a `--run-id` that already exists.

- **What's reviewed:** `prepare.json` lists the files in scope, grouped by partition, and `prompt.md` gives the `git diff` command for the change. The tree ID names the reviewed tree. For `--diff REF` with a single ref, that is the index plus uncommitted changes to tracked files, because that's what `git diff REF` compares.
- **Where rules and config come from:** rules files and `.vld8.toml` are read from a base ref, never from a PR's tree. That's `--base-ref` when given; otherwise the PR's base branch for `--pr`, the left side of the range for `--diff`, and `HEAD` of your own checkout for `--component` and `--deep`. `--base-ref` doesn't change what's diffed. `--config` reads a `.vld8.toml` outside the repository instead, and `--service-map` reads a map from a path you name.
- **PRs:** `--pr` fetches the PR head and its base branch from the PR's remote and reads both as git objects, so the diff doesn't depend on a stale local `origin/<base>` and nothing from the PR is checked out. If either can't be fetched, it exits `2` rather than guess from local refs.
- **Untrusted trees:** on a fork's or a bot's PR, or with `--untrusted`, nothing from the PR's tree is run or read as config, and `--spec` and `--service-map` must be outside the repository. With `--untrusted`, `--component` and `--deep` read no rules or config unless you give `--base-ref`.
- **Evidence:** each `--evidence` file is accepted only when it names the reviewed tree ID.
- **Linked issues:** `--fetch-issues` (or `[prepare].fetch_linked_issues`) applies to `--pr` only, and `--tier fast` never fetches them.
- **Checking findings:** `vld8 review report` checks citations against the files under `--repo`, so point it at a checkout of the reviewed tree. `prompt.md` gives the commands for each mode.
- **Exit codes:** `0` prepared; `1` blocking code findings (`--tier fast` only, which writes `prepare.json` alone); `2` preparation failed.

### From a clone

```bash
git clone https://github.com/cyrus-is/vld8 && cd vld8
pip install -e .            # the vld8 CLI, running from this checkout
```

Each tool also runs on its own from the clone:

```bash
python generate-peer-review/generate.py /path/to/your-repo --output .claude/commands/vld8-review.md
python generate-security-review/generate.py /path/to/your-repo --output .claude/commands/vld8-security.md
cp generate-servicemap/SKILL.md /path/to/your-repo/.claude/commands/vld8-map.md
cp mcp-review/SKILL.md /path/to/your-repo/.claude/commands/vld8-mcp.md
```

Both generators use `servicemap.json` at the repo root when it's present. Pass `--service-map PATH` for a map stored somewhere else, or `--no-service-map` to skip it. Both also take `--preview MILESTONE`.

## Requirements

- Python 3.14+ and `pyyaml>=6.0`, which pip installs for you.
- [Claude Code](https://claude.ai/code) to run the commands.
- `git`. Detection reads git's file list, and falls back to walking the directory outside a git repo.
- [`gh`](https://cli.github.com) for PR mode in both reviews.
- The `claude` CLI for `vld8 install --crawl`.

## Customizing

Three YAML files drive the tools:

- **`generate-peer-review/peer_review_guidance.yaml`:** for the code review, the platform detection rules, pre-flight checks, focus areas, change-type signals and verification ladders.
- **`generate-security-review/security_guidance.yaml`:** for the security review, the platform detection rules and the vulnerability checklists, with OWASP references and secure alternatives.
- **`mcp-review/mcp_risk_guidance.yaml`:** for the MCP analyzer, the config problems, sensitive environment-variable patterns, capability and data-sensitivity taxonomies, and tool-poisoning patterns.

Edit them in a clone installed with `pip install -e .`, then run `vld8 install --force` to regenerate the review commands. The generators only detect platforms these files describe. Drafts from a review's coverage gaps aren't written back automatically, so add the ones worth keeping here. If a change would help everyone, open a PR.

To check generated skills against the checked-in golden snapshots (or intentionally regenerate them after output changes):

```bash
python tests/test_snapshots.py           # verify generated skills match tests/snapshots/golden/
python tests/test_snapshots.py --update  # regenerate checked-in golden files
```

## Agent support

vld8 supports **Claude Code** only. Support for Cursor, Gemini CLI and OpenAI Codex CLI is planned but not started; it's tracked in the [Multi-tool support milestone](https://github.com/cyrus-is/vld8/milestone/1).

## License

MIT
