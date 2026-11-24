# vld8 roadmap: from 2.0 to the original pipeline

**Status:** draft for Cyrus (2026-11-23). Approving it counts as the design review, per `ENGINEERING.md`.

**Design:** the restructure plan, `docs/plans/2026-11-23-restructure.md` (landed in PR #45), holds the reasoning, the alternatives and the risks. This roadmap puts that plan's work in order and says what each release has to prove.

**Where we are:** vld8 2.0.0 shipped the rename, the generator fixes and the install fixes.

**The goal is the pipeline Scrutineer was meant to be:**

> scan → triage and validation → a rated finding with lines and context → suggested fix

Only the first stage was ever built. This roadmap builds the others, in order, and checks each against measurements before anything new is added on top.

## Sources

Every item below traces to one of these:

| Tag | Source |
|---|---|
| **HQ-n** | Change *n* in the HQ proposal (`hq/projects/scrutineer/review-skill-improvements-2026-11-23.md` §1), from the qwen-review-recall study. Recall was 20–23 of 26 seeded defects; precision was 37–41%. |
| **CR-n** | Item *n* in §5 of the unled whole-project design review. Its verdict: two products sharing a name, prose-only output, and validation that grades its own work. |
| **CTX** | The context audit. The original reviews worked because they had the repo's rules, its gate inventory, a "read the callers" step, and a sub-agent that validated findings. |
| **COV** | The portfolio coverage audit, plus the research desk's ~90% language set. |
| **STD** | Gaps against `ENGINEERING.md`, listed in the design review. |

## Releases at a glance

| Release | Theme | Pipeline stage | Ships when |
|---|---|---|---|
| **2.0.x** | Finish the rename; repo hygiene | — | Repo changes only; no release needed |
| **2.1** | Precision without a spec | Scan: rated findings | The held-out test passes its pre-registered rule |
| **2.2** | Foundations: findings contract, one engine | Scan: structured findings | CI, snapshot tests, and no regression on the 2.1 eval |
| **2.3** | Validation stage | Triage and validation | The held-out test shows precision holds or rises with no recall loss |
| **2.4** | Terrain: service map v2, business rules as implemented, the context packet | Scan: system context | Rule-change and cross-module seeds are caught; no regression elsewhere |
| **2.5–2.7** | Coverage for the 90% set | Scan: breadth | Detection snapshots, plus one live review per new block |
| **2.8+** | MCP as its own tool; measure and prune | All | Per item |
| **Later** | Suggested fixes; onfire; the improvement pipeline; other agents; vld8.ai | Suggested fix, and more | After 2.3's validation is measured |

The order: precision first, because it's the measured problem and its fix is cheap. Then the contract, because it unblocks validation and measurement. Then validation, because it's the stage that was never built. Then terrain, because it's where intent comes from: the system's own rules, not a spec per change. Breadth comes last, so new checks land on an engine whose output can be measured, with terrain they can cite as evidence.

## 2.0.x: finish the rename, repo hygiene

**Done (2026-11-23):**
- `staging` is the default branch, with force-pushes and deletion blocked and linear history required. The rules apply to admins too.
- Publishing only from `main`: `publish.yml` refuses a release tag whose commit isn't on `main` (#43). It reached `main` by a fast-forward promotion (#44), the first under the branch model below.
- The plan landed on `staging` (#45), replacing draft #40. The branches whose history carried private project names were deleted.
- The announcement post is live at cyrus.is/building/vld8.

**Open:**

| Item | Owner | Source |
|---|---|---|
| **A GitHub account for the agents:** a machine user with write access and its own token in `~/.claude/pats/`. Today every agent PR is authored by `cyrus-is`, and GitHub won't let Cyrus approve his own PRs. Once it exists, `staging` requires a PR, one code-owner approval (Cyrus can bypass the review rule for PRs he writes himself), and the `test (3.10)` and `test (3.13)` checks | Cyrus | Cyrus, 2026-11-23 |
| **Branch model (in use since #44):** feature PRs squash into `staging`. `main` receives only releases: a "Release X.Y" PR from `staging` for review and CI, then a fast-forward push of `main` to `staging`, which GitHub records as merging the PR. A squash or rebase promotion would put commits on `main` that `staging` doesn't have, and the two would drift | Cyrus | Cyrus, 2026-11-23 |
| Optional hardening of publishing: a `pypi` environment with Cyrus as required reviewer, and a tag ruleset so only Cyrus can create `v*` and `scrutineer-v*` tags | Cyrus | Supply chain |
| Archive `scrutineer` on PyPI | Cyrus | Rename |
| Update the GitHub repo description, which still describes Scrutineer | Cyrus | Rename |
| Point vld8.ai at cyrus.is/building/vld8; Cloudflare has the nameservers but no A record | Cyrus | Plan D8 |
| Rename "Scrutineer security audit" in the HQ engineering standard (canonical copy), then re-render `ENGINEERING.md` | HQ | Rename |
| Record vld8 in HQ's `CLAUDE.md` as a repo with a `staging` branch, and as the exception to "the default branch stays `main`" | HQ, once Cyrus confirms | Branch model |
| Ask GitHub Support to purge the commits that carried private names from PRs #39–#41 (the request is drafted) | Cyrus | Opsec |
| Add a ruff config and a lint step to CI | vld8 | STD |
| Add a diff-coverage gate at 80% to CI | vld8 | STD |
| Pin CI dependencies with a constraints file. There's no lockfile today | vld8 | STD |
| Write `decisions/` records for: the MCP auditor built instead of the triage layer (April, written up after the fact); the rename (D7); dev-tooling positioning (D3) | vld8 | STD, CR-8 |

## 2.1: precision without a spec

**Why:** in the qwen-review-recall study the review found most seeded defects, but about 60% of what it flagged wasn't real.

**TypeScript wasn't the cause.** The missed TypeScript detection was a coverage hole. One seeded defect traces to it, and it's fixed in 2.0.0. It doesn't explain the noise.

**The noise came from asserting need without evidence:** "might want a timeout", "could use an audit trail", on code where nothing required one.

**The fix doesn't need a spec.** The question is whether something *needed* to be there, not what the author intended, and need has to be shown (Cyrus, 2026-11-23). These are prompt and generator changes to the current skill, so they don't wait for the engine work.

| Item | Source |
|---|---|
| **Evidence rule:** ISSUE only with evidence of need: it breaks a written rule, a confirmed map rule or a stated requirement; departs from a contract two named sites follow; has a traced, reachable trigger; or breaks a security invariant. Otherwise it isn't a gap. At most it's a CONCERN, which must name a concrete scenario. One vocabulary throughout; Phase 1's CRITICAL/INFO/P0/P3 terms are retired | HQ-2, Cyrus |
| **Verdict rule:** REQUEST CHANGES if and only if there's an ISSUE. This also fixes the clean-review contract | HQ-2, HQ-7 |
| **Read the repo's rules files** (CLAUDE.md, AGENTS.md, ENGINEERING.md, CONTRIBUTING.md, and nested ones on the changed paths). A broken written rule is an ISSUE, and the rule is quoted | HQ-4, CTX |
| **Callers check,** moved up from 2.4: list the callers of each changed export, and check each caller's assumptions. The cross-module seeds scored 0 of 2 | HQ-9, CTX |
| **Ambient-nondeterminism check:** flag `Date.now`, `new Date()`, `Math.random` or `crypto.randomUUID` used where an injected clock or ID source exists | HQ-5 |
| **The lens table only cites findings.** It can't introduce new claims | HQ-6 |
| **Optional intent sources:** `--spec <file>`, the PR body and linked issue, a design doc the diff adds. The review states which one it used and works without any. A spec counts as one more source of stated requirements; objections to it still need evidence of need | HQ-3, Cyrus |

**Gate:** the held-out test, pre-registered before any run.
- **The primary set is real PRs with no spec:** about 10 PRs with fresh seeds and 2 clean ones. Spec-driven change sets are secondary.
- **The baseline is 2.0.0,** so the TypeScript fix that already shipped isn't counted as part of 2.1's gain.
- **Score on evidence of need:** a finding is real if it shows a broken rule, a broken contract or a triggerable failure, even when it contradicts a spec.
- **Ship if:** Finding precision is at least the baseline + 20 points, and recall is at least the baseline − 2.
- **If it fails:** the work stays off `staging` (see *Release train*), and its measurements go back into the design.

**Needs:**
- decision **D4**: test before shipping. Assumed yes.
- someone to build and run the held-out set, under the new scoring rule.

## 2.2: foundations

| Item | Source |
|---|---|
| **Findings contract v1:** every lens writes JSON with `file`, lines, `lens`, `checkId`, `category`, `claim`, `evidence`, `severity`, `basis`, `suppressed`/`reason` and `fingerprint`. The Markdown report is rendered from it | CR-1 |
| **Choose JSON key casing on purpose.** `ENGINEERING.md` says camelCase, but the MCP output and the service map use snake_case. Convert, or record the deviation | CR-1 |
| **Storage:** `.vld8/findings.json` is local and gitignored; `.vld8/triage.json` is checked in and holds fingerprints and decisions only (plan §4) | Cyrus, 2026-11-23 |
| **One shared analyzer module** instead of two copies, and one detection spec for both lenses | CR-5, COV |
| **Choose checks at review time:** `vld8 checks --changed <paths>` returns only the guidance blocks that match the diff. The installed YAML is the single source of truth, `pip install -U` upgrades the guidance, and the prompt shrinks to fit the diff | CR-4, HQ-8 |
| **Bring the security lens to parity:** Phase 0, diff sizing and Check Performance, which today exist only in the code review | CR-5 |

**Gate:** CI and snapshot tests, plus the 2.1 eval re-run to show no regression.

**Needs:** decision **D1**, one engine with two lenses (recommended) or one merged review. Decide it before 2.2 starts.

## 2.3: the validation stage

This is the stage that was never built.

| Item | Source |
|---|---|
| **A separate validator over the findings JSON,** modelled on `mcp-review/validate_findings.py`. A fresh context tries to refute each finding: it reads the callers, applies the Phase 0 exclusions deterministically, and reproduces where it can. It may only suppress or downgrade, and it records why | CR-3, CTX |
| **Retire the security skill's pasted-in exclusion list** and its contradictions (rate limits, CVEs, ReDoS) | CR-3 |
| **SARIF export,** opt-in, for GitHub code scanning. Its states map onto still on fire, false positive and ignore | Cyrus, 2026-11-23 |

**Gate:** the held-out test re-run. Precision holds or rises, and recall doesn't fall: the validator must not suppress real seeded defects.

## 2.4: terrain

The service map becomes the system's known terrain, and the reviews read it. Design: plan §4, *Terrain*.

| Item | Source |
|---|---|
| **Business rules as implemented in the map:** authorization (who can do what to which resource), tenancy, trust translation points such as a gateway that turns external JWT into internal tokens, identifier properties such as random IDs with no oracle, data classifications, accepted risks. Each comes with file and line evidence and a confidence | Cyrus, CTX |
| **`vld8 map rules`:** reports the rules as implemented and asks yes / no, bug / not sure for each. Yes is confirmed terrain in the checked-in map. A bug is a finding, stored like findings and never in the map. Not sure stays a hint | Cyrus |
| **Rule-change detection in reviews:** compare the rules as implemented before and after the diff. A change to a confirmed rule is an ISSUE; a change to an unconfirmed rule is a question | Cyrus |
| **`crawled_commit` and drift detection,** plus a CI refresh that opens a PR | CTX |
| **Terrain slice:** Modes 1 and 2 read only the touched components' terrain; Modes 3 and 4 keep the full map | HQ-10 |
| **`vld8 context`:** the context packet, with rules files, intent, terrain slice and callers, under a size budget so it doesn't crowd out the lens prompt | CTX, plan §11 |
| **Intent capture,** opt-in: a Claude Code hook that writes the approved plan into the PR description; an experimental reader for local session prompts | Cyrus |
| **Map issues** from the old backlog: background and hosted services and job schedulers (#4), transactional outbox and messaging (#5), shared source includes (#6), a documentation / schema-spec component type (#19), cloud provider coverage (#3) | Backlog |

**Gate:**
- seeded authorization changes are caught as rule changes;
- the cross-module seeds improve on 2.1;
- no regression elsewhere.

## 2.5–2.7: coverage for the 90% set

Coverage means four things, not a generic checklist per language:
- detection that never silently misses a file;
- a verification ladder per platform;
- a few deep, measured checks;
- a loud fallback for anything uncovered.

| Release | Items | Source |
|---|---|---|
| 2.5 | Two-layer detection, package roots, roles, and an **uncovered-files report**, so nothing is silently skipped. The Kotlin JVM block is split from Android | COV |
| 2.6 | **Verification ladders for Tier 1:** TypeScript/JS, Go, Rust, C#, Java, PHP, Kotlin, Shell, C++. Only Swift and Python have ladders today | COV (research) |
| 2.7 | **New blocks:** Cloudflare Workers, Shell, AWS serverless, Next.js server code, LLM/MCP apps, Unity, HTML templates. Then Tier 2 (C, Dart) | COV |

**Gate, for each new block:** detection snapshot tests, plus one live review on a real repo, recorded in Check Performance.

## 2.8 and on

| Item | Source |
|---|---|
| **MCP review as its own tool:** a user-scoped install, `vld8 mcp` as the front door, and the shared findings contract (decision **D5**). Its backlog: a sandboxed side-effect tracer for behavioral capture (#38), and an OSV lookup for known-vulnerable MCP packages (#35, shared with `onfire`) | CR-7, Backlog |
| **Measure and prune,** ongoing from 2.3: aggregate Check Performance across runs; prune checks that never yield, starting with the March-era generic blocks; promote "Unnamed" findings to checks | CR-6 |

## Later

These are in the plan's future-features list. They wait until validation (2.3) is measured, because each one builds on findings someone can trust.

- **Suggested fixes:** the original pipeline's last stage. A patch per validated finding, verified by re-running the lens. It comes last on purpose: a fix generator on top of unvalidated findings multiplies the noise.
- **`vld8 onfire day|week`:** checks new CISA KEV entries (48-hour and 8-day windows) for exposure. It has triage states, and false-positive submissions are encrypted.
- **Automated improvement pipeline:** replay GitHub advisories against the code from before each fix, with a held-out set by date. A miss becomes a draft PR plus an eval case.
- **Threat model generator (#1):** largely absorbed by terrain (2.4), whose trust translation points, authorization rules and data classifications are a threat model's inputs. Whatever's left is reassessed after 2.4.
- **Other agents:** Cursor, Gemini CLI and Codex CLI (#31–#34). The design review's advice holds: no more breadth until the pipeline above lands.
- **vld8.ai docs site:** a static site built from the READMEs (plan D8).

## Release train

Weekly, until the issue backlog is empty (Cyrus, 2026-11-23). The backlog is every roadmap item as an issue under its release milestone, plus the 12 issues that were open before the roadmap, each now mapped to a release.

- **Every Monday:** if `staging` has changed since the last release and CI is green, cut a release:
  1. open a "Release X.Y.Z" PR from `staging` to `main`, with notes drafted from the merged PRs;
  2. Cyrus approves it;
  3. fast-forward `main` to `staging`;
  4. `gh release create vX.Y.Z --target main`, which publishes to PyPI.
- **`staging` is always releasable.** Work that changes what reaches the reader, meaning the 2.1 bundle and the 2.3 validator, stays on its feature branch, or behind an opt-in flag, until its held-out gate passes. Only then does it merge. Everything else (fixes, hygiene, coverage behind its own gates) merges when it's ready and rides the next train.
- **Version numbers follow what shipped,** not the calendar. A week with only fixes is a patch (2.0.1). The week a theme lands, the minor version goes up (2.1.0).
- **A quiet week ships nothing.** No empty releases.
- **The train stops** when the backlog's milestones are closed. Cadence is then revisited.

## Decisions this roadmap waits on

| # | Decision | Needed before |
|---|---|---|
| D1 | One engine with two lenses, or one merged review | 2.2 |
| D2 | Positioning: our own engine, or an expertise pack for other engines | 2.8 (MCP split), and before publishing the contract |
| D4 | Held-out study before shipping 2.1 and 2.3 | 2.1 |
| D5 | MCP review stays in the package until it becomes its own tool | 2.8 |
| D6 | File the 90% research note in HQ | 2.6 (it sets the Tier 1 list) |
| D8 | Where the vld8.ai site lives | Later; the redirect is a 2.0.x item |
