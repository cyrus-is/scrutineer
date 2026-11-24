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
| **2.1** | Review precision bundle | Scan: rated findings | The held-out test passes its pre-registered rule |
| **2.2** | Foundations: findings contract, one engine | Scan: structured findings | CI, snapshot tests, and no regression on the 2.1 eval |
| **2.3** | Validation stage | Triage and validation | The held-out test shows precision holds or rises with no recall loss |
| **2.4** | Context packet | Scan: system context | Cross-module seeds improve; no regression elsewhere |
| **2.5–2.7** | Coverage for the 90% set | Scan: breadth | Detection snapshots, plus one live review per new block |
| **2.8+** | Service map v2; MCP as its own tool; measure and prune | All | Per item |
| **Later** | Suggested fixes; onfire; the improvement pipeline; other agents; vld8.ai | Suggested fix, and more | After 2.3's validation is measured |

The order: precision first, because it's the measured problem and its fix is cheap. Then the contract, because it unblocks validation and measurement. Then validation, because it's the stage that was never built. Breadth comes last, so new checks land on an engine whose output can be measured.

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

## 2.1: review precision bundle

**Why:** in the qwen-review-recall study the review found most seeded defects, but about 60% of what it flagged wasn't real. Most of that noise came from objecting to designs the spec had already chosen, and from severity labels that were never defined. These are prompt and generator changes to the current generated skill, so they don't wait for the engine work.

| Item | Source |
|---|---|
| A `--spec <file>` input, plus intent from acceptance criteria and a linked issue in the PR | HQ-3, HQ-1 |
| **Spec questions:** objections to prescribed behaviour, and asks the spec doesn't make, are quoted here. They never count as findings and never set the verdict | HQ-1 |
| **Evidence rubric:** ISSUE means the change breaks a stated requirement, a written rule, or an in-repo contract; or it has a traced, reachable trigger; or it breaks a security invariant. A CONCERN names a concrete scenario. One vocabulary throughout; Phase 1's CRITICAL/INFO/P0/P3 terms are retired | HQ-2 |
| **Verdict rule:** REQUEST CHANGES if and only if there is an ISSUE. This also fixes the clean-review contract | HQ-2, HQ-7 |
| **Spec-conformance walk:** each stated behaviour is marked implemented, deviates or can't verify, with file and line | HQ-3 |
| **Read the repo's rules files** (CLAUDE.md, AGENTS.md, ENGINEERING.md, CONTRIBUTING.md, and nested ones on the changed paths). A broken written rule is an ISSUE, and the rule is quoted | HQ-4, CTX |
| **Ambient-nondeterminism check:** flag `Date.now`, `new Date()`, `Math.random` or `crypto.randomUUID` used where an injected clock or ID source exists | HQ-5 |
| **The lens table only cites findings.** It can't introduce new claims | HQ-6 |

**Gate:** HQ's held-out test (§5 of the HQ proposal), pre-registered before any run.
- Fresh change sets with newly planted bugs, never seen while tuning, plus about 10 real PRs to check that home-setting reviews don't get worse.
- Opus first, 2 reps, in a spec setting and a home setting.
- **Ship if:**
  - Finding precision is at least the baseline + 20 points;
  - recall is at least the baseline − 2;
  - no more than 2 seeded defects land in Spec questions.
- **If it fails:** the bundle doesn't ship. Its measurements go back into the design.

**Needs:**
- decision **D4**: study before shipping. The roadmap assumes yes.
- held-out seeds, built by whoever runs the study (HQ's study desk built the last set).

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

## 2.4: the context packet

| Item | Source |
|---|---|
| **`vld8 context`:** rules files, intent sources, and a size budget, so the packet doesn't crowd out the lens prompt | CTX, plan §11 |
| **Map slice:** Modes 1 and 2 read only the touched components' entries; Modes 3 and 4 keep the full map | HQ-10 |
| **Contract fan-out:** list the callers of each changed export, and check each caller's assumptions | HQ-9, CTX |

**Gate:** the cross-module seeds, which scored 0 of 2 in the study, improve, with no regression elsewhere.

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
| **Service map v2:** `crawled_commit` and drift detection; an intra-component contracts layer for single-deployable repos; an invariants file seeded by the crawl and confirmed by a person; a CI refresh that opens a PR | CTX, HQ (map granularity) |
| **MCP review as its own tool:** a user-scoped install, `vld8 mcp` as the front door, and the shared findings contract (decision **D5**) | CR-7 |
| **Measure and prune,** ongoing from 2.3: aggregate Check Performance across runs; prune checks that never yield, starting with the March-era generic blocks; promote "Unnamed" findings to checks | CR-6 |

## Later

These are in the plan's future-features list. They wait until validation (2.3) is measured, because each one builds on findings someone can trust.

- **Suggested fixes:** the original pipeline's last stage. A patch per validated finding, verified by re-running the lens. It comes last on purpose: a fix generator on top of unvalidated findings multiplies the noise.
- **`vld8 onfire day|week`:** checks new CISA KEV entries (48-hour and 8-day windows) for exposure. It has triage states, and false-positive submissions are encrypted.
- **Automated improvement pipeline:** replay GitHub advisories against the code from before each fix, with a held-out set by date. A miss becomes a draft PR plus an eval case.
- **Other agents:** Cursor, Gemini CLI and Codex CLI (#31–#34). The design review's advice holds: no more breadth until the pipeline above lands.
- **vld8.ai docs site:** a static site built from the READMEs (plan D8).

## Decisions this roadmap waits on

| # | Decision | Needed before |
|---|---|---|
| D1 | One engine with two lenses, or one merged review | 2.2 |
| D2 | Positioning: our own engine, or an expertise pack for other engines | 2.8 (MCP split), and before publishing the contract |
| D4 | Held-out study before shipping 2.1 and 2.3 | 2.1 |
| D5 | MCP review stays in the package until it becomes its own tool | 2.8 |
| D6 | File the 90% research note in HQ | 2.6 (it sets the Tier 1 list) |
| D8 | Where the vld8.ai site lives | Later; the redirect is a 2.0.x item |
