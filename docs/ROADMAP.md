# vld8 roadmap: from 2.0 to the original pipeline

**Status:** draft for Cyrus (2026-11-23). Approving it counts as the design review, per `ENGINEERING.md`.

**Design:** the restructure plan, `docs/plans/2026-11-23-restructure.md` (landed in PR #45), holds the reasoning, the alternatives and the risks. This roadmap puts that plan's work in order and says what each release has to prove.

**Where we are:** vld8 2.0.0 shipped the rename, the generator fixes and the install fixes.

**The goal is the pipeline Scrutineer was meant to be:**

> scan → triage and validation → a rated finding with lines and context → suggested fix

Only the first stage was ever built. This roadmap builds triage and validation, in order, and checks each against measurements before anything new goes on top. Suggested fixes stay a `recommendation` field. First-party tools already apply fixes, so a fix stage comes last, if at all (plan §3).

## Sources

Every item below traces to one of these:

| Tag | Source |
|---|---|
| **SP-n** | Change *n* in the proposal from a private review-recall study (Qwen 27B and Opus as reviewers). Recall was 20–23 of 26 seeded defects; precision was 37–41%. |
| **CR-n** | Item *n* in §5 of the unled whole-project design review. Its verdict: two products sharing a name, prose-only output, and validation that grades its own work. |
| **CTX** | The context audit. The original reviews worked because they had the repo's rules, its gate inventory, a "read the callers" step, and a sub-agent that validated findings. |
| **COV** | A coverage audit across the maintainer's repos, plus a survey of language share in agent-written PRs (the ~90% set). |
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
- The plan landed on `staging` (#45), replacing draft #40.
- The announcement post is live at cyrus.is/building/vld8.

**Open:**

| Item | Owner | Source |
|---|---|---|
| **A GitHub account for the agents:** a machine user with write access and its own token. Today every agent PR is authored by `cyrus-is`, and GitHub won't let Cyrus approve his own PRs. Once it exists, `staging` requires a PR, one code-owner approval (Cyrus can bypass the review rule for PRs he writes himself), and the `test (3.10)` and `test (3.13)` checks | Cyrus | Cyrus, 2026-11-23 |
| **Branch model (in use since #44):** feature PRs squash into `staging`. `main` receives only releases: a "Release X.Y" PR from `staging` for review and CI, then a fast-forward push of `main` to `staging`, which GitHub records as merging the PR. A squash or rebase promotion would put commits on `main` that `staging` doesn't have, and the two would drift | Cyrus | Cyrus, 2026-11-23 |
| Archive `scrutineer` on PyPI | Cyrus | Rename |
| Update the GitHub repo description, which still describes Scrutineer | Cyrus | Rename |
| Point vld8.ai at cyrus.is/building/vld8 | Cyrus | Plan D8 |
| Rename "Scrutineer security audit" in the canonical copy of the shared engineering standard, then re-render `ENGINEERING.md` | Cyrus | Rename |
| Add a ruff config and a lint step to CI | vld8 | STD |
| Add a diff-coverage gate at 80% to CI | vld8 | STD |
| Pin CI dependencies with a constraints file. There's no lockfile today | vld8 | STD |
| Write `decisions/` records for: the MCP auditor built instead of the triage layer (April, written up after the fact); the rename (D7); dev-tooling positioning (D3) | vld8 | STD, CR-8 |

## 2.1: precision without a spec

**Why:** in the review-recall study the review found most seeded defects, but about 60% of what it flagged wasn't real.

**What the study found the noise was:**
- **Objections to behaviour the spec had prescribed:** about half of it for Qwen (20 of 41 non-real findings) and two thirds for Opus (30 of 46).
- **Requests for things nothing required:** far fewer (7 and 6).
- **The study's fix for this was dropped.** It proposed a spec input with a conformance walk and a "Spec questions" section (SP-1, SP-3). 2.1 drops both (Cyrus, 2026-11-23). vld8 judges whether code is secure and correct, not whether it matches a design, and intent will come from the system's terrain (2.4), not from a spec per change.

**What 2.1 tests is a hypothesis, not an established result:** that an evidence-of-need rule cuts most of that noise without a spec.
- **Part of it is a change in scoring.** An objection to a prescribed design that shows a triggerable failure counts as real.
- **The rest is the rule itself.** An objection with no evidence of need is no longer a finding.
- **If the hypothesis fails,** confirmed terrain rules (2.4) are the next lever.

**TypeScript wasn't the cause.** The missed TypeScript detection was a coverage hole, fixed in 2.0.0. The seeded defect it hid, `crypto.randomUUID` used where the codebase injects an ID source, is still missed until the nondeterminism check or the rules-file step lands.

**What ships:** prompt and generator changes to the current skill, behind the 2.1 preview flag (see *Release train*).

| Item | Source |
|---|---|
| **Preview flag:** `vld8 install --preview 2.1`. Skills are generated at install time, so the generators take the flag and emit the new sections only when it's set | Release train |
| **Evidence rule:** ISSUE only with evidence of need: it breaks a written rule, a confirmed map rule or a stated requirement; departs from a contract two named sites follow; has a traced, reachable trigger; or breaks a security invariant. Otherwise it isn't a gap. At most it's a CONCERN, which must name a concrete scenario. The code review gets one vocabulary (ISSUE / CONCERN) and retires Phase 1's CRITICAL/INFO/P0/P3. The security lens keeps its CRITICAL–LOW scale, and the findings contract (2.2) maps both | SP-2, Cyrus |
| **Verdict rule:** REQUEST CHANGES if and only if there's an ISSUE | SP-2 |
| **Read the repo's rules files** (CLAUDE.md, AGENTS.md, ENGINEERING.md, CONTRIBUTING.md, and nested ones on the changed paths). A broken written rule is an ISSUE, and the rule is quoted | SP-4, CTX |
| **Callers check,** moved up from 2.4: list the callers of each changed export, and check each caller's assumptions. The cross-module seeds scored 0 of 2 | SP-9, CTX |
| **Ambient-nondeterminism check:** flag `Date.now`, `new Date()`, `Math.random` or `crypto.randomUUID` used where an injected clock or ID source exists | SP-5 |
| **The lens table only cites findings.** It can't introduce new claims | SP-6 |
| **Optional intent sources:** `--spec <file>`, the PR body and linked issue, a design doc the diff adds. The review states which one it used and works without any. A spec counts as one more source of stated requirements, and objections to it still need evidence of need | SP-3 (input only; the walk is dropped) |

**Gate:** the held-out test, pre-registered before any run.
- **Calibrate first.** Re-score the study's existing findings under the evidence-of-need definition. That sets the expected baseline and the threshold. The old +20-point bar was calibrated on the dropped Spec-questions mechanism and no longer applies.
- **Metric:** precision over all findings (ISSUE and CONCERN), with ISSUE-only reported alongside. Recall is the number of seeded defects found.
- **Sets:**
  - primary: real PRs with no spec, at least 15 fresh seeds across about 10 PRs, plus 2 clean PRs;
  - secondary: spec-driven change sets, used only as a no-regression guard, where precision and recall must not drop below 2.0.0.
- **Runs:**
  - 2.0.0 (with no preview) and the 2.1 preview, on the same sets, under the same scoring, 2 reps each;
  - a result is inconclusive if two reps differ by more than 3 defects.
- **Judging:** the judge checks each finding's evidence against the code, not just whether the finding follows the rubric's form.
- **Where the data lives:** private storage, because real PRs from private repos can't be committed to this public repo.
- **If it fails:** the items stay behind their flag. Any re-test uses fresh seeds, because a set that informed a fix is no longer held out.

**Needs:**
- decision **D4**: test before the default changes;
- someone to build and run the held-out set.

## 2.2: foundations

| Item | Source |
|---|---|
| **Findings contract v1:** every lens writes JSON with `file`, lines, `lens`, `checkId`, `category`, `claim`, `evidence`, `severity`, `basis`, `suppressed`/`reason` and `fingerprint`. The Markdown report is rendered from it | CR-1 |
| **Choose JSON key casing on purpose.** `ENGINEERING.md` says camelCase, but the MCP output and the service map use snake_case. Convert, or record the deviation | CR-1 |
| **Storage:** `.vld8/findings.json` is local and gitignored; `.vld8/triage.json` is checked in and holds fingerprints and decisions only. In public repos, `ignore` decisions and free-text reasons go to the private stores instead (plan §4) | Cyrus, 2026-11-23 |
| **One shared analyzer module** instead of two copies, and one detection spec for both lenses | CR-5, COV |
| **Choose checks at review time:** `vld8 checks --changed <paths>` returns only the guidance blocks that match the diff. The installed YAML is the single source of truth, `pip install -U` upgrades the guidance, and the prompt shrinks to fit the diff | CR-4, SP-8 |
| **Bring the security lens to parity:** the code review's verify-before-judging step (its Phase 0), diff sizing and Check Performance. The security lens already has a different Phase 0, its threat model, which stays | CR-5 |
| **Snapshot harness:** golden-output tests for the generated skills, so a change to review output is visible in review | Gate support |
| **Security eval set:** seeded vulnerabilities with expected findings, so changes to the security lens have a gate. Until it exists, security-lens changes stay flagged | Gate support |

**Gate:**
- CI and the snapshot harness;
- a regression run of the 2.1 eval with the 2.2 preview: precision and recall within 2.1's noise band;
- the security eval, for the security-lens items.

The Markdown report rendered from JSON is an output change, so it ships behind the 2.2 flag.

**Needs:** decision **D1**, one engine with two lenses (recommended) or one merged review. Decide it before 2.2 starts.

## 2.3: the validation stage

This is the stage that was never built.

| Item | Source |
|---|---|
| **A separate validator over the findings JSON.** It takes its contract from `mcp-review/validate_findings.py`: it can only suppress or downgrade, and it records why. The refutation itself is new work: a fresh context reads the callers, checks the verify-before-judging results, and reproduces where it can. So is turning the prose exclusion lists into categories it can apply consistently | CR-3, CTX |
| **Retire the security skill's pasted-in exclusion list** and its contradictions (rate limits, CVEs, ReDoS). This happens only after the validator becomes the default, because removing the list earlier would leave default users with neither | CR-3 |
| **SARIF export,** opt-in, for GitHub code scanning. Its states map onto still on fire, false positive and ignore | Cyrus, 2026-11-23 |

**Gate:** a paired run on fresh seeds. The same saved findings JSON is scored with and without the validator. Precision rises, recall is at least the 2.2 result − 2, and every suppression is listed with its reason.

## 2.4: terrain

The service map becomes the system's known terrain, and the reviews read it. Design: plan §4, *Terrain*.

| Item | Source |
|---|---|
| **Business rules as implemented in the map:** authorization (who can do what to which resource), tenancy, trust translation points such as a gateway that turns external JWT into internal tokens, identifier properties such as random IDs with no oracle, and data classifications. Each comes with file and line evidence and a confidence. Accepted risks are *not* in the map; they're triage decisions (2.2 storage) | Cyrus, CTX |
| **`vld8 map rules`:** reports the rules as implemented and asks yes / no, bug / not sure for each. Yes is confirmed terrain in the checked-in map. A bug is a finding, stored like findings and never in the map. Not sure stays a hint | Cyrus |
| **Rule-change detection in reviews:** compare the rules as implemented before and after the diff. A change to a confirmed rule is an ISSUE; a change to an unconfirmed rule is a question | Cyrus |
| **`crawled_commit` and drift detection,** plus a CI refresh that opens a PR | CTX |
| **Terrain slice:** Modes 1 and 2 read only the touched components' terrain; Modes 3 and 4 keep the full map | SP-10 |
| **`vld8 context`:** the context packet, with rules files, intent, terrain slice and callers, under a size budget so it doesn't crowd out the lens prompt | CTX, plan §11 |
| **Intent capture,** opt-in: a Claude Code hook that writes the approved plan into the PR description; an experimental reader for local session prompts. **Leak risk:** plans and prompts can name private projects, and a PR description is public in a public repo. The hook shows the text before writing, redacts secrets, and is off by default for public repos | Cyrus |
| **Intra-component contracts layer:** the map records contracts between modules inside one deployable, which is where the study's cross-module bugs lived | SP (map granularity) |
| **Terrain eval:** seeded authorization changes and cross-module defects, with expected findings | Gate support |
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
| 2.6 | **Verification ladders for Tier 1:** TypeScript/JS, Go, Rust, C#, Java, Kotlin, Shell. Swift and Python already have them. Then Tier 2 ladders (PHP, C/C++, Ruby, Dart and the rest, plan §5) | COV (research) |
| 2.7 | **New blocks:** Cloudflare Workers, Shell, AWS serverless, Next.js server code, LLM/MCP apps, Unity, HTML templates. Then Tier 2 (C, Dart) | COV |

**Gates:**
- **Each new block:** detection snapshot tests, plus one live review on a real repo, recorded in Check Performance.
- **Each ladder:** a seeded run showing the ladder's exclusions don't suppress real defects. Detection snapshots can't catch that.
- **Flags:** each block or ladder ships behind a flag and becomes the default when its own gate passes.

## 2.8 and on

| Item | Source |
|---|---|
| **MCP review as its own tool:** a user-scoped install, `vld8 mcp` as the front door, and the shared findings contract (decision **D5**). Its backlog: a sandboxed side-effect tracer for behavioral capture (#38), and an OSV lookup for known-vulnerable MCP packages (#35, shared with `onfire`) | CR-7, Backlog |
| **Measure and prune.** Aggregation can start once 2.2's JSON exists; pruning is scheduled here: aggregate Check Performance across runs; prune checks that never yield, starting with the March-era generic blocks; promote "Unnamed" findings to checks | CR-6 |

## Later

These are in the plan's future-features list. They wait until validation (2.3) is measured, because each one builds on findings someone can trust.

- **Suggested fixes,** if at all: the original pipeline's last stage. First-party tools already apply fixes (plan §3). A patch per validated finding, verified by re-running the lens. It comes last on purpose: a fix generator on top of unvalidated findings multiplies the noise.
- **`vld8 onfire day|week`:** checks new CISA KEV entries (48-hour and 8-day windows) for exposure. It has triage states, and false-positive submissions are encrypted.
- **Automated improvement pipeline:** replay GitHub advisories against the code from before each fix, with a held-out set by date. A miss becomes a draft PR plus an eval case.
- **Threat model generator (#1):** largely absorbed by terrain (2.4), whose trust translation points, authorization rules and data classifications are a threat model's inputs. Whatever's left is reassessed after 2.4.
- **Other agents:** Cursor, Gemini CLI and Codex CLI (#31–#34). The design review's advice holds: no more breadth until the pipeline above lands.
- **vld8.ai docs site:** a static site built from the READMEs (plan D8).

## Release train

**One reviewable change a week** (Cyrus, 2026-11-23: "just one thing a week").
- **Grouping:** small items from the same milestone can be grouped into one change when they're reviewed together.
- **Splitting:** large items (the validator, the ladders, new blocks) get split into weekly slices when their turn comes.
- So the 47 backlog items before "Later" set a pace, not a schedule.

**Who runs it:** Cyrus starts each week's change, in an interactive session. No unattended loop runs it (`ENGINEERING.md`: `autonomy: interactive-only`).

**The backlog:** every vld8-owned roadmap item is an issue under its release milestone, along with the eval and gate-support work. The 12 issues that were open before the roadmap are each mapped to a release.

**Flags:**
- **Changes to review output** ship behind their milestone's preview flag (`vld8 install --preview 2.1`) until the milestone's gate passes. Then the flag becomes the default. Review output means what's found, how it's rated, or how it's rendered.
- **Changes that don't alter output** ship as is: CLI helpers, CI, docs, and JSON written alongside unchanged Markdown.
- **A removal waits for its replacement to become the default.** For example, the security exclusion list goes only after the 2.3 validator is the default.

**Release day is Monday,** and only if the package itself changed since the last release. CI-only and docs-only weeks don't release.
1. Commit the version bump on `staging`. `publish.yml` refuses a tag that doesn't match the built version.
2. Open a "Release X.Y.Z" PR from `staging` to `main`, with notes drafted from the merged PRs.
3. Cyrus approves it. Until the agent account exists, PRs are authored as `cyrus-is` and can't be approved in GitHub. Until then, approval is Cyrus's explicit go-ahead, and the next step uses his admin exemption.
4. Fast-forward `main` to the approved commit, `git push origin <approved-sha>:main`, not to whatever `staging` has moved to since.
5. Run `gh release create vX.Y.Z --target main`.

**Version numbers:**
- **Patch:** default output doesn't change (fixes, flagged items, infrastructure).
- **Minor:** a milestone's or block's flag becomes the default (2.1.0, 2.2.0 and so on).

**The train stops** when the milestones before "Later" are closed. The cadence is then revisited.

## Decisions this roadmap waits on

| # | Decision | Needed before |
|---|---|---|
| D1 | One engine with two lenses, or one merged review | 2.2 |
| D2 | Positioning: our own engine, or an expertise pack for other engines | 2.8 (MCP split), and before publishing the contract |
| D4 | Held-out test before a milestone's default changes (items ship earlier behind a flag) | 2.1's default flip |
| D5 | MCP review stays in the package until it becomes its own tool | 2.8 |
| D6 | File the ~90% research note in the private research registry | 2.6 (it sets the Tier 1 list) |
| D8 | Where the vld8.ai site lives | Later; the redirect is a 2.0.x item |
