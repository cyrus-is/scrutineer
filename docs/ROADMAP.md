# vld8 roadmap: from 2.0 to the original pipeline

**Status:** approved 2026-11-23; revised 2026-11-24 for the code-first conversion (`docs/plans/2026-11-24-code-first-engine.md`). Approving the revision counts as the design review, per `ENGINEERING.md`. Progress updated 2026-11-26.

**Design:**
- The restructure plan, `docs/plans/2026-11-23-restructure.md` (landed in PR #45), holds the reasoning, the alternatives and the risks.
- The code-first engine design, `docs/plans/2026-11-24-code-first-engine.md`, reshapes releases 2.1–2.4.
- This roadmap puts both in order and says what each release has to prove.

**Where we are (2026-11-26):**
- **Released:**
  - vld8 2.0.0 shipped the rename, the generator fixes and the install fixes.
  - 2.0.1 fixed three review-guidance defects found by validation (#92–#94) and added `vld8 install --preview` (#81).
- **Ready to release:** 2.0.2's changes are on `staging`; the version bump comes with the release.
  - map schema 1.2;
  - the Python 3.14 floor;
  - 2.1's CLI helpers (`vld8 checks`, `vld8 review size|prepare|report`), which no skill calls yet.

  It waits on Cyrus's go-ahead, including whether the helpers' open trust and file-safety follow-ups (#161, #164, #167, #172) block it.
- **Built, not yet in use:** 2.1's verbs are on `staging`:
  - the findings contract;
  - `vld8 review prepare` and `vld8 review report`;
  - trust and state;
  - `vld8 checks --changed`.

  No skill calls them yet. Next come the skills switch behind `--preview 2.1` (#129), the remaining precision items, and the gate work (the eval set and held-out test).
- **Not started:** 2.2 and later. 2.2 waits on the replay (#125), which decides how much of its candidate machinery gets built. Two pieces landed early with the verbs:
  - a first `--tier fast` (#166), whose code findings so far come only from `--evidence`;
  - recurrence marking and dispositions in `report --prior` (#152).

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

**Since 2026-11-24, the main line is converting vld8 to a code-first engine** (Cyrus: "most of the effort will be at getting this built, tested, validated, and resilient").
- Design: `docs/plans/2026-11-24-code-first-engine.md`.
- vld8 finds issues with code and a model together. `vld8 review prepare` (code) feeds vld8's lens prompt (any model runs it), and `vld8 review report` (code) checks the result and merges both sets of findings.
- The releases below are reshaped around that. Their gates are unchanged where they already existed.

| Release | Theme | Pipeline stage | Ships when |
|---|---|---|---|
| **2.0.x** | Finish the rename; repo hygiene; map schema 1.2; the Python floor; the replay | — | 2.0.2 ships schema 1.2 and the Python floor |
| **2.1** | The verbs (`prepare`, the lens prompt, `report`) and precision without a spec | Scan: structured, accounted findings | The held-out test passes its pre-registered rule |
| **2.2** | Code analysis and the fast tier: facts, code findings, repo rule packs | Scan: code and model together | No regression on the 2.1 eval; fast-tier precision and wall time |
| **2.3** | Validation and re-review | Triage and validation | A paired run on fresh seeds: precision rises, and recall stays within 2 of the unvalidated arm |
| **2.4** | Terrain: the crawl accounts for code's edge candidates; business rules as implemented | Scan: system context | Rule-change and cross-module seeds are caught; no regression elsewhere |
| **2.5–2.7** | Coverage for the 90% set: extractors, framework models, checks, ladders | Scan: breadth | Detection snapshots, plus one live review per new block |
| **2.8+** | MCP as its own tool; measure and prune | All | Per item |
| **Later** | Suggested fixes; onfire; the improvement pipeline; other agents; vld8.ai; new tools (repo health #116, pentest #117, cvm #119, smartci #121); the test lens; the review in CI (#146) | Suggested fix, and more | After 2.3's validation is measured |

**The order:**
1. **Prove first.** The replay (2.0.x) decides how much of 2.2's candidate machinery gets built.
2. **The verbs,** because every later stage reads and writes their contracts. 2.1's precision work lands inside them rather than as prompt text that would be rebuilt.
3. **Code analysis,** so the model judges a list that code has made complete for what it models.
4. **Validation,** the stage that was never built.
5. **Terrain,** where intent comes from.
6. **Breadth,** last, on an engine whose output can be measured.

## 2.0.x: finish the rename, repo hygiene

**Done (2026-11-23):**
- `main` is the default branch, so the landing page matches what `pip install vld8` installs. `staging` was the default for a few hours, then the change was reverted. Both branches block force-pushes and deletion, require linear history, and require the `test (3.14)` and `test (3.15)` checks (switched from `test (3.10)` and `test (3.13)` on 2026-11-25, when the 3.14 floor landed). The rules apply to admins too. No reviews are required. A direct push is accepted only for a commit that has already passed CI.
- Repo hardening: release tags can't be moved or deleted, and releases are immutable. Dependabot opens one grouped PR a week against `staging` for the pinned actions (#106). Actions are limited to GitHub's own plus the PyPI publish action, each pinned to a commit. CodeQL, secret scanning and push protection are on.
- Publishing only from `main`: `publish.yml` refuses a release tag whose commit isn't on `main` (#43). It reached `main` by a fast-forward promotion (#44), the first under the branch model below.
- The plan landed on `staging` (#45), replacing draft #40.
- The announcement post is live at cyrus.is/building/vld8.

**Done (2026-11-24):**
- `ENGINEERING.md` names `/vld8-security` instead of the Scrutineer audit (#120), following the shared standard's rename.
- 2.0.1 released (#108, #109, #113).
- Publishing is gated on the `pypi` environment: the publish job uses it (#106), and both PyPI trusted publishers name it.

**Done (2026-11-25):**
- Python floor 3.14, with CI testing 3.14 and 3.15 (#142, for #124; D15). The required checks on `staging` and `main` are now `test (3.14)` and `test (3.15)`. It ships in 2.0.2, with the release-notes callout the version rules require.
- **Map schema 1.2** (#143, for #123):
  - `process`, `ipc` and `file` edges;
  - `evidence[]` on edges and components;
  - `vld8 map validate --check-evidence`, which recomputes each evidence hash offline and reports drifted, moved and missing evidence.

  The crawl skill records evidence and keeps findings out of the map. For now it lists its observations in its final report; writing them to the findings JSON (design §7) waits until the skills use the verbs. It ships in 2.0.2.
- **CI lint and pinned dependencies** (#148, for #46 and #48):
  - ruff in CI;
  - a hash-pinned `requirements/ci-constraints.txt` applied through `PIP_CONSTRAINT`, so isolated builds are covered too;
  - Dependabot for that file, with a cooldown.

  Seventeen older files are excluded from the format check until #149 formats them.

**Open:**

| Item | Owner | Source |
|---|---|---|
| **A GitHub account for the agents:** a machine user with write access and its own token. Today every agent PR is authored by `cyrus-is`, and GitHub won't let Cyrus approve his own PRs. Once it exists, `staging` also requires a PR and one code-owner approval (Cyrus can bypass the review rule for PRs he writes himself) | Cyrus | Cyrus, 2026-11-23 |
| **Branch model (in use since #44):** feature PRs squash into `staging`. `main` receives only releases: a "Release X.Y" PR from `staging` for review and CI, then a fast-forward push of `main` to `staging`, which GitHub records as merging the PR. A squash or rebase promotion would put commits on `main` that `staging` doesn't have, and the two would drift | Cyrus | Cyrus, 2026-11-23 |
| Archive `scrutineer` on PyPI | Cyrus | Rename |
| Update the GitHub repo description, which still describes Scrutineer | Cyrus | Rename |
| Point vld8.ai at cyrus.is/building/vld8 | Cyrus | Plan D8 |
| **Release 2.0.2:** schema 1.2, the Python floor and 2.1's CLI helpers (no skill calls them yet) are on `staging`. Decide whether the helpers' open trust follow-ups (#161, #164, #167, #172) block it. The notes must name 2.0.1 as the last release for Python 3.10–3.13 | Cyrus | Release train |
| **The replay** (#125), on consumer loops' recorded history (private):<br>• the candidate lister is frozen before the test changes are chosen, and no change that informed the design is eligible;<br>• three arms: the old prompt, today's thorough prompt, and that prompt plus vld8's code findings and candidates;<br>• win, partial, tie and loss outcomes are fixed before any run.<br>The result decides how much of 2.2's candidate machinery gets built | vld8 | Design §15 |
| Add a diff-coverage gate at 80% to CI (#47) | vld8 | STD |
| Write `decisions/` records for: the MCP auditor built instead of the triage layer (April, written up after the fact); the rename (D7); dev-tooling positioning (D3) (#49). Also the design's decisions D9–D16, design §17 (#174) | vld8 | STD, CR-8 |
| **Fixes to today's skills, CLI and release tooling,** found by validation and review: <br>• detection (#95–#98, #100, #104); <br>• Mode 2 and Phase 0 (#101, #110, #111); <br>• install and setup (#102, #103); <br>• the preview flag (#112); <br>• the publish workflow's floor check (#99); <br>• servicemap docs (#145) | vld8 | Validation |
| **Hardening filed during the 2.0.x work:** <br>• formatting the remaining files (#149); <br>• pinning `build` in the publish workflow and widening Dependabot (#150); <br>• MCP review file handling (#147, #151); <br>• generator hardening (#155); <br>• test isolation from the host's git config (#160) | vld8 | Reviews |

## 2.1: the verbs, and precision without a spec

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

**What ships:** the three verbs, with 2.1's precision items placed where they belong (design §9). They sit behind the 2.1 preview flag (see *Release train*), and today's generated skills stay the default until the gate passes.

**Built (2026-11-25 and 26), on `staging`,** as CLI helpers no skill calls yet:
- findings contract v1 with fingerprints (#144);
- `vld8 review report` (#152);
- `vld8 checks --changed` and `vld8 review size` (#153);
- trust and state (#157);
- the context packet (#163);
- `vld8 review prepare` with `prepare.json`, `prompt.md` and a first `--tier fast` (#166). That writes only `prepare.json` and exits 1 on blocking code findings. Those come only from `--evidence` until 2.2's code findings land (#136);
- golden-output snapshots of the generated skills (#156).

`prepare` reads a PR's head and base as git objects with no checkout, and fails closed if the base can't be fetched. It pins every ref to a commit id and keeps all run state outside the worktree. Its review follow-ups are tracked under 2.1.

| Item | State | Source |
|---|---|---|
| **The eval set and the held-out harness** (#83, #57). They come first, because every later gate is measured with them | Open. Cyrus runs it, because the eval data is private (see the gate's *Where the data lives*) | Gate support |
| **Findings contract v1** (#58): file, lines, lens, `checkId`, claim, evidence, severity, basis; plus `class` (rule, `sites[]`, `fixSite`, "closes N of N"), `source` (code, model, both), `proof`, `blocking`, `disposition`, and fingerprints per site and per class. Written alongside today's Markdown at first | **Built** (#144). Follow-ups: control characters (#154); fingerprints a model can compute (#169) | CR-1, design §9 |
| **Choose JSON key casing on purpose.** `ENGINEERING.md` says camelCase, but the MCP output and the service map use snake_case. Convert, or record the deviation | **Decided** (#144): new contracts use camelCase; the service map and MCP output stay snake_case, recorded as deviations | CR-1 |
| **`vld8 review report`** (#126): <br>• checks the accounting (every candidate ruled on), the citations (file, line and quote exist) and the rubric form; <br>• sets the verdict from ISSUEs only (#51); the lens table cites findings only (#55); <br>• renders md, json and SARIF; exits 0 clean, 1 blocking, 2 incomplete or invalid | **Built** (#152). Follow-ups: checking citations against the reviewed tree's objects (#170); symlink and size hardening (#161, #164, #165) | SP-2, SP-6, design §9 |
| **`vld8 review prepare`** (#127): <br>• the PR head and base read as git objects, fork and bot detection, diff sizing (the #93 behaviour, moved into code); <br>• check selection at review time (#61); rules files (#52); optional intent sources (#56); <br>• modes 1–4; the context packet with a size budget | **Built** (#153, #163, #166). #52 and #56 stay open until the skills switch (#129) uses them. Follow-ups: <br>• git environment and blob limits in `checks` (#162); <br>• bounded output and unsafe paths (#168); <br>• fingerprints a model can compute (#169); <br>• the `prepare.json` byte cap (#171) | SP-3, SP-4, CR-4, SP-8, design §9 |
| **Trust and state** (#128): <br>• config, check packs and commands come only from the trusted base ref or from outside the repo; <br>• state lives in the git common dir; <br>• `--evidence` counts only when it names the reviewed tree; <br>• `--prior` records a disposition for each earlier finding | **Built** (#152 for `--prior`, #157, #166). Follow-ups: <br>• per-run PR fetch refs (#167); <br>• the remaining outside-the-repo gaps (#172) | Design §6, §10 |
| **Evidence rule** (#50): ISSUE only with evidence of need. That means it breaks a written rule, a confirmed map rule or a stated requirement; departs from a contract two named sites follow; has a traced, reachable trigger; or breaks a security invariant. Otherwise it's at most a CONCERN, which must name a concrete scenario. One vocabulary for the code review; the security lens keeps CRITICAL–LOW, mapped by the contract | **Partly built:** `report` downgrades an ISSUE without a `basis`. `prompt.md` lists the six bases, says every ISSUE needs one, and says a broken written rule must be quoted. Still open: explaining each basis, and the rule that a CONCERN names a concrete scenario | SP-2, Cyrus |
| **Ambient-nondeterminism check** (#54) in the lens prompt | Open | SP-5 |
| **The skills switch** to prepare → lens prompt → report behind `--preview 2.1` (#129), with the snapshot harness (#84) | Open; unblocked now the verbs exist. Snapshots of the generated skills are built (#156); snapshots of `prepare` and `report` are #158 | Release train, gate support |
| **Storage** (#59): run outputs (`prepare.json`, `prompt.md`, findings JSON) go under `<git-common-dir>/vld8/runs/<tree id>/<run id>/`, never in the worktree, which supersedes plan §4's `.vld8/findings.json`. `triage.json`, which holds people's decisions, stays checked in | **Partly built:** `prepare` writes `prepare.json` and `prompt.md` there (#157, #166). Where the findings JSON and the rendered report go is still up to the runner, and the checked-in `triage.json` is open | Cyrus, 2026-11-23; design §6 |

**Gate:** the held-out test, pre-registered before any run.
- **Calibrate first** (#82). Re-score the study's existing findings under the evidence-of-need definition. That sets the expected baseline and the precision threshold. The old +20-point bar was calibrated on the dropped Spec-questions mechanism and no longer applies.
- **Metric:** precision over all findings (ISSUE and CONCERN), with ISSUE-only reported alongside. Recall is the number of seeded defects found.
- **Sets:**
  - primary: real PRs with no spec, at least 15 fresh seeds across about 10 PRs, plus 2 clean PRs;
  - secondary: spec-driven change sets, used only as a no-regression guard: precision and recall must not drop below 2.0.0 by more than the noise band, which is two reps differing by up to 3 defects.
- **Runs:**
  - 2.0.0 (with no preview) and the 2.1 preview, on the same sets, under the same scoring, 2 reps each;
  - a result is inconclusive if two reps differ by more than 3 defects.
- **Ship if:** precision is at least the calibrated threshold, and recall is at least 2.0.0's − 2 seeded defects on the same set.
- **Judging:** the judge checks each finding's evidence against the code, not just whether the finding follows the rubric's form.
- **Where the data lives:** private storage, because real PRs from private repos can't be committed to this public repo.
- **If it fails:** the items stay behind their flag. Any re-test uses fresh seeds, because a set that informed a fix is no longer held out.
- **What the gate can't separate:** it measures the prompt changes and the new structure together. That's accepted, because the structure is what ships either way.

**Needs:** decision **D4**: test before the default changes.

## 2.2: code analysis and the fast tier

vld8's code starts finding issues itself, and listing the sites the model must rule on (design §5–§8).

| Item | Source |
|---|---|
| **The fact cache** (#130): SQLite in the git common dir, holding only code-sourced rows, with observed and derived columns kept apart (design §6) | Design §6 |
| **Extractors, consumer languages first** (#131): Swift through tree-sitter (an extra, under the dependency policy, D16), Python through stdlib `ast`, then TypeScript | Design §6, loop analyses |
| **Imports and callers,** and the **callers check** (#53, moved here from 2.1 because it needs import facts). The cross-module seeds scored 0 of 2 | SP-9, CTX |
| **Comparing facts before and after a change** (#132), which gives each change its risk list | Design §6 |
| **Code findings (exact proofs):** OSV matches on lockfiles, and rule-pack violations. **Candidates the model rules on:** departures from a pattern the code already follows, and the change's effects on the system (a route added with no auth, a new process launch, an edge the map doesn't have) | Design §5 |
| **Repo rule packs** (#133): call boundaries, placement, banned API and required helper, census and pins matching their sources, references that resolve, vendored data matching its pins (design §8.1) | Loop analyses |
| **The checks every loop rebuilt** (#134): <br>• a private-denylist leak check that never prints a match; <br>• pinned Actions and dependencies; diff hygiene; <br>• discarded errors; sleeps and the wall clock in tests; vacuous assertion shapes; <br>• orchestrated script and workflow linters (design §8.2) | Loop analyses |
| **Orchestrated analyzers** (#135): run linters and SARIF-producing tools with the base ref's config and vld8's rule selection, and read their results. On a fork's or a bot's PR, nothing runs and only `--evidence` is read | Design §4, §10 |
| **`vld8 review prepare --tier fast`** (#136): code findings only, in seconds, with an exit status. The switch and its exit status landed with #166; this item adds code's own findings, since today they come only from `--evidence` | Design §9 |
| **Hybrid checks the replay justified** (#137), each with a proof; `shell=True` and secrets-in-failure-output first | Design §8 |
| **The check schema** (#138; `kind`, `applies_to`, `tier`, `query`, `judge`, `proof`, `blind_spots`), added as each check's query lands; #118's inventory labels every step | Design §8, #118 |
| **One shared analyzer module and one detection spec** for both lenses (#60) | CR-5, COV |
| **Bring the security lens to parity** (#62): Phase 0, diff sizing, Check Performance | CR-5 |
| **Security eval set** (#85), so changes to the security lens have a gate | Gate support |

**Gate:**
- CI and the snapshot harness;
- a regression run of the 2.1 eval with the 2.2 preview: precision and recall within 2.1's noise band;
- the security eval, for the security-lens items;
- fast-tier precision per check on a corpus, and wall time on the largest consumer repo;
- **each item also has its own gate before it's added to the preview:** fixture tests for each extractor and framework model, fixture rules for each rule shape, and the replay's outcome for hybrid checks.

## 2.3: validation and re-review

This is the stage that was never built.

| Item | Source |
|---|---|
| **A separate validator over the findings JSON.** It takes its contract from `mcp-review/validate_findings.py`: it can only suppress or downgrade, and it records why. The refutation itself is new work: a fresh context reads the callers, checks the verify-before-judging results, and reproduces where it can. So is turning the prose exclusion lists into categories it can apply consistently | CR-3, CTX |
| **Proof hooks** (#139): probes, tests and canaries that confirm or refute a finding; #117 plugs in here later | Design §8, §11 |
| **Re-review** (#140, `report --prior`): <br>• code re-runs each earlier finding's proof; a class closes when its proof passes; <br>• a finding whose class comes back is marked recurring; <br>• fix growth is shown as a signal, not a finding; <br>• the model rules on each earlier finding, then reviews the delta. <br>Recurrence marking and per-finding dispositions are already in `report --prior` (#152); proof re-runs and the rest are open | Design §11, loop analyses |
| **Retire the security skill's pasted-in exclusion list** and its contradictions (rate limits, CVEs, ReDoS). This happens only after the validator becomes the default, because removing the list earlier would leave default users with neither | CR-3 |
| **SARIF upload,** opt-in, for GitHub code scanning. Its states map onto still on fire, false positive and ignore (rendering lands in 2.1) | Cyrus, 2026-11-23 |

**Gate:** a paired run on fresh seeds. The same saved findings JSON is scored with and without the validator. Precision rises, recall is at least the unvalidated arm's − 2 on the same seeds, and every suppression is listed with its reason.

## 2.4: terrain

The service map becomes the system's known terrain, and the reviews read it. Design: plan §4, *Terrain*, and design §7.

| Item | Source |
|---|---|
| **The crawl accounts for code's candidate edges** (#141): each one is recorded, or explained, and the crawl adds what code can't see | Design §7 |
| **Business rules as implemented in the map:** <br>• authorization (who can do what to which resource), including capability grants such as sudoers rules, tool allow-lists and command allow-lists; <br>• tenancy; trust translation points; identifier properties; data classifications. <br>Each comes with evidence and a confidence. Accepted risks are *not* in the map; they're triage decisions | Cyrus, CTX, design §7 |
| **`vld8 map rules`:** reports the rules as implemented and asks yes / no, bug / not sure for each. Yes is confirmed terrain in the checked-in map. A bug is a finding, stored like findings and never in the map. Not sure stays a hint | Cyrus |
| **Rule-change detection in reviews:** compare the rules as implemented before and after the diff. A change to a confirmed rule is an ISSUE; a change to an unconfirmed rule is a question | Cyrus |
| **`crawled_commit`,** plus a CI refresh that opens a PR. Drift detection itself landed with schema 1.2 (#143) | CTX |
| **Terrain slice in the context packet:** Modes 1 and 2 read only the touched components' terrain; Modes 3 and 4 keep the full map | SP-10 |
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

Since the code-first conversion, each Tier 1 entry also gets an extractor and framework models (design §6). Its facts then feed code findings, candidates and rule packs, and a file no extractor covers is listed as unmodelled.

| Release | Items | Source |
|---|---|---|
| 2.5 | Two-layer detection, package roots, roles, and an **uncovered-files report**, so nothing is silently skipped. The Kotlin JVM block is split from Android | COV |
| 2.6 | **Verification ladders for Tier 1:** TypeScript/JS, Go, Rust, C#, Java, Kotlin, Shell. Swift and Python already have them. Then Tier 2 ladders (PHP, C/C++, Ruby, Dart and the rest, plan §5) | COV (research) |
| 2.7 | **New blocks:** Cloudflare Workers, Shell, AWS serverless, Next.js server code, LLM/MCP apps, Unity, HTML templates. Then Tier 2 (C, Dart) | COV |

**Gates:**
- **Each new block:** detection snapshot tests, plus one live review on a real repo, recorded in Check Performance.
- **Each ladder:** a seeded run showing the ladder's exclusions don't suppress real defects. Detection snapshots can't catch that.
- **Flags:** blocks and ladders ship behind their milestone's preview flag (`--preview 2.5` and so on). Each one is enabled by default only after its own gate passes, and those flips land at the milestone boundary.

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
- **New tools, each on the shared engine:**
  - repo configuration health (#116);
  - pentest, which confirms findings against a running app you own (#117);
  - `vld8 cvm`, which finds agent steps that should be code (#119);
  - `vld8 smartci`, which measures and restructures CI (#121).
- **The test lens:** a third lens for test quality (design D13).
- **The review in CI** (#146): a review a pipeline can call. It builds on the 2.1 verbs and 2.2's fast tier rather than on 2.3, so its timing is set by a design discussion first: the runner, credentials, fork-PR trust, output, and carrying `--prior` across pushes.

## Release train

**Cadence:** from 2026-11-23, one reviewable change a week (Cyrus: "just one thing a week"). **Since 2026-11-24 the code-first conversion is the main line:** changes go back to back as capacity allows. Each is still one reviewable PR with a fresh-context review.
- **Grouping:** small items from the same milestone can be grouped into one change when they're reviewed together.
- **Splitting:** large items (the validator, the ladders, new blocks) get split into weekly slices when their turn comes.
- So the backlog's item count sets a pace, not a schedule. Fixes found by validation join the 2.0.x milestone as they're filed, so the count moves.

**Who runs it:** Cyrus starts each working session, interactively. Coding agents build each change and, until the agent account and code-owner approval exist, merge it into `staging` once a fresh-context review of its head is clean, escalating to Cyrus when reviews don't converge. Releases to `main` stay with Cyrus. No unattended loop runs it (`ENGINEERING.md`: `autonomy: interactive-only`).

**The backlog:** every vld8-owned roadmap item is an issue under its release milestone, along with the eval and gate-support work. The milestones were swept to match the 2026-11-24 revision: issues moved to their new releases, shipped items closed, and the new items got issues (#123–#141).

**Flags:**
- **Changes to review output** ship behind their milestone's preview flag (`vld8 install --preview 2.1`) until the milestone's gate passes. Then the flag becomes the default. Review output means what's found, how it's rated, or how it's rendered.
- **Changes that don't alter output** ship as is: CI, docs, JSON written alongside unchanged Markdown, and CLI helpers no skill calls yet. Switching a skill to `prepare` and `report` is an output change.
- **A removal waits for its replacement to become the default.** For example, the security exclusion list goes only after the 2.3 validator is the default.

**Release when `staging` has a package change and CI is green on it,** with Cyrus's go-ahead. CI-only and docs-only changes don't release.
1. Commit the version bump on `staging`. `publish.yml` refuses a tag that doesn't match the built version.
2. Open a "Release X.Y.Z" PR from `staging` to `main`, with notes drafted from the merged PRs.
3. Cyrus approves it. Until the agent account exists, PRs are authored as `cyrus-is` and can't be approved in GitHub. Until then, approval is Cyrus's explicit go-ahead.
4. Fast-forward `main` to the approved commit, `git push origin <approved-sha>:main`, not to whatever `staging` has moved to since. `main` accepts the push only because CI already passed on that commit on `staging`.
5. Run `gh release create vX.Y.Z --target main`. Releases are immutable: once one is published, its tag and attached files can't change, so check the target commit first.
6. Cyrus approves the `pypi` deployment, and the package publishes.

**Version numbers:**
- **Patch:** default output doesn't change (fixes, flagged items, infrastructure).
- **Minor:** a milestone's flag becomes the default (2.1.0, 2.2.0 and so on), one minor version per milestone.
- **Raising the Python floor** can ship in a patch, because `requires-python` keeps older interpreters on the last compatible release. The release notes must say so first, naming that last release.

**The train stops** when the milestones before "Later" are closed. The cadence is then revisited.

## Decisions this roadmap waits on

| # | Decision | Needed before |
|---|---|---|
| D1 | One engine with two lenses, or one merged review | **Decided** 2026-11-25 (#90): one engine with two lenses, adopted with the design (#122) |
| D2 | Positioning: our own engine, or an expertise pack for other engines | 2.8 (MCP split), and before publishing the contract |
| D4 | Held-out test before a milestone's default changes (items ship earlier behind a flag) | 2.1's default flip |
| D5 | MCP review stays in the package until it becomes its own tool | 2.8 |
| D6 | File the ~90% research note in the private research registry | 2.6 (it sets the Tier 1 list) |
| D8 | Where the vld8.ai site lives | Later; the redirect is a 2.0.x item |
| D9, D10 | Facts cache; code-check backends (design §17) | 2.2 |
| D11, D14 | Trusted config; runner-neutral prompts (design §17) | 2.1 |
| D12, D15, D16 | A self-contained map; the Python floor (decided: 3.14); the dependency policy (design §17) | 2.0.2 |
| D13 | The test lens (design §17) | After 2.3 |
