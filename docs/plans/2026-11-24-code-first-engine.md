# Design: a code-first review engine

**Status:** v2 draft (2026-11-24) for Cyrus's approval. Approving it is the design review, per `ENGINEERING.md`.
- v1 went through an independent design review, with the verdict "adopt with changes". This version takes those changes and Cyrus's answers to the review's questions.
- It builds on the restructure plan (`docs/plans/2026-11-23-restructure.md`) and replaces the shape of roadmap releases 2.1–2.4. §15 has the new order.

**Priority (Cyrus, 2026-11-24):** this conversion is the main line of work. The goal is an engine that is built, tested, validated and resilient. A fast mode that reaches quality sooner should speed up the autonomous build loops that use vld8.

## 1. In one page

**vld8 finds the issues, with code and a model together.** Today a model builds the service map, a model reads it, and every review step is prose in a 60 KB generated prompt. In this design:
- **vld8's code** handles everything with one right answer:
  - checking out the change and sizing it;
  - choosing the checks that apply;
  - extracting facts and comparing them before and after the change;
  - finding issues that code can prove;
  - listing the candidate sites a model must judge;
  - checking the model's output and rendering the report.
- **vld8's prompt** handles judgment: ruling on every candidate, the open-ended pass, intent, absence, severity by need, naming classes and choosing where to fix them. Any model can run it, Claude Code or another agent, but the instructions, checks and rubric are always vld8's.
- **vld8's code merges both sets of findings.** Every finding is labelled with its source (code, model or both), and every citation is checked against the code.

**Three verbs:**

```
vld8 review prepare  ──▶  vld8's lens prompt, run by any model  ──▶  vld8 review report
(code: checkout, size,     (judgment: rule on every candidate,        (code: merge, check accounting
 route, facts, diff,        open-ended pass, classes, fixes)           and citations, rubric form,
 code findings,                                                         verdict, classes, recurrence,
 candidates, packet)                                                    render, exit code)
```

**A fast tier** runs `prepare` alone: code findings only, in seconds, with no model. It's for a loop to run after a build and before its gate or model review, or for a pre-commit hook.

## 2. Problem

**A model at both ends.**
- The map is crawled by a model and read as prose.
- Every review step is prose, including the ones with one right answer.
- A review takes minutes even for questions code could settle in seconds.
- Nothing runs without a model.

**Reviews stop early, and a clean review says nothing.** Evidence from a private build loop that runs review and fix cycles unattended:
- Across its parseable history, 38 of 82 reviews that asked for fixes reported exactly one blocking finding, and re-reviews averaged 1.67. The 42 reviews still on disk show the same share: 12 of 28.
- Narrow fixes caused 16 of the 25 findings that came back after a fix.
- One change spent six reviews on one defect class. Credential values reached test-failure output through five different routes, and each route was found by a new kind of test injection, not by searching more sites.
- No review said what it had checked. vld8's own pre-flight table says "Do not list passing checks."

**Generic fast checks barely speed loops up; better first reviews and repo rules do.** Two more private loops were measured, both building Swift apps:

| | Loop A (1 month) | Loop B (5 weeks) |
|---|---|---|
| Findings that need judgment | 77% of 443 P1/P2s | about 89% of 2,283 |
| Rounds a code-only tier could have removed | 16 of 179, about 7% of fix time | 1 of 329, about 1.5% of item wall time |
| Where the time goes | fix cycles (median 39 min) and builders' gate, test and simulator time (about half their span) | fix cycles plus a CI re-run after each push (median 61 min) |
| Recurrence | mostly judgment classes; fixes often caused the next round's findings | 323 of the 365 findings that were still open or came from the previous fix needed judgment |

- **Both loops built their real fast tier in the slow lane.**
  - Loop A has about 170 rules in 31 source-text test files, on a hand-written lexer. One was bypassed by a type alias.
  - Loop B has about 138 census, pin and wiring test files inside an 8-minute test stage. Three P1 census failures surfaced only when someone ran the full suite.
- **So the fast tier's value is running a repo's own rules in seconds before review** (§8.1), plus a short list of checks every loop rebuilt (§8.2). Speed comes mostly from fewer rounds: better first reviews (G2) and reviewing the fix's delta (§11).
- CI re-running trees that already passed costs more than any of this. That's each loop's own fix, not vld8's.

**The map can't hold some systems' most important edges.**
- A crawl of a private orchestrator produced 80 valid edges. 24 of its 26 `infrastructure` edges would fit a process or IPC type. The crawler itself noted 20 of them as launches, socket calls or signals, including a launch as another user.
- Security observations landed in free-text notes.
- Staleness and `manual_override` handling are prose instructions that no code enforces.

**The phases are fixed.**
- Phase 0 always runs the toolchain itself, even when a two-hour gate has already run.
- There's no re-review input.
- A repo can't add its own pass without forking the generator.
- Only Claude Code can run the reviews.

## 3. Goals

| # | Goal | Measured by |
|---|---|---|
| G1 | **Every step with one right answer runs as code**; the model does judgment only | #118's inventory: every step labelled, every code step tested |
| G2 | **Accounting, not a claim of exhaustiveness.** Code lists candidates and every one gets a ruling; the open-ended pass stays; the report names what each candidate list can't see | The replay (§15 Phase 0); then sites found per class against ground truth, and class recurrence in a loop |
| G3 | **A fast tier that runs the repo's own rules and vld8's code findings in seconds, before review,** with no model | Rule failures caught before review and CI rather than in the full suite; wall time on the largest consumer repo. The main speed lever for loops is fewer rounds (G2, §11), not this tier |
| G4 | **The map is a database you can check against the code.** Every edge carries evidence; drift is computed | Edge recall against a labelled set; drift found when cited code changes |
| G5 | **Flexible phases without a fork.** Outside evidence, prior findings, a consumer's own runner and extra passes | A loop runs it with its own gate result and runner, plus one added pass |
| G6 | **Everything machine-readable, and every report says what was checked** | Findings JSON validates; the coverage table lists every applicable check and candidate list |
| G7 | **Resilient:** deterministic code stages, graceful degradation, and safety on untrusted PRs | §12's failure tests pass |
| G8 | **The plan's commitments hold:** evidence rubric, suppress-only validator, storage split, preview flags, held-out gates | No regression on each milestone's eval |

**Non-goals:**
- **Rebuilding CodeQL's per-language data flow.** vld8 reads SARIF from tools that do it, and its own facts stay syntactic.
- A fix stage.
- Replacing linters. vld8 runs them, or reads their results.
- A custom query language.

## 4. Prior art

- **CodeQL**:
  - *How it works:* extracts each program into a database, queries it with QL, and keeps framework knowledge in libraries.
  - *Taken:* extract once and query many times; provenance on every fact; framework knowledge kept as data.
  - *Not taken:* its semantic model. As GitHub's terms read, analyzing private code needs a paid licence; SARIF ingestion covers repos that already run it.
  - *What it leaves to vld8:* CodeQL sees inside one program. The system level (one service's call landing on another's route, a shared datastore, a launch as another user) is the service map's job. The map is CodeQL's database one level up.
- **A code-only engine** (an outside design):
  - *Taken:*
    - routing by the map;
    - two tiers;
    - the cache key `(file hash, rule version, map slice hash)`;
    - rules that declare where they apply;
    - diff-aware reporting;
    - deterministic ordering;
    - suppressions that need a reason;
    - **acting as an orchestrator** that runs existing analyzers with vld8's rule selection and reads their SARIF, instead of rewriting single-file pattern checks;
    - **import and caller facts.**
  - *Not taken:* code-only judgment.
- **The MCP reviewer, in this repo, is the working precedent:** code emits candidates with evidence, a model judges them, and code applies a suppress-only result (`mcp-review/validate_findings.py`).

## 5. What code finds, and what the model finds

| Source | Examples | Reported as |
|---|---|---|
| **Code findings** (proven by code) | **Departure from a followed pattern:** two or more sites follow a pattern and a new one doesn't, such as every route in a component carrying auth middleware except the new one (rubric basis b). **The change's effect on the system,** from comparing facts before and after it: a route added with no auth, a launch added as another user, a credential read in a test role, an edge the map doesn't have. **Known-bad dependencies** (OSV against lockfiles). **Results of linters and SARIF the repo's config enables** | Findings, `source: code` |
| **Candidates** (code can say where, not whether it's wrong) | a launch whose argv may carry outside input (`shell=True` needs user input in the command to be a finding); a `raise` inside an `except` whose frame holds a sensitive name; a test double that may ignore its arguments; every path to a sink, so the guards can be compared | A list the model must rule on, item by item |
| **Model findings** (judgment) | absence, intent, severity by need, a guard that can't fail, a class's rule and fix site, the open-ended pass over the change's risk list | Findings, `source: model` |

**How the two sets merge in `report`:**
- A finding reached by both halves is labelled `source: both`, which is strong evidence.
- The model can dispute a code finding only with a stated reason, and the dispute stays visible.
- Code checks every model citation (that the file, line and quoted text exist) and rejects one that doesn't.
- Code checks the rubric's form: an ISSUE with none of the four bases is downgraded to a CONCERN.
- **Accounting:** every candidate must come back as part of a finding or dismissed with a reason. Output that leaves a candidate unaccounted is rejected, and the run says so. That turns "be exhaustive" from a request into a check.

**Code groups candidates as a proposal.** Clustering by check and by shared sink or fix site is a suggestion the model may merge or split. One defect class can reach output through several routes, and many unrelated launches can share a sink.

**The open-ended pass stays,** with no candidates. A check proves only its exact pattern, never the whole class (`generate.py`'s rule), and the reviewer still hunts for siblings. The coverage table names each candidate list and what it can't see. Each gate also requires that findings with no check behind them don't drop.

## 6. Facts

**They're a private cache, not a second map.**
- **Where:** `<git-common-dir>/vld8/facts.db` (SQLite), so state never lands in the worktree, and worktrees of one repo share it. A `--state-dir` flag overrides the location.
- **What it holds:** only `source: code` rows, rebuildable from the code. Human and model content stays in `servicemap.json`.
- **Columns are split by kind.** *Observed* columns (file, line, the call, its literal arguments) are certain. *Derived* columns are labelled with their method and confidence, never 1.0 by default: sensitivity from a name, `public`, `auth_mechanism`, whether a double `ignores_args`, the file's role.
- **Component is not a fact.** It's an interpretation, so it lives in the map, and facts don't carry it.
- **Fact keys:** `(extractor id, file path, a normalized anchor such as the enclosing symbol plus a kind-specific signature)`. The file hash goes in the cache key, not the identity, so an unrelated edit in a file doesn't make every fact in it new.

**Fact kinds, first set:**

| Kind | Observed | Derived |
|---|---|---|
| `endpoint` | method, path, handler symbol | auth mechanism, public |
| `call_out` | client call, target expression | resolved target |
| `db_access` | driver call, DSN source expression | mode, store |
| `spawn` | call, argv expression, literal program if any | program, as_user, via (sudo, launchd, shell) |
| `ipc` | socket, stdio or pipe calls, signal sends and handlers | channel role |
| `env_read` | name | sensitivity |
| `import` / `call` | module, symbol, call site | callers of a changed export |
| `test_double` | double construction, assertions on it | ignores_args |
| `tool_result` | tool, rule, status, scope, **tree id** | — |

**Comparing the facts before and after a change** (base against head) gives the change's risk list: what it adds, removes or alters in each kind. It feeds both the code findings and the model's open-ended pass.

**Some facts need more than syntax.** In one consumer, a launch's argv is built by one function and spawned by its callers, so no syntactic query yields `program` or `as_user`. Such a site is a candidate and an interpretation question, never a confident fact.

## 7. The service map

`servicemap.json` stays complete and readable on its own: on GitHub, across repos, and for stacks with no extractor.

**Schema 1.2 (additive; old maps keep validating):**
- **New edge types:**
  - `process`: program, as_user, via, environment (inherited or built from nothing), and the data passed in argv or stdin;
  - `ipc`: channel (unix_socket, stdio, pipe, signal) and how the channel authenticates;
  - `file`: a shared control file or directory used as a channel.
- **Network calls made through a CLI** (`gh`, `git`, `docker`) are `http` edges with a `via` field.
- **Container mounts** are recorded on `process` edges, or on infrastructure edges.
- **Capability grants** (sudoers rules, tool allow-lists, surface verb tables) are terrain: authorization recorded as business rules (2.4), not edges.
- **Every edge and component can carry `evidence[]`:** each entry is a file, a line range and a content hash of those lines. `vld8 map validate` recomputes the hashes and reports drift when cited code changes or disappears. A crawl of a private repo already cited file and line for 31 of 80 edges, and every citation resolved.
- **Findings never go in the map.** The crawl skill writes observations to the findings JSON, and `vld8 map validate` warns when notes look like findings.

**Using facts in the crawl (2.4):** code hands the crawl a candidate edge list. The crawl must account for each candidate (record it, or say why not) and can add edges code can't see.

## 8. Checks

The guidance YAML gains these fields, each added when a check's query lands, not all up front:

| Field | Meaning |
|---|---|
| `kind` | `code`: matches are findings. `hybrid`: matches are candidates. `model`: judgment over the packet |
| `applies_to` | languages, frameworks, roles, component tags |
| `tier` | `fast` (code only) or `deep` |
| `query` | tree-sitter query, stdlib `ast` visitor, SQL over facts, or the name of a linter or Semgrep rule run through orchestration |
| `judge` | for `hybrid` and `model`: the question the model answers |
| `proof` | how a finding is shown real: a test, a probe, a query, a canary |
| `blind_spots` | what the candidate list can't see; printed in the coverage table |

**Corrections from the review:**
- `shell=True` is `hybrid`, not `code`: the finding needs user input in the command, and ruff S602 already owns the bare pattern.
- **Secrets in failure output is `hybrid` with a proof.** Candidates are what syntax can list: functions whose frame holds a sensitive name, each `raise` inside an `except`, and launches passed such values. The proof is a canary probe that runs the failing paths and searches the output, reusing the approach of `mcp-review/capture_runtime.py`. Syntax can't see every route, so the probe is what closes the class.
- **A class is closed when its proof passes,** not when its query stops matching. A hybrid check's candidates remain after a correct fix.

**Check Performance becomes data.** The router knows which checks applied, and each records whether it ran, its candidates, its rulings, its findings and its false positives. The report lists every applicable check and candidate list, including those with nothing found, plus their blind spots.

### 8.1 Repo rule packs

**A repo's written rules, run as code in seconds.** Today they live in slow test suites built on hand-written lexers (§2). They're declarative rules in the guidance schema, loaded only from the trusted base (§10). Their findings cite the rule, which is rubric basis (a): the repo wrote it down. First rule shapes:
- **Call boundaries:** only these functions or modules may call X ("only the store batches writes").
- **Placement:** a literal or symbol appears only in file F; code matching P stays inside `#if DEBUG` or a named guard.
- **Banned API, required helper:** "use `normalizeName`, never ad-hoc normalization"; "never `standardizedFileURL` in path guards".
- **Census and pins match their sources:** each needle a census or text-pin test names exists in the file it claims to pin, and matches whole identifiers, not a longer one.
- **References resolve:** docs, ledgers and comments that cite a test, decision, path or symbol point at something that exists.
- **Vendored data matches its pins:** a vendored schema's limits and versions match the code's constants.

Rules resolve names through the fact store, so a type alias or re-export can't hide a call (the bypass in §2). Rules the engine can't express stay in the repo's tests.

### 8.2 Checks every loop rebuilt

Three private loops each wrote their own version of these, so they're vld8's first generic fast-tier checks:
- **A private-denylist leak check.** It matches a diff, and optionally text recovered from committed images, against a denylist kept outside the repo, and reports counts and locations, never the matched text.
- **Pinned third-party Actions and other dependencies.**
- **Diff hygiene:** loop artifacts, compiled files, home-directory paths and unfilled placeholders committed by accident.
- **Discarded errors:** `try?` on a load or a store, `_ = try`, an ignored return code in a script.
- **Sleeps and the wall clock used to synchronise tests.** Timing flakes were 8 of 14 CI failures in one loop.
- **Vacuous assertion shapes:** a non-empty check as the only assertion, an exact count on a substring query.
- **Orchestrated linters for scripts and workflows** (shellcheck, actionlint or zizmor, ruff), with vld8's rule selection.

## 9. The verbs and contracts

**`vld8 review prepare`** (code):
- **Modes:** `--diff <range>`, `--pr <n>`, `--component <name>`, `--deep`. Modes 3 and 4 survive.
- **What it does:**
  - PR checkout into a temporary worktree (the #93 behaviour, now in code), fork and bot detection, and diff sizing and partitioning;
  - routing and check selection (#61);
  - rules files and intent sources;
  - extracting facts and comparing them before and after;
  - running the linters and analyzers the repo's config enables, or reading their results;
  - code findings, candidates, and the context packet with a size budget.
- **Output:** `prepare.json`, holding the code findings, candidates, risk list, packet and coverage, plus `prompt.md`, the lens prompt with only the applicable checks.
- **Tiers:** `--tier fast` stops after code findings and exits with a status. `--tier deep`, the default, also writes the prompt.

**The lens prompt** (model). It must rule on every candidate, review the code findings, and run the open-ended pass. Its output is findings JSON. In Claude Code, `/vld8-review` and `/vld8-security` run `prepare`, do this step in the session, then run `report`. A loop runs the step with its own runner.
- **Runner neutrality is about wording too.** One consumer's Codex reviews were refused when probes were written in attack language. The security lens's prompt uses plain test wording (probe names like `replaced_gitdir`, never "attacker"), and it never prints a secret value.

**`vld8 review report`** (code):
- checks the accounting, the citations and the rubric form, and merges the code and model findings;
- groups classes, using code's proposal as revised by the model;
- applies `--prior` (§11);
- sets the verdict from ISSUEs only;
- renders md, json and SARIF, and exits with a status: 0 for clean, 1 for blocking findings, 2 for incomplete or invalid output.
- A loop formats its own lines from the JSON. vld8 doesn't hard-code one consumer's protocol.

**Two contracts:** `prepare.json` and findings JSON (#58, extended):
- a `class` with its rule, `sites[]`, `fix_site` and "closes N of N";
- `source`;
- `proof`;
- `blocking`;
- `disposition` (for prior findings);
- fingerprints per site and per class.

**Extra passes:** a consumer command that reads `prepare.json` and appends findings JSON before `report`. A repo-specific test review, for example, is a check pack plus, at most, one such command.

## 10. Outside evidence and trust

- **`--evidence <file>`** reads results the repo already has: a gate verdict, linter output, SARIF. Each must carry a tree id equal to the reviewed tree, or it earns no Phase 0 exclusions.
- **Config, check packs, queries and extra commands come only from the trusted base ref or from outside the repo,** never from the tree under review. A PR from a fork can't choose what vld8 runs. This extends #93's rule: vld8 runs nothing from a fork's or a bot's PR without the user's go-ahead.
- **Config format:** TOML, read with the standard library's `tomllib`, which the 3.12 floor (D15) makes available.

## 11. Re-review

`vld8 review report --prior <findings.json>`, after `prepare` on the fix's delta:
1. **Code re-runs every prior finding's proof.** A class is closed when its proof passes.
2. **Recurrence is computed:** a new finding whose class fingerprint matches a prior one is `recurring`.
3. **Fix growth is a signal, not a finding.** The report shows the change in size and the new facts of the class's kinds. A fix that adds a choke-point helper is often correct, so the model judges.
4. **The model** rules on each prior finding (closed, partly closed, or a valid dispute), then reviews the delta.

## 12. Resilience

| Failure | Behaviour |
|---|---|
| No grammar or extractor for a language | Files listed as unmodelled in the coverage table; the review continues |
| The model's output is incomplete or invalid | `report` exits 2 and names the unaccounted candidates and bad citations; the code findings are still reported |
| The model stage fails or times out | `prepare.json` stands alone; the fast-tier result is still valid |
| The fact cache is corrupt or from an old extractor version | Rebuilt, keyed by extractor version |
| Evidence doesn't match the reviewed tree | Ignored for exclusions, and the report says so |
| A PR from a fork or a bot | Its tree's config and commands are never run; analysis is read-only |
| A large repo | Incremental extraction; the fast tier reads changed files only |
| No network | Everything except OSV lookups and PR checkout works offline |

**Every code stage is deterministic:** the same tree, config and versions give byte-identical output. Snapshot tests enforce it.

## 13. Testing and validation

- **Extractors:** fixture repos per framework model, with expected facts.
- **`prepare` and `report`:** snapshot tests (#84), plus tests that `report` rejects an unaccounted candidate, a missing citation, and an ISSUE with no basis.
- **The fast tier:** precision per check on a corpus, and wall time on the largest consumer repo.
- **The deep tier:** the held-out gates (plan §6).
- **G2:** the replay, then sites per class and class recurrence in consumer loops.
- **Edges:** recall against a labelled set, starting with a private crawl whose edges were checked by hand.

## 14. What stays with the model

- Intent and business rules (confirmed by a person in 2.4).
- Severity by need.
- Absence.
- Naming a class and choosing its fix site.
- Edges code can't resolve.
- Rulings on candidates.
- The open-ended pass.
- Validation.

## 15. Roadmap

Releases ship behind preview flags, and today's generated skills stay the default until each gate passes.

**Phase 0: decide and prove.**
1. This design and its decision records, approved.
2. **Map schema 1.2** (§7) and the rule that findings never go in the map. It needs no fact store; ships as 2.0.2.
3. **The replay,** on a consumer loop's recorded history (kept private):
   - **Ground truth:** every site a later review flagged that already existed in the tree the first review saw, in three changes.
   - **Arms:** the old prompt; today's thorough prompt; that prompt plus vld8's code findings and candidates. Two reps each.
   - **Built for it:** minimal `prepare` and `report` (with accounting), plus one stdlib `ast` candidate lister.
   - **Success, fixed beforehand:** the third arm finds at least 80% of ground-truth sites, beats the second arm by more than the spread between reps, and loses nothing the second arm found.
   - **On a tie:** keep code for #118's deterministic steps and code findings, and drop hybrid candidate lists from Phase 2.

**Phase 1: the verbs (2.1).**
- The eval set and held-out harness (#83, #57).
- Findings contract v1 with classes and sources (#58).
- `report`: accounting, citations, rubric form, verdict (#51), lens table (#55), renderers, exit codes.
- `prepare`: checkout, sizing, routing (#61), rules files (#52), intent sources (#56), modes 1–4.
- Trust and state (§10, §6).
- `--evidence`, and `--prior` with dispositions.
- The skills switch behind `--preview 2.1`, with snapshot tests (#84).
- The rubric (#50) and the nondeterminism check (#54) in the lens prompt; calibration (#82).
- **Gate:** the held-out test against 2.0.0.

**Phase 2: code analysis and the fast tier (2.2).**
- The fact cache.
- Extractors for the consumer languages first: Swift through tree-sitter (two of the three measured loops are Swift apps), Python through stdlib `ast`, then TypeScript.
- The fast tier's first contents: repo rule packs (§8.1) and the checks every loop rebuilt (§8.2).
- Imports and callers; the callers check (#53).
- Comparing facts before and after a change.
- Code findings (followed-pattern departures, effects on the system, OSV).
- Orchestrating existing analyzers through SARIF.
- `--tier fast`.
- Hybrid checks the replay justified, each with a proof.
- **Gate:** no regression on the 2.1 eval, plus fast-tier precision and wall time.

**Phase 3: validation and re-review (2.3).**
- The validator over the findings JSON.
- Proof hooks (probes, tests, canaries).
- Re-review (§11).
- **Gate:** a paired run on fresh seeds.

**Phase 4: terrain (2.4).**
- The crawl accounts for code's candidate edges.
- Business rules and `vld8 map rules`, including capability grants.
- The terrain slice in the packet.

**After:**
- coverage per Tier 1 platform (extractors, framework models, checks);
- the test lens;
- runner adapters;
- `vld8 cvm` (#119).

## 16. Risks

| Risk | Mitigation |
|---|---|
| G2 doesn't hold | The replay decides before the fact store is built |
| Overselling the fast tier | Two measured loops show generic code checks save 1.5–7% of loop time. The design claims rule packs and early failures, not cycle savings, and measures that |
| False completeness | Accounting; blind spots in the coverage table; the open-ended pass; the gate on findings with no check behind them |
| Running a fork's config | §10: trusted base or outside the repo only |
| State in the worktree breaking a loop | §6: the git common dir |
| Maintaining framework models | Tier 1 only; fixture tests; unmodelled files reported |
| The tree-sitter dependency | An extra until proven; tree-sitter 0.27 publishes cp314 and cp315 wheels, and the Swift and TypeScript grammars ship abi3 wheels (checked 2026-11-24); Python needs only stdlib `ast` |
| Original-system bias, repeated with one new consumer | Evaluate on several consumers and on the portfolio's other shapes |
| Rewrite risk | Phases behind flags; the generated skills remain the default until each gate passes |

## 17. Decisions

| # | Decision | Status |
|---|---|---|
| — | The conversion is the main line; the fast tier is wanted | **Decided** (Cyrus, 2026-11-24) |
| D9 | Facts: a private SQLite cache in the git common dir; the map holds edges, with evidence | Recommended; assumed |
| D10 | Code checks: stdlib `ast` for Python, tree-sitter as an extra for other languages, orchestrated analyzers via SARIF; Semgrep optional | Recommended; assumed |
| D11 | Config only from the trusted base ref or outside the repo | Recommended; assumed |
| D12 | `servicemap.json` stays complete and readable on its own | Recommended; assumed |
| D13 | A test lens on the shared engine, after 2.3 | Recommended |
| D14 | Model stages: vld8's prompt run by any runner; vld8 renders JSON plus an exit code, and the consumer formats its own protocol | Recommended |
| D15 | **Python floor: 3.14** (released 2025-10-07). CI tests 3.14 and 3.15 (released 2026-10-09, the newest stable). Config can be TOML through `tomllib`.<br>**Rule (Cyrus, 2026-11-24):** "We should never be partial to old tech for the sake of continuity. We can always adopt newer tech provided it meets our supply chain requirements." Any release over a week old is acceptable.<br>**Dependencies:** PyYAML and tree-sitter publish wheels for both versions, and the grammars ship abi3 wheels.<br>**CI:** the required checks change with this, which is Cyrus's setting | **Decided** |
| D16 | **Dependency policy.** Adopt a newer dependency or runtime whenever it meets the supply-chain bar: at least a week old; pinned with hashes in the constraints file; published with provenance (Trusted Publishing or attestations) where the ecosystem supports it; actively maintained; licence-compatible; covered by Dependabot. tree-sitter and its grammars are checked against this bar before they move from an extra into the default install | Recommended |
| D1 | (existing) One engine, two lenses | Yes: this is that engine |
