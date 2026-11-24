# Plan: restructure vld8 (formerly Scrutineer) into three tools that review the way the original did

**Status:** draft for Cyrus's approval (2026-11-23). Approving it is the design review, per `ENGINEERING.md` § Design review & plans. The open questions are listed under **Decisions needed**; each one carries a recommendation.

**Starting point:** vld8 2.0.0, PR #41. It ships the 1.7.0 fixes from #39 (rendering, TypeScript detection, git index, install paths) under the new name. This plan covers what comes after it.

**Naming:** the rename to vld8 shipped in 2.0.0, ahead of P1 (D7). The evidence in §2 describes the tool as it was then, under its old name.

**Release order:** `docs/ROADMAP.md` (PR #42) puts these phases in release order and gives each release its ship gate.

## 1. Goal

In Cyrus's words: *"Targeted reviews with deep language and platform expertise to find issues in code."* The original design was a pipeline: scan → triage and validation → rated finding with lines and context → suggested fix. The second and third stages were never built; the MCP reviewer was built instead.

Effective means three things:

1. **Context.** The reviewer knows the system it is reviewing: its rules, trust boundaries, contracts, and the intent of the change.
2. **Validation.** A finding reaches the reader only after something other than its author has tried to refute it.
3. **Coverage.** The reviewer covers the platforms that make up ~90% of shipped code, and says so loudly when a file falls outside them.

## 2. What the evidence says

Five inputs, all from 2026-11-23. The study and the research note are private, and the session scratch copies may be cleared.

| Source | Finding that drives this plan |
|---|---|
| A private review-recall study (Qwen 27B and Opus as reviewers) and its proposal | Recall is good (20–23/26) but precision is poor (37–41%). ISSUE and CONCERN were never defined. About half to two thirds of the noise objected to behaviour the spec prescribed. The reviewer had no way to read the spec or the repo's rules. Cross-module contracts: 0/2. |
| Unled whole-project design review (session notes, not published) | Scrutineer is two products sharing a name. Its output is prose, so no triage stage can consume it. Validation is self-grading. The MCP auditor already has the target shape: structured findings, then a separate validator that can only suppress. |
| Context audit (session notes, not published) | The original effective reviews were one product repo's hand-written review commands. They had the repo's `CLAUDE.md` and gate inventory, repo-specific rules in the prompt, a standing "read the callers" step, and a sub-agent that validated each finding. Generic Scrutineer lost all four. The service map was only ever a routing layer: the generators read four fields from it. |
| Coverage audit across the maintainer's repos (session notes, not published) | The detection faults were structural: a working-tree index, root-anchored globs, no manifest parsing, a fixed depth-2 path key, no role classification, and two drifting YAMLs. Missing blocks: Cloudflare Workers (5 repos), Shell (15), AWS serverless (5), Next.js server (4), LLM/MCP apps (6), Unity (2). |
| A research note on the ~90% target (private; to be filed in the research registry) | Twelve languages reach 90% of agent-written PRs: TS, Python, JS+HTML, Rust, C#, Go, PHP, Java, C++, Shell, Kotlin. Adding C, Dart and Swift reaches ~93%. Claude Code PRs skew toward TS, Rust, Go, Shell and Swift. **The biggest gap is the verification ladders:** only Swift and Python have one. |

## 3. Target structure: three tools on one shared core

```
                     ┌───────────────────────── shared core (one package) ─────────────────────────┐
                     │ repo index (git) · detection spec · findings contract (JSON) · validator    │
                     │ · CLI (`vld8 …`)   · eval harness                                       │
                     └──────────────────────────────────────────────────────────────────────────────┘
   1. service map ──── context layer: crawl, slice, invariants, refresh
   2. review ───────── one engine, two lenses (code, security), each runnable alone or together
   3. mcp review ───── separate target (third-party servers), user-scoped install
```

- **Service map.** This tool becomes the source of the review's system context, which it has never really been. It keeps its own lifecycle: crawl once, then refresh on merges that change architecture.
- **Review.** One engine runs detection, the context packet, check selection, the findings contract and validation. On top of it sit two lenses with their own prompts, check sets and severity bars. `/vld8-security` stays addressable on its own, because `ENGINEERING.md` makes a security review a merge gate for product repos (it accepts `/security-review` or this lens). **(Decision D1.)**
- **MCP review.** Stays in the package for now and adopts the shared findings contract. Its scope is user-level (client configs), so it installs at user scope rather than into every repo. **(Decision D5.)**
- **Triage and validation is a shared stage, not a fourth tool.**
- **Suggested fixes stay a `recommendation` field.** First-party tools already apply fixes (`/code-review --fix`, the claude-security plugin), so building a fix stage is last, if ever.

## 4. The review engine, stage by stage

| Stage | What it does | Status in 2.0.0 | Work |
|---|---|---|---|
| **0. Index and detect** | Git index → languages (complete extension table) → frameworks and runtimes (parsed manifests) → package-rooted components → role per path (source / test / fixture / docs / scratch / generated) | Git index done; extension globs only | Two-layer detection; package roots (nearest manifest, or service-map component); roles; incidental platforms labelled, with no ladder; an "Uncovered in this diff" block and a `--strict` mode |
| **1. Context packet** | Built by a deterministic `vld8 context` step at review start, placed before any checklist, with a size budget | Only the PR body (Mode 2) | **A. Rules:** `CLAUDE.md`/`AGENTS.md`/`ENGINEERING.md`/`CONTRIBUTING.md` and nested rules files on changed paths, quoted. **B. Intent, optional:** `--spec`, PR body, linked issue, a design doc in the diff, commits. The review states which source it used, and works without any of them. **C. Terrain:** the map's slice for the touched components, meaning their auth, endpoints and secrets plus the business rules as implemented and the confirmed rules (see *Terrain* below). **D. Contract fan-out:** callers of changed exports, routes and payloads, computed by a script. **E. Repo history:** local checks and suppressions curated from past reviews. |
| **2. Scan** | Lens prompt plus only the checks whose platforms the diff touches, plus Phase 0 (what the toolchain proves) | Checks frozen at install; ~47% of the prompt inert on a typical diff; ladders for Swift and Python only | `vld8 checks --changed <paths>` selects checks at review time from the installed YAML; ladders for every Tier 1 platform (§5) |
| **3. Findings contract** | Every finding written as JSON: `file`, `lineStart`/`lineEnd`, `lens`, `checkId`, `category`, `claim`, `evidence`, `severity`, `basis`, `suppressed`/`reason`, and a stable `fingerprint` (see *Storing findings and decisions*) | Prose only | Define once; peer, security and MCP all emit it; the Markdown report is rendered from it |
| **4. Validate** | A fresh context tries to refute each finding: it reads callers, applies the Phase 0 exclusions, reproduces where it can. It may only suppress or downgrade, and records why | Security self-grades at confidence ≥ 0.8; peer has nothing | Port the shape of `mcp-review/validate_findings.py`. Severity follows an **evidence rubric**. The question is whether something *needed* to be there, never what the author intended, and need has to be shown. ISSUE if and only if it: (a) breaks a written rule, a confirmed map rule or a stated requirement; (b) departs from a contract that two named sites follow; (c) has a traced, reachable trigger; or (d) breaks a security invariant, whatever the current exploitability. Without that evidence it isn't a gap. At most it's a CONCERN, and a CONCERN must name a concrete scenario in this change. (Adopted 2026-11-23, Cyrus.) |
| **5. Report** | Verdict from ISSUEs only; CONCERNs listed; changes to the business rules as implemented listed as questions when no confirmed rule covers them; Check Performance written to the findings JSON | Verdict vocabulary differs per tool | One vocabulary; Check Performance aggregated across runs, to prune checks that never yield and to promote "Unnamed" findings to checks |

**Why this order.** The findings contract (3) unblocks validation (4), measurement, and the feedback loop. The context packet (1) restores what made the original reviews work. Coverage (0, 2) is wide, so it runs on top of a measurable engine.

### Terrain: the service map knows the business rules

Adopted 2026-11-23 (Cyrus). This is where intent comes from, rather than a spec per change. A spec only says what one change was meant to do. The map holds what's true of the whole system, every review reuses it, and it's the "context from the system" that made the original reviews work.

- **What the map records,** each item with file and line evidence and a confidence:
  - business rules and authorization, as implemented: who can do what to which resource;
  - tenancy;
  - trust translation points, for example a border gateway that turns external JWT auth into internal tokens;
  - identifier properties, for example random GUIDs with no exposed oracle;
  - data classifications.

  Accepted risks are deliberately not in the map. They're triage decisions, kept where the storage design keeps them, so a public repo doesn't publish them.
- **What the crawl is authoritative on:** how the rules are *implemented*, not whether they're *intended*. A map read from code would otherwise turn the bug into the spec.
- **`vld8 map rules`** reports the rules as implemented and asks about each one: intended? yes / no, bug / not sure.
  - **yes:** the rule becomes confirmed terrain in the checked-in map. A change that breaks it is an ISSUE that cites the rule.
  - **no, bug:** it becomes a finding right away, with its evidence, and the person records the rule they actually want. The finding is stored like any other, never in the map: in a public repo, "admins can read every tenant's invoices" is a disclosure.
  - **not sure:** the rule stays unconfirmed, and reviews treat it only as a hint.
- **In reviews:**
  - each review reads the terrain slice for the components its diff touches;
  - it compares the rules as implemented before and after the change, for example "this change alters who can delete projects: before, owners only; after, any member";
  - against a confirmed rule, that's an ISSUE. Against an unconfirmed one, it's a question.
- **Known terrain also cuts noise.** No "guessable ID" findings when IDs are random and there's no oracle, unless the change adds one. No demands for JWT validation behind the gateway, unless a new path bypasses it.
- **In a public repo, the confirmed rules are reconnaissance material:** an authorization matrix plus the trust translation points. So a public repo can keep confirmed rules in the encrypted store (*Storing findings and decisions*) instead of in the clear.
- **It stands on its own as a feature.** The confirmed rules are an authorization matrix with file and line for every rule, which is what an access review or a SOC 2 audit asks for.

### Storing findings and decisions

Adopted 2026-11-23 (Cyrus). Checking findings into a repo is risky: in a public repo it publishes the vulnerabilities. So the plan splits two kinds of data, and needs no new secret store for the default case.

- **What was found** is sensitive, but re-running the review produces it again.
  - It's written to `.vld8/findings.json`, which is local and gitignored.
  - It's the output of each run, and the Markdown report is rendered from it.
- **What you decided** is the only part that must persist and be shared: still on fire, false positive or ignore (see `vld8 onfire`), plus suppressions.
  - It lives in `.vld8/triage.json`, which is checked in.
  - Each entry is a fingerprint and a decision, never the finding's details. The fingerprint is a hash of the check ID, the normalized code region and, where relevant, the package and version.
  - A fingerprint means nothing without the code, and an entry expires when its fingerprint stops matching. The MCP reviewer's digest-bound suppressions already work this way and can move into the same file later.
- **The leak that remains in public repos.** Anyone can run vld8 on your public code, compute the same fingerprints, and read which findings you marked `ignore`, that is, real but accepted. For public repos, `ignore` entries, and any free-text reasons, go in one of the two optional stores below rather than in the clear.

Two optional stores, for teams that want a shared, private record:
1. **GitHub code scanning, via SARIF upload.**
   - vld8 renders `findings.json` as SARIF and uploads it. Only people with security access to the repo can see the result.
   - Code scanning's own states map almost one-to-one onto vld8's: open is still on fire, "dismissed: false positive" is false positive, "dismissed: won't fix" is ignore, and closed when a later scan doesn't find it is fixed.
   - It's free for public repos; private repos need GitHub's paid Code Security product.
2. **SOPS with age, checked in.**
   - `.vld8/findings.sops.json` is encrypted to the age public keys listed in `.sops.yaml`, for teams that want the full findings history in git. SOPS can leave the JSON structure readable, so diffs still show what changed.
   - The cost is key management: every collaborator and the CI job needs a key, and removing someone's access means re-encrypting the file and rotating keys.

Default: `findings.json` local, `triage.json` checked in, with SARIF export and SOPS both opt-in. Lands with the findings contract in P1. `onfire`'s triage states use the same `triage.json`.

## 5. Coverage target: the 90% set

**Coverage means four things.** Not just a checklist per platform:

1. detection that never silently misses a file;
2. a toolchain ladder, meaning what the build, type checker and linter prove (§4, stage 2);
3. a few deep checks that the model wouldn't produce unprompted, measured over time;
4. a loud fallback for everything else.

**Tier 1: detection, ladder and deep checks.** This tier covers most of the agent-PR 90% set plus the portfolio. PHP and C++ are in the 90% set but rare in the portfolio, so they sit in Tier 2.

| Layer | Entries |
|---|---|
| Languages | TypeScript/JavaScript (incl. HTML/CSS in templates), Python, Go, Rust, Java, Kotlin (separate from Android), C#/.NET, Swift, Shell |
| Runtimes and frameworks | Node (Express, Nest, Hono), Next.js server code, Cloudflare Workers, AWS Lambda/SAM, Bun/Deno; FastAPI, Django, Flask; Spring; ASP.NET Core |
| Clients | React/Next, Apple platforms (already deep), Android |
| Infra and CI | Docker/Compose, Terraform/OpenTofu, CloudFormation/SAM/CDK, Kubernetes/Helm, GitHub Actions |
| Data | SQL and migrations (Postgres incl. RLS, SQLite/D1, MySQL), ORMs per stack |
| Cross-cutting | LLM API and MCP code: tool use, prompt injection that reaches tools or data, secret handling |

**Tier 2: detection and ladder, generic checks.** PHP/Laravel, Ruby/Rails, C/C++, Dart/Flutter, React Native, Vue/Nuxt, Angular, Svelte, GitLab CI, Jenkins, Azure Pipelines, Ansible, Bicep, OpenAPI/GraphQL/gRPC, MongoDB/Redis/DynamoDB, Unity.

**Outside both tiers:** the "Uncovered in this diff" block names the files and says that review there runs without a platform checklist.

**How coverage is proven, not asserted:**
- **Detection snapshot tests** over a corpus. It starts from the coverage audit's harness, adds the portfolio's real layouts, and adds a public repo per Tier 1 entry. Each test asserts platform → package root → role.
- **A regression gate:** a tracked code file in the corpus that no platform claims fails CI unless it is listed as accepted.
- **The research note is refreshed** when SO 2027 and Octoverse 2027 publish. Tiers move with the data.

## 6. Evaluation: how a change earns a release

- **Code-review eval set:** seeded defects with expected findings, across Tier 1 stacks, kept out of anything used to tune prompts. Sets built from real PRs in private repos live in private storage; synthetic sets can be committed, as `mcp-review/tests/corpus` is.
- **For the engine changes (stages 1, 3, 4):**
  - adopt the study proposal's held-out design, Opus first with 2 reps. The **primary set is real PRs with no spec**, and the spec setting is secondary;
  - **the baseline is 2.0.0**, not 1.6.4. Otherwise the TypeScript detection fix, which has already shipped, is counted as part of the gain;
  - **score on evidence of need:** a finding is real if it shows a broken rule, a broken contract or a triggerable failure, even when it contradicts a spec;
  - ship rule: precision at least the calibrated threshold, and recall at least the baseline's − 2 seeded defects on the same set. The roadmap's 2.1 gate has the details.
- **For coverage changes:** the detection snapshots, plus one live review per new Tier 1 block on a real repo, recorded in Check Performance.
- **Every PR:** CI runs the generator, CLI and MCP suites plus the wheel smoke test (in place since 2.0.0). Add diff-cover at 80% per `ENGINEERING.md`.

## 7. Phases

Phases ship through the weekly release train (`docs/ROADMAP.md`). Work that changes review output ships behind a preview flag, and the minor version goes up when a milestone's flag becomes the default. Nothing is removed until its replacement is the default.

| Phase | Contents | Depends on |
|---|---|---|
| **P0** | **Shipped in 2.0.0** (PR #41, with the fixes from #39): rendering, TS detection, git index, install paths, tests, CI, and the rename | — |
| **P1: Foundations** | One shared analyzer module (no more copy-paste); one detection spec shared by both lenses; findings contract v1, emitted alongside today's Markdown, with local `findings.json` and checked-in `triage.json` (§4, *Storing findings and decisions*); `vld8 checks --changed` | P0 |
| **P2: Precision and context** | First, with no engine dependency (roadmap 2.1): the evidence rubric, rules files, the verdict rule, the lens-table rule, the ambient-nondeterminism check, the callers check, and optional intent sources. Then `vld8 context` with a size budget | P0 for 2.1; P1 for `vld8 context` |
| **P3: Validation** | Separate validator over the findings JSON (fresh context, refute, suppress-only, recorded reasons); retire the security skill's pasted-in hard-exclusion list and its contradictions (rate limits, CVEs, ReDoS) | P1 |
| **P4: Coverage** | Two-layer detection, package roots, roles, uncovered report; Tier 1 ladders; new blocks: Workers, Shell, AWS serverless, Next.js server, LLM/MCP apps, Kotlin JVM (split from Android), Unity, HTML templates; then Tier 2 | P1 (spec), P2 (context feeds checks), P5 (checks cite terrain as evidence) |
| **P5: Terrain (service map v2)** | Business rules as implemented, with evidence; the `vld8 map rules` confirmation report; rule-change detection in reviews; `crawled_commit` and drift detection; an intra-component contracts layer; a CI refresh that opens a PR. See *Terrain* below. It now comes before coverage (roadmap 2.4) | P1, P2 |
| **P6: MCP as its own tool** | User-scoped install; `vld8 mcp` as the front door; shared findings contract | P1 |
| **P7: Measure and prune** | Each gated milestone runs its own held-out eval (roadmap). P7 itself: aggregate Check Performance; prune checks that never yield (starting with the March-era generic blocks); promote "Unnamed" findings to checks | P2, P3 |

**Order (roadmap):**
1. P2's spec-free precision work (2.1);
2. P1 (2.2);
3. P3 (2.3);
4. P2's context packet together with P5 terrain (2.4);
5. P4 coverage;
6. P6 and P7.

P4's detection work can start alongside P1, but its checks wait for terrain.

### Future features

These come after the phases above. They aren't scheduled yet.

**Automated improvement pipeline** (Cyrus, 2026-11-23). Pull recent GitHub security advisories that link to their fix. Run vld8 against the code as it was before the fix, and check whether it would have caught the problem. When it wouldn't have, work out why and prepare a fix.

- **Source:**
  - reviewed advisories in the GitHub Advisory Database that link a fix commit or PR;
  - only in ecosystems the 90% set covers (§5): npm, PyPI, Go, crates.io, NuGet, Maven, Composer;
  - each one checked out at the fix commit's parent.
- **Run:** the security lens, plus the code lens for logic bugs, over the files the fix touched, at that parent commit.
- **Score:** a catch is a finding on the lines or function the fix changed, in the advisory's CWE class. This needs the findings contract (P1) and the validator (P3), so scoring reads JSON rather than prose.
- **Triage a miss into one cause:**
  - detection: the platform was never detected;
  - coverage: no check exists for that class;
  - context: the check exists but the reviewer lacked what it needed;
  - validation: a correct finding was suppressed;
  - judgment: the finding was raised but at the wrong severity.
- **Prepared fix:**
  - a guidance-YAML or prompt change, opened as a draft PR;
  - the advisory added to the eval set (§6) as a new case;
  - never merged automatically. The PR goes through the normal review and §6 gates.
- **Guardrails:**
  - **Hold out by date.** A change made in response to one batch of advisories is judged only on advisories published after that batch. Otherwise the pipeline grades its own homework, the problem the held-out study (§6) exists to prevent.
  - **Never run the target's code.** Phase 0 ("verify before judging") runs the repo's own gate script, and in this pipeline that would mean executing arbitrary public code. Turn Phase 0 off, or run it only in a throwaway sandbox with no credentials and no network.
  - **Bounded runs.** Run on a schedule with a cap on advisories per run and a stop condition.
- **Why it's worth building:**
  - it tracks recall on real, current vulnerabilities rather than planted ones;
  - it turns each miss into a check or a context fix, with the advisory as the test that proves it.
- **Depends on:**
  - P1, so findings are machine-readable;
  - P3, for consistent scoring;
  - P7's measurement plumbing.

  It is most useful after P4, once coverage is broad enough that a miss points at a real gap rather than a known one.

**`vld8 onfire day|week`** (Cyrus, 2026-11-23). Pull every entry added to CISA's Known Exploited Vulnerabilities (KEV) catalog in the last day or week, and scan your repo to see whether you're exposed. KEV lists vulnerabilities being exploited in the wild right now, so it's the short list to act on first.

- **Fetch:**
  - CISA's public KEV JSON feed, filtered on `dateAdded` to the window;
  - the windows overlap on purpose: `day` means the last 48 hours, and `week` means the last 8 days. `dateAdded` is a date with no time or timezone, and the feed can publish late, so an exact 24-hour or 7-day cutoff would drop entries that land near the boundary. (Cyrus, 2026-11-23)
  - the overlap means back-to-back runs can see an entry twice. That's intended. If the repo is still exposed, it's still on fire, so every run reports it again (Cyrus, 2026-11-23);
  - each entry carries the CVE, vendor and product, the required action, a due date, and whether ransomware campaigns use it.
- **Map each CVE to code with OSV** (osv.dev): the affected ecosystems, packages and version ranges.
  - Query OSV by the CVE ID only, and do the matching locally. The repo's dependency list never leaves the machine.
- **Match deterministically, in a script, not by the model.** This is the MCP reviewer's pattern: evidence in Python, judgment in the skill. Compare against:
  - resolved versions in the repo's lockfiles (package-lock, pnpm and yarn locks, poetry/uv locks, go.sum, Cargo.lock, NuGet and Maven files, composer.lock);
  - container base images;
  - products named in IaC and in the service map's infrastructure and datastores.
- **Verdict per entry:** affected version present, not present, or can't tell. "Can't tell" covers, for example, no lockfile, or a CVE OSV hasn't mapped. Many KEV entries are appliances, operating systems or browsers with no package mapping. Those are listed as not applicable to this repo's code. If the service map shows you run that product, they go in a "check your infrastructure" section instead.
- **Reachability pass for hits:** the security lens, scoped to the vulnerable package. Is the affected function, config or feature actually used? This separates "patch today" from "patch, but it isn't reachable".
- **Output:**
  - findings in the findings contract (P1), each carrying KEV's required action, due date and ransomware flag;
  - a coverage statement naming which lockfiles and ecosystems were read, so silence never reads as "not vulnerable".
- **Triage states** (Cyrus, 2026-11-23). The user sets a state on each tracked hit:
  - **still on fire:** the default. It's reported on every run.
  - **false positive:** vld8 was wrong.
  - **ignore:** the hit is real but accepted, recorded with who, why and until when.

  States live in the checked-in `.vld8/triage.json` (see *Storing findings and decisions*), as fingerprints, never details. Each one is bound to a digest of its evidence, the way the MCP reviewer binds its suppressions. A mark therefore expires when the dependency version, the reachability evidence or the KEV entry changes. Ignored and false-positive hits stay visible as a count in every report, so they never silently disappear.
- **False-positive submissions,** opt-in. When marking a false positive, the user can send a code excerpt they've approved and a sentence on why it's safe, so vld8 can fix the check.
  - **What's sent:** the user sees exactly what will be sent, after secret redaction (reusing the analyzer's), and nothing goes without an explicit confirmation. The payload is the CVE, package, version, excerpt and explanation. The repo name and path are included only if the user adds them.
  - **Transport:** the payload is encrypted on the user's machine to the project's public key (for example with age) and sent over HTTPS. Only the maintainer can read it, whatever carries it. It never goes in the clear in a public GitHub issue.
  - **Retention:** a retention and deletion policy is published before the endpoint goes live.
  - **Treat submissions as untrusted input.** Someone can submit a crafted "false positive" to teach vld8 that a real vulnerable pattern is safe, or hide instructions for whatever model reads it. So a submission never changes a check or suppresses a finding for anyone else. It becomes a candidate eval case that a person reviews, and the improvement pipeline treats its text as data, never as instructions.
  - **Needs a backend.** See D8.
- **Running it:** a CLI subcommand, plus a `/vld8-onfire` skill for the reachability pass. It could also run as a daily CI job:
  - one issue per CVE, updated on every run while the repo is still exposed, never skipped and never duplicated;
  - closed automatically when a run finds the fix in place;
  - open issues are re-checked on every run, even after their KEV entry ages out of the window, so an old fire doesn't go quiet just because it's no longer new.
- **Be honest about what's new here.** Dependabot and OSV-Scanner already flag dependency CVEs. vld8's additions are:
  - KEV prioritization: exploited now, with due dates;
  - the reachability verdict;
  - coverage beyond lockfiles, into base images, IaC and the service map's infrastructure.
- **Depends on:**
  - P1, for the findings contract;
  - P4's package roots and manifest parsing, for lockfile discovery in monorepos;
  - P5, if the service map's infrastructure inventory is going to drive the infrastructure section.

## 8. Alternatives considered

1. **Keep generate-time skills and keep patching.** Rejected. Every review pays for every detected platform. Guidance improvements need a reinstall in every repo. The output can't feed validation. And the coverage audit showed the detection faults are structural, not a list of misses.
2. **Merge code and security review into one prompt.** Rejected. It doubles the context the study already measured as half unused, mixes two severity bars, and removes the separately addressable security gate.
3. **Become only an expertise pack that first-party engines consume** (`/code-review`, the claude-security plugin), with no engine of our own. Open; see **D2**. The expertise layer (measured checks, ladders, exclusions, repo context) is what Scrutineer has that they don't. But a thin engine of our own is still needed to measure that layer.
4. **Split the MCP auditor into its own package now.** Deferred to P6. Shared CLI, release pipeline and findings contract are cheaper inside one package until the contract is stable.
5. **Build the suggested-fix stage from the original pipeline.** Deprioritized. It is a commodity next to validation.

## 9. Back-out

- **Output changes are opt-in until their gate passes.** Not passing the preview flag keeps the old behaviour. After a default flips, rolling back means pinning the previous version (`pip install vld8==X`); PyPI keeps every version.
- **The generated skills stay the default** until the review-time path passes §6. The preview flag replaces the old idea of a `--legacy` flag.
- **The findings JSON is additive.** It's written next to the Markdown. Rendering the Markdown from it is an output change, so it ships behind the 2.2 flag.
- **Service map v2 fields are optional additions** to schema 1.1. Old maps keep validating.

## 10. Decisions needed

| # | Decision | Recommendation |
|---|---|---|
| D1 | Review tool: one engine with two separately runnable lenses, or one merged review | One engine, two lenses (§3, §8.2) |
| D2 | Positioning: our own engine, or an expertise pack for first-party engines | Both, in that order: a thin engine of our own, so the expertise layer can be measured; publish the layer in a form other engines can consume once the findings contract is stable |
| D3 | ~~Positioning of the collection~~ **Decided 2026-11-23: pitch it as dev tooling** (Cyrus). Security is one lens of the review tool, not the product's label | — |
| D7 | ~~Rename~~ **Decided 2026-11-23: rename to `vld8`** (Cyrus), read as "validate". One PyPI package, `vld8`, with the three tools as subcommands (`vld8 map`, `vld8 review`, `vld8 mcp`) and skills (`/vld8-map`, `/vld8-review`, `/vld8-mcp`); how the security lens is addressed follows D1. **Shipped early, in 2.0.0 (PR #41)**, once Cyrus had renamed the repo and registered the PyPI name, rather than waiting for P1. Keep "Cyrus's toolbox" as the tagline | Availability on 2026-11-23: `vld8` and the `-map`/`-review`/`-mcp` names are free on PyPI and npm. The GitHub account `vld8` is taken, so the repo becomes `cyrus-is/vld8`. Before P1, Cyrus registers a PyPI pending trusted publisher for `vld8` (web UI) so the name is held for this repo's release workflow. Mechanics: new PyPI package; a last `scrutineer` release that depends on it and prints a notice; GitHub repo rename (URLs redirect); the installer replaces old `/scrutineer-*` command files |
| D4 | Held-out test before a milestone's default changes | Yes. Items ship earlier behind a preview flag, so testing first doesn't hold up building |
| D5 | MCP review stays in the package until P6 | Yes |
| D6 | Where the ~90% research note lives. Today it's only in session scratch | File it in the private research registry |
| D8 | Where the vld8.ai site lives: in this repo, on cyrus.is, or on its own | Split by what each part is. **Now:** point vld8.ai at cyrus.is/building/vld8, so the announcement post is the landing page and nothing new needs hosting. **Product docs, when they're needed:** a static site in this repo (`site/`), built from the READMEs so docs ship with the code they describe. Deploy it through the host's Git integration (Cloudflare Pages or GitHub Pages), so no deploy secret sits in a repo whose CI publishes to PyPI. On cyrus.is, every release would need a pull request to the personal site, and the docs would drift. **The false-positive submission endpoint:** its own small service and repo. It holds other people's code and needs credentials, so it shouldn't share CI, permissions or blast radius with the package. **cyrus.is keeps the story posts,** and vld8.ai links to them |

## 11. Risks

- **Context packet size.** The packet competes with the lens prompt for attention: the study showed a reviewer reading only the head of a 169K map. Mitigation: a hard size budget, with slices rather than whole files.
- **Validator recall cost.** The field's validators raise precision and cut recall (Lu et al.: key-bug inclusion 31% → 20%), and every suppression is that cost. Mitigation: each suppression is recorded with its reason and audited on the eval, and the validator stays behind its flag until the 2.3 eval shows recall holds.
- **Intent capture leaking private context.** Approved plans and session prompts can name private projects, and a PR description is public in a public repo. Mitigation: the hook is opt-in, shows the text before writing it, redacts secrets, and is off by default for public repos.
- **A crawled map turning the bug into the spec.** A rule read from code describes what the code does, not what was meant. Mitigation: a rule is authoritative only once a person confirms it in `vld8 map rules`. Unconfirmed rules are hints, and changes to them are questions, never ISSUEs.
- **Coverage breadth crowding out depth.** The September data showed generic blocks yield little. Mitigation: Tier 1 entries earn deep checks only from measured findings; Tier 2 stays at detection plus ladder.
- **Original-system bias.** The original reviews were tuned to one multi-service Go system that no longer exists. Mitigation: evaluate on the current portfolio's shapes: single Workers, Apple apps, monorepos.
