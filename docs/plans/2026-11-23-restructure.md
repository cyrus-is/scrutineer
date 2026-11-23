# Plan: restructure Scrutineer into three tools that review the way the original did

**Status:** draft for Cyrus's approval (2026-11-23). Approving it is the design review, per `ENGINEERING.md` § Design review & plans. The open questions are listed under **Decisions needed**; each one carries a recommendation.

**Starting point:** vld8 2.0.0, PR #41. It ships the 1.7.0 fixes from #39 (rendering, TypeScript detection, git index, install paths) under the new name. This plan covers what comes after it.

**Naming:** the rename to vld8 shipped in 2.0.0, ahead of P1 (D7). Commands below that still say `scrutineer` mean the `vld8` equivalent: `scrutineer servicemap` is now `vld8 map`, and `/scrutineer-code` is now `/vld8-review`.

## 1. Goal

In Cyrus's words: *"Targeted reviews with deep language and platform expertise to find issues in code."* The original design was a pipeline: scan → triage and validation → rated finding with lines and context → suggested fix. The second and third stages were never built; the MCP reviewer was built instead.

Effective means three things:

1. **Context.** The reviewer knows the system it is reviewing: its rules, trust boundaries, contracts, and the intent of the change.
2. **Validation.** A finding reaches the reader only after something other than its author has tried to refute it.
3. **Coverage.** The reviewer covers the platforms that make up ~90% of shipped code, and says so loudly when a file falls outside them.

## 2. What the evidence says

Five inputs, all from 2026-11-23. Session scratch paths may be cleared; the HQ files are durable.

| Source | Finding that drives this plan |
|---|---|
| HQ qwen-review-recall study (`hq/ideas/wedding-saas/studies/qwen-review-recall/scrutineer-performance.md`) and its proposal (`hq/projects/scrutineer/review-skill-improvements-2026-11-23.md`) | Recall is good (20–23/26) but precision is poor (37–41%). ISSUE and CONCERN were never defined. About half to two thirds of the noise objected to behaviour the spec prescribed. The reviewer had no way to read the spec or the repo's rules. Cross-module contracts: 0/2. |
| Unled whole-project design review (`cohesion-review/REPORT.md`, scratch) | Scrutineer is two products sharing a name. Its output is prose, so no triage stage can consume it. Validation is self-grading. The MCP auditor already has the target shape: structured findings, then a separate validator that can only suppress. |
| Context audit (`context-audit/REPORT.md`, scratch) | The original effective reviews were pocket-extrovert's hand-written commands. They had the repo's `CLAUDE.md` and gate inventory, repo-specific rules in the prompt, a standing "read the callers" step, and a sub-agent that validated each finding. Generic Scrutineer lost all four. The service map was only ever a routing layer: the generators read four fields from it. |
| Portfolio coverage audit (`coverage-audit/`, scratch: harness and per-repo results) | The detection faults were structural: a working-tree index, root-anchored globs, no manifest parsing, a fixed depth-2 path key, no role classification, and two drifting YAMLs. Missing blocks: Cloudflare Workers (5 repos), Shell (15), AWS serverless (5), Next.js server (4), LLM/MCP apps (6), Unity (2). |
| Research desk, ~90% target (`research-90pct/ANSWER.md`, scratch; to be filed in HQ) | Twelve languages reach 90% of agent-written PRs: TS, Python, JS+HTML, Rust, C#, Go, PHP, Java, C++, Shell, Kotlin. Adding C, Dart and Swift reaches ~93%. Claude Code PRs skew toward TS, Rust, Go, Shell and Swift. **The biggest gap is the verification ladders:** only Swift and Python have one. |

## 3. Target structure: three tools on one shared core

```
                     ┌───────────────────────── shared core (one package) ─────────────────────────┐
                     │ repo index (git) · detection spec · findings contract (JSON) · validator    │
                     │ · CLI (`scrutineer …`) · eval harness                                       │
                     └──────────────────────────────────────────────────────────────────────────────┘
   1. service map ──── context layer: crawl, slice, invariants, refresh
   2. review ───────── one engine, two lenses (code, security), each runnable alone or together
   3. mcp review ───── separate target (third-party servers), user-scoped install
```

- **Service map.** This tool becomes the source of the review's system context, which it has never really been. It keeps its own lifecycle: crawl once, then refresh on merges that change architecture.
- **Review.** One engine runs detection, the context packet, check selection, the findings contract and validation. On top of it sit two lenses with their own prompts, check sets and severity bars. `/scrutineer-security` stays addressable on its own, because `ENGINEERING.md` makes a security review a merge gate. **(Decision D1.)**
- **MCP review.** Stays in the package for now and adopts the shared findings contract. Its scope is user-level (client configs), so it installs at user scope rather than into every repo. **(Decision D5.)**
- **Triage and validation is a shared stage, not a fourth tool.**
- **Suggested fixes stay a `recommendation` field.** First-party tools already apply fixes (`/code-review --fix`, the claude-security plugin), so building a fix stage is last, if ever.

## 4. The review engine, stage by stage

| Stage | What it does | Status in 1.7.0 | Work |
|---|---|---|---|
| **0. Index and detect** | Git index → languages (complete extension table) → frameworks and runtimes (parsed manifests) → package-rooted components → role per path (source / test / fixture / docs / scratch / generated) | Git index done; extension globs only | Two-layer detection; package roots (nearest manifest, or service-map component); roles; incidental platforms labelled, with no ladder; an "Uncovered in this diff" block and a `--strict` mode |
| **1. Context packet** | Built by a deterministic `scrutineer context` step at review start, placed before any checklist, with a size budget | Only the PR body (Mode 2) | **A. Rules:** `CLAUDE.md`/`AGENTS.md`/`ENGINEERING.md`/`CONTRIBUTING.md` and nested rules files on changed paths, quoted. **B. Intent:** `--spec`, PR body, linked issue, commits. **C. Map slice:** touched components and their neighbours, with auth, endpoints and secrets. **D. Contract fan-out:** callers of changed exports, routes and payloads, computed by a script. **E. Repo history:** local checks and suppressions curated from past reviews. |
| **2. Scan** | Lens prompt plus only the checks whose platforms the diff touches, plus Phase 0 (what the toolchain proves) | Checks frozen at install; ~47% of the prompt inert on a typical diff; ladders for Swift and Python only | `scrutineer checks --changed <paths>` selects checks at review time from the installed YAML; ladders for every Tier 1 platform (§5) |
| **3. Findings contract** | Every finding written as JSON: `file`, `lineStart`/`lineEnd`, `lens`, `checkId`, `category`, `claim`, `evidence`, `severity`, `basis`, `suppressed`/`reason` | Prose only | Define once; peer, security and MCP all emit it; the Markdown report is rendered from it |
| **4. Validate** | A fresh context tries to refute each finding: it reads callers, applies the Phase 0 exclusions, reproduces where it can. It may only suppress or downgrade, and records why | Security self-grades at confidence ≥ 0.8; peer has nothing | Port the shape of `mcp-review/validate_findings.py`. Severity follows an **evidence rubric**: ISSUE if and only if (a) it breaks a stated requirement, (b) it breaks a written rule or stated invariant, (c) it departs from a contract that two named sites follow, (d) it has a traced, reachable trigger, or (e) it breaks a security invariant, whatever the current exploitability. CONCERN needs a concrete scenario. Objections to prescribed design go to **Spec questions**, which never set the verdict. |
| **5. Report** | Verdict from ISSUEs only; CONCERNs and Spec questions listed; Check Performance written to the findings JSON | Verdict vocabulary differs per tool | One vocabulary; Check Performance aggregated across runs, to prune checks that never yield and to promote "Unnamed" findings to checks |

**Why this order.** The findings contract (3) unblocks validation (4), measurement, and the feedback loop. The context packet (1) restores what made the original reviews work. Coverage (0, 2) is wide, so it runs on top of a measurable engine.

## 5. Coverage target: the 90% set

**Coverage means four things.** Not just a checklist per platform:

1. detection that never silently misses a file;
2. a toolchain ladder, meaning what the build, type checker and linter prove (§4, stage 2);
3. a few deep checks that the model wouldn't produce unprompted, measured over time;
4. a loud fallback for everything else.

**Tier 1: detection, ladder and deep checks.** This tier covers the agent-PR 90% set plus the portfolio.

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

- **Code-review eval set**, mirroring `mcp-review/tests/corpus`. Seeded defects with expected findings, across Tier 1 stacks, kept out of anything used to tune prompts.
- **For the engine changes (stages 1, 3, 4):**
  - adopt the HQ proposal's held-out design (§5 there): Opus first, 2 reps, a spec setting plus a home setting (PRs with no spec);
  - ship rule: Finding precision at least the baseline + 20 points, recall at least the baseline − 2;
  - reject Spec questions if more than 2 seeded defects land in them.
- **For coverage changes:** the detection snapshots, plus one live review per new Tier 1 block on a real repo, recorded in Check Performance.
- **Every PR:** CI runs the generator, CLI and MCP suites plus the wheel smoke test (in place since 1.7.0). Add diff-cover at 80% per `ENGINEERING.md`.

## 7. Phases

Each phase is a release. Nothing is removed until its replacement has passed §6.

| Phase | Contents | Depends on |
|---|---|---|
| **P0** | 1.7.0: rendering, TS detection, git index, install paths, tests, CI (PR #39) | — |
| **P1: Foundations** | One shared analyzer module (no more copy-paste); one detection spec shared by both lenses; a globstar matcher; findings contract v1, emitted alongside today's Markdown; `scrutineer checks --changed` | P0 |
| **P2: Context** | `scrutineer context`: rules files, intent sources (`--spec`, PR body, linked issue), map slice for touched components, contract fan-out script; the evidence rubric; Spec questions | P1 |
| **P3: Validation** | Separate validator over the findings JSON (fresh context, refute, suppress-only, recorded reasons); retire the security skill's pasted-in hard-exclusion list and its contradictions (rate limits, CVEs, ReDoS) | P1 |
| **P4: Coverage** | Two-layer detection, package roots, roles, uncovered report; Tier 1 ladders; new blocks: Workers, Shell, AWS serverless, Next.js server, LLM/MCP apps, Kotlin JVM (split from Android), Unity, HTML templates; then Tier 2 | P1 (spec), P2 (context feeds checks) |
| **P5: Service map v2** | `crawled_commit` and drift detection; an intra-component contracts layer for single-deployable repos; an invariants file seeded by the crawl and confirmed by a person (trust model, tenancy, gate inventory); a CI refresh that opens a PR | P2 |
| **P6: MCP as its own tool** | User-scoped install; `scrutineer mcp` as the front door; shared findings contract | P1 |
| **P7: Measure and prune** | Held-out study for P2+P3; aggregate Check Performance; prune checks that never yield (starting with the March-era generic blocks); promote "Unnamed" findings to checks | P2, P3 |

P2 and P3 can run in parallel once P1 lands. P4's detection work can start in P1, but its checks should wait for P2's context packet.

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
2. **Merge code and security review into one prompt.** Rejected. It doubles the context HQ already measured as half unused, mixes two severity bars, and removes the separately addressable security gate.
3. **Become only an expertise pack that first-party engines consume** (`/code-review`, the claude-security plugin), with no engine of our own. Open; see **D2**. The expertise layer (measured checks, ladders, exclusions, repo context) is what Scrutineer has that they don't. But a thin engine of our own is still needed to measure that layer.
4. **Split the MCP auditor into its own package now.** Deferred to P6. Shared CLI, release pipeline and findings contract are cheaper inside one package until the contract is stable.
5. **Build the suggested-fix stage from the original pipeline.** Deprioritized. It is a commodity next to validation.

## 9. Back-out

- **Each phase ships as a minor release.** Rolling back means pinning the previous version (`pip install scrutineer==X`). PyPI keeps every version.
- **The generated skills stay** (a `--legacy` install flag) until the review-time path passes §6. Users can stay on them.
- **The findings JSON is additive.** It sits next to the Markdown until P3, so consumers of the Markdown are unaffected.
- **Service map v2 fields are optional additions** to schema 1.1. Old maps keep validating.

## 10. Decisions needed

| # | Decision | Recommendation |
|---|---|---|
| D1 | Review tool: one engine with two separately runnable lenses, or one merged review | One engine, two lenses (§3, §8.2) |
| D2 | Positioning: our own engine, or an expertise pack for first-party engines | Both, in that order: a thin engine of our own, so the expertise layer can be measured; publish the layer in a form other engines can consume once the findings contract is stable |
| D3 | ~~Positioning of the collection~~ **Decided 2026-11-23: pitch it as dev tooling** (Cyrus). Security is one lens of the review tool, not the product's label | — |
| D7 | ~~Rename~~ **Decided 2026-11-23: rename to `vld8`** (Cyrus), read as "validate". One PyPI package, `vld8`, with the three tools as subcommands (`vld8 map`, `vld8 review`, `vld8 mcp`) and skills (`/vld8-map`, `/vld8-review`, `/vld8-mcp`); how the security lens is addressed follows D1. **Shipped early, in 2.0.0 (PR #41)**, once Cyrus had renamed the repo and registered the PyPI name, rather than waiting for P1. Keep "Cyrus's toolbox" as the tagline | Availability on 2026-11-23: `vld8` and the `-map`/`-review`/`-mcp` names are free on PyPI and npm. The GitHub account `vld8` is taken, so the repo becomes `cyrus-is/vld8`. Before P1, Cyrus registers a PyPI pending trusted publisher for `vld8` (web UI) so the name is held for this repo's release workflow. Mechanics: new PyPI package; a last `scrutineer` release that depends on it and prints a notice; GitHub repo rename (URLs redirect); the installer replaces old `/scrutineer-*` command files |
| D4 | Run the held-out study before shipping P2/P3, or ship behind a flag and measure after | Study first for P2/P3 (they change what reaches the reader); P1 and P4 ship on CI and snapshot tests |
| D5 | MCP review stays in the package until P6 | Yes |
| D6 | Where the 90% research note lives. It is in session scratch now; the research desk could not file it in HQ | File it in `hq/research/notes/` with the desk's suggested frontmatter |

## 11. Risks

- **Context packet size.** The packet competes with the lens prompt for attention: the HQ study showed a reviewer reading only the head of a 169K map. Mitigation: a hard size budget, with slices rather than whole files.
- **Validator recall cost.** The field's validators raise precision and cut recall (Lu et al.: key-bug inclusion 31% → 20%). Mitigation: the validator may only suppress, with reasons recorded and audited; it is tuned on held-out data.
- **Spec questions as a sink for real defects.** Mitigation: the precedence rule (code that departs from the spec is always a Finding), "needs a ruling" marking, and the reject rule in §6.
- **Coverage breadth crowding out depth.** The September data showed generic blocks yield little. Mitigation: Tier 1 entries earn deep checks only from measured findings; Tier 2 stays at detection plus ladder.
- **Original-system bias.** The original reviews were tuned to one multi-service Go system that no longer exists. Mitigation: evaluate on the current portfolio's shapes: single Workers, Apple apps, monorepos.
