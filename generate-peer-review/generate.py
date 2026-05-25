#!/usr/bin/env python3
"""
Peer Review Skill Generator

Scans a repository (and optionally consumes a servicemap.json) to generate a
tailored .claude/commands/scrutineer-code.md with platform-specific pre-flight
checks, focus areas, and evaluation lenses.

The generated skill supports four invocation modes:
  /scrutineer-code                  — review current branch diff vs main
  /scrutineer-code 123              — review PR #123 (git pull + checkout)
  /scrutineer-code <component-name> — full review of a service/app from the service map
  /scrutineer-code --deep           — deep repo-wide review across services

Usage:
    python generate.py /path/to/repo
    python generate.py /path/to/repo --service-map servicemap.json
    python generate.py /path/to/repo --dry-run
"""

import argparse
import fnmatch
import json
import os
import re
import sys
import textwrap
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Repo Analyzer (shared logic with security review generator)
# ---------------------------------------------------------------------------

class RepoAnalyzer:
    # Directories to skip during repo scan. Includes language-specific build,
    # cache, and test-coverage output that's gitignored by convention. Without
    # these, locally-generated artifacts (e.g. `coverage/*.js` left over from a
    # past `pnpm test --coverage` run) get picked up as Node source files,
    # producing different platform-detection output on developer machines than
    # on a fresh CI clone.
    SKIP_DIRS = {
        # VCS / editor / IDE
        ".git", ".claude", ".idea", ".vscode",
        # JS / TS
        "node_modules", ".next", "build", "dist", "coverage",
        # Python
        "__pycache__", "venv", ".venv", ".pytest_cache", ".mypy_cache",
        ".ruff_cache", ".tox", ".eggs", "htmlcov",
        # Go / Rust / Java
        "vendor", "target", ".gradle",
        # iOS / macOS
        "Pods", ".build", "DerivedData",
        # Infra
        ".terraform",
    }

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.is_dir():
            raise ValueError(f"Not a directory: {self.repo_path}")
        self._file_index: list[Path] | None = None

    @property
    def file_index(self) -> list[Path]:
        if self._file_index is None:
            # Sort directories and files so traversal order is deterministic
            # across filesystems. Without this, output (and any drift-detection
            # gates downstream) differs between macOS APFS, Linux ext4, etc.
            self._file_index = []
            for root, dirs, files in os.walk(self.repo_path):
                dirs[:] = sorted(d for d in dirs if d not in self.SKIP_DIRS)
                for f in sorted(files):
                    self._file_index.append(Path(root) / f)
        return self._file_index

    def relative_paths(self) -> list[str]:
        return [str(f.relative_to(self.repo_path)) for f in self.file_index]

    def matches_glob(self, pattern: str) -> list[str]:
        return [rel for rel in self.relative_paths() if fnmatch.fnmatch(rel, pattern)]

    def file_contains(self, pattern: str, max_files: int = 50, max_bytes: int = 50_000) -> bool:
        regex = re.compile(pattern, re.MULTILINE)
        count = 0
        for f in self.file_index:
            if f.stat().st_size > max_bytes:
                continue
            count += 1
            if count > max_files:
                break
            try:
                if regex.search(f.read_text(errors="ignore")):
                    return True
            except (OSError, UnicodeDecodeError):
                continue
        return False

    def detect_platforms(self, guidance: dict) -> dict[str, dict]:
        detected = {}
        rel_paths = self.relative_paths()
        for category_name, platforms in guidance.items():
            for platform_key, platform_data in platforms.items():
                file_match = False
                for pattern in platform_data.get("detect_files", []):
                    for rel in rel_paths:
                        if fnmatch.fnmatch(rel, pattern):
                            file_match = True
                            break
                    if file_match:
                        break
                content_match = False
                if not platform_data.get("detect_files"):
                    for cp in platform_data.get("detect_content", []):
                        if self.file_contains(cp):
                            content_match = True
                            break
                if file_match or content_match:
                    detected[platform_key] = {**platform_data, "_category": category_name}
        return detected

    def map_component_paths(self, detected: dict) -> dict[str, list[str]]:
        component_paths = {}
        rel_paths = self.relative_paths()
        for pk, pd in detected.items():
            paths = set()
            for pattern in pd.get("detect_files", []):
                for rel in rel_paths:
                    if fnmatch.fnmatch(rel, pattern):
                        parts = Path(rel).parts
                        if len(parts) >= 2:
                            paths.add(f"{parts[0]}/{parts[1]}")
                        elif len(parts) == 1:
                            paths.add(parts[0])
            component_paths[pk] = sorted(paths)
        return component_paths


# ---------------------------------------------------------------------------
# Service Map Loader
# ---------------------------------------------------------------------------

class ServiceMapLoader:
    def __init__(self, path: str):
        with open(path) as f:
            self.data = json.load(f)
        self.components = {c["id"]: c for c in self.data.get("components", [])}

    def get_reviewable_components(self) -> list[dict]:
        """Components that can be targeted for full review (services + apps)."""
        return [
            c for c in self.data.get("components", [])
            if c["type"] in ("service", "app") and c.get("path") and not c.get("stub")
        ]

    def get_component_by_name(self, name: str) -> dict | None:
        for c in self.data.get("components", []):
            if c["name"] == name or c["id"] == name:
                return c
        return None


# ---------------------------------------------------------------------------
# Skill Generator
# ---------------------------------------------------------------------------

class SkillGenerator:

    def generate(self, detected: dict, component_paths: dict,
                 all_known_platforms: list[str],
                 service_map: ServiceMapLoader | None = None,
                 cross_cutting: dict | None = None) -> str:
        sections = [
            self._header(),
            self._help_section(),
            self._invocation_section(service_map),
            self._process_section(detected, component_paths, service_map),
            self._understand_first_section(),
            self._preflight_section(detected, component_paths),
            self._agentic_analysis_section(),
            self._cross_cutting_section(cross_cutting),
            self._focus_areas_section(detected, component_paths),
            self._lenses_section(),
            self._change_type_modifiers(detected),
            self._output_format(),
            self._deep_review_section(service_map),
            self._self_heal_section(all_known_platforms),
        ]
        return "\n".join(sections)

    def _header(self) -> str:
        return textwrap.dedent("""\
            You are a TL/Principal SDE performing a peer code review. Your goal is NOT style review.
            Your goal is to find real issues that would cause production incidents, reliability problems,
            scaling issues, maintenance burden, or subtle bugs that a Senior Engineer might miss but a
            Principal would catch.

            You are an AGENT, not a linter. A linter matches patterns — you reason about code. The
            checklists below are starting points for investigation, not substitutes for understanding.
            Your highest-value findings will come from tracing data flows, comparing parallel code paths,
            and asking "what's missing?" — things no checklist can do.

        """)

    def _invocation_section(self, service_map: ServiceMapLoader | None) -> str:
        lines = [textwrap.dedent("""\
            ## Invocation Modes

            This skill supports three modes based on the argument:

            ### Mode 1: Current Branch Diff (no arguments)
            ```
            /scrutineer-code
            ```
            Reviews the current branch's changes against main. Runs `git diff main...HEAD`.

            ### Mode 2: PR Review (numeric argument)
            ```
            /scrutineer-code 123
            ```
            Reviews PR #123. Process:
            1. `git fetch origin`
            2. Get PR metadata: `gh pr view 123 --json number,title,headRefName,baseRefName`
            3. Get full diff: `gh pr diff 123`
            4. Review the diff.
            5. Post findings as a PR comment via `gh pr comment`.

            ### Mode 3: Full Service/App Review (component name argument)
            ```
            /scrutineer-code <component-name>
            ```
            Full review of all code in a service or app directory — not just a diff. This is for
            comprehensive reviews of an entire component.

            Process:
            1. Identify the component directory from the service map (see table below).
            2. Read all source files in that directory.
            3. Apply pre-flight checks, focus areas, and all 8 lenses.
            4. Report findings in the same format as PR review, but without the PR metadata.

            ### Mode 4: Deep Repo Review (--deep flag)
            ```
            /scrutineer-code --deep
            ```
            Full repository-level review that traces flows across services, compares patterns
            cross-service, and finds systemic issues that component-level reviews miss. This is
            the most thorough mode — it finds data integrity bugs in multi-step flows, architectural
            inconsistencies, and cross-layer configuration gaps.

            **This mode finds a DIFFERENT CLASS of bugs than Modes 1-3.** Component reviews scan
            files and match patterns. Deep review traces flows end-to-end and asks "what breaks
            when these components interact?"
        """)]

        if service_map:
            reviewable = service_map.get_reviewable_components()
            if reviewable:
                lines.append("\n**Available components for full review:**\n")
                lines.append("| Name | Type | Path | Language |")
                lines.append("|------|------|------|----------|")
                for c in reviewable:
                    lines.append(f"| `{c['name']}` | {c['type']} | `{c.get('path', '')}` | {c.get('language', '')} |")
                lines.append("")

        lines.append(textwrap.dedent("""\
            ### How to detect the mode

            Parse `$ARGUMENTS`:
            - `--help` → show help summary and stop
            - Empty or whitespace → **Mode 1** (current diff)
            - Matches `^\\d+$` → **Mode 2** (PR number)
            - `--deep` → **Mode 4** (deep repo review)
            - Anything else → **Mode 3** (component name lookup)

        """))
        return "\n".join(lines)

    def _process_section(self, detected: dict, component_paths: dict,
                         service_map: ServiceMapLoader | None) -> str:
        detection_rules = []
        for key, data in detected.items():
            paths = component_paths.get(key, [])
            if paths:
                path_str = "`, `".join(paths[:5])
                detection_rules.append(f"   - `{path_str}` → **{data['name']}**")
            else:
                detection_rules.append(f"   - (content detection) → **{data['name']}**")
        detection_block = "\n".join(detection_rules)

        return textwrap.dedent(f"""\
            ## Process

            1. **Determine mode** — parse arguments (see Invocation Modes above)
            2. **Get the code** — Mode 1: `git diff main...HEAD`, Mode 2: `gh pr diff <number>`, Mode 3: read all files in component directory
            3. **Detect platforms** — scan file paths to determine which platform checklists apply:
            {detection_block}
            4. **Understand first** — build a mental model of the code before judging it (see below)
            5. **Pre-flight checks** — scan for known high-frequency bug patterns. These are starting points for investigation, not final answers.
            6. **Agentic analysis** — trace data flows, audit consistency, detect absences, follow signals depth-first (see below)
            7. **Detect change types** — check if the diff/files touch migrations, API contracts, auth, dependencies, or infra (see Change-Type Modifiers). Increase scrutiny on relevant lenses.
            8. **Evaluate through all 8 lenses** — rate each as PASS / CONCERN / ISSUE.
            9. **Post findings** — Mode 2: `gh pr comment <number>` with structured output. Mode 1 and 3: output to terminal.

        """)

    def _understand_first_section(self) -> str:
        return textwrap.dedent("""\
            ## Phase 1: Understand Before Judging

            Before running any checks, build a mental model of the code. This context determines
            whether a finding is CRITICAL or INFO — a missing timeout is P0 in an auth service and
            P3 in a batch job.

            1. **What is this code's job?** Summarize in one sentence.
            2. **What are the trust boundaries?** Where does untrusted input enter? Where does
               sensitive data leave? What's authenticated vs public?
            3. **What are the failure domains?** If this component crashes, what breaks? If it's
               slow, what backs up? If it returns wrong data, who sees it?
            4. **What are the implicit contracts?** What does this code assume about its callers,
               its dependencies, and the data it receives? Are those assumptions documented or
               just hoped for?
            5. **What changed and why?** (Mode 1 and 2 only) What was the author trying to
               accomplish? Read PR description and commit messages. Understanding intent prevents
               false findings.

            Carry this model through the rest of the review. A checklist item that fires is only
            a finding if it matters given this context.

        """)

    def _agentic_analysis_section(self) -> str:
        return textwrap.dedent("""\
            ## Phase 3: Agentic Analysis

            This is where you earn your keep. Pre-flight checks catch known patterns — this phase
            catches the bugs that no checklist anticipates. These are active investigations, not
            pattern matches.

            ### Consistency Audit

            For every guard or restriction you encounter (auth check, rate limit, billing gate,
            input validation, size limit):
            1. Identify the resource or operation it protects
            2. Find ALL other code paths that reach the same resource/operation
            3. Verify each path has the same guard
            4. If a path is missing the guard, that's a finding — classify by what an attacker
               or unintended user could do through the unguarded path

            This is the #1 source of missed bugs. Restrictions are added to the first endpoint
            that needed them but rarely backfilled to new endpoints that touch the same resource.

            ### Trace Data Flows

            For critical inputs and outputs, trace the full path:
            1. Pick up user input at the handler boundary
            2. Follow it through validation, transformation, storage, forwarding
            3. At each step, ask: is it validated? transformed? logged? Could it be nil/null?
            4. Check the reverse: when data comes back from a dependency, what happens if it's
               malformed, null, empty, or an unexpected type?

            Don't trace every field — focus on: IDs (IDOR risk), strings that become queries,
            URLs that become HTTP calls, and values that cross service boundaries.

            ### Absence Detection

            Ask for each significant function or endpoint:
            - What error can occur here that has **no handler**?
            - What decision is made here that has **no log statement**?
            - What external call is made here that has **no timeout**?
            - What resource is acquired here that has **no cleanup on error path**?
            - What state change happens here that has **no audit trail**?
            - What failure mode exists here that has **no test**?

            Absence bugs are invisible to checklists. Only reasoning about what SHOULD be there
            but ISN'T can find them.

            ### Depth-First on Signals

            When you find a concerning pattern:
            1. Don't just log it and move on
            2. Search the codebase for the same pattern — if it's wrong here, it's probably
               wrong elsewhere
            3. Check the callers and callees of the affected code — does the bug propagate?
            4. Check if there's a test for this code path — if not, that's an additional finding

        """)

    def _preflight_section(self, detected: dict, component_paths: dict) -> str:
        lines = [textwrap.dedent("""\
            ## Phase 2: Pre-flight Checks

            Scan for these known patterns that have caused production incidents. Each is a
            starting point for investigation — when you find a match, don't just flag it.
            Trace it: is it actually reachable? What's the blast radius? Are there other
            instances of the same pattern?

        """)]

        by_category: dict[str, list[tuple[str, dict]]] = {}
        for key, data in detected.items():
            cat = data["_category"]
            by_category.setdefault(cat, []).append((key, data))

        for category, platforms in by_category.items():
            for platform_key, platform_data in platforms:
                checks = platform_data.get("preflight_checks", [])
                if not checks:
                    continue
                paths = component_paths.get(platform_key, [])
                name = platform_data["name"]

                if paths:
                    path_str = "`, `".join(paths[:3])
                    lines.append(f"### {name}\n")
                    lines.append(f"When reviewing `{path_str}`:\n")
                else:
                    lines.append(f"### {name}\n")

                for item in checks:
                    lines.append(f"- **{item['title']}**: {item['pattern']}")
                    lines.append(f"  - *Failure mode*: {item['failure_mode']}")
                    lines.append(f"  - *Fix*: {item['fix']}")
                    lines.append(f"  - *Lens*: {item['lens']} | *Severity*: {item['severity']}")
                    lines.append("")

        return "\n".join(lines) + "\n"

    def _cross_cutting_section(self, cross_cutting: dict | None) -> str:
        if not cross_cutting:
            return ""

        areas = cross_cutting.get("focus_areas", [])
        if not areas:
            return ""

        lines = [textwrap.dedent("""\
            ## Cross-Cutting Review (all code, all platforms)

            These are the highest-value focus areas. They catch bugs that platform-specific
            checklists miss — inconsistencies between code paths, bypass vectors, and
            assumptions that only surface under adversarial use. Apply these to EVERY review,
            regardless of platform.

        """)]

        for area in areas:
            desc = area["description"].strip().replace("\n", " ")
            why = area.get("why", "").strip().replace("\n", " ")
            lines.append(f"- **{area['area']}**: {desc} *(Lens: {area['lens']})*")
            if why:
                lines.append(f"  - *Why this matters*: {why}")
            lines.append("")

        return "\n".join(lines) + "\n"

    def _focus_areas_section(self, detected: dict, component_paths: dict) -> str:
        lines = [textwrap.dedent("""\
            ## Focus Areas

            Beyond pattern-matching pre-flight checks, actively explore these areas during review.
            These require reading surrounding code and understanding intent — they can't be detected
            from the diff alone.

        """)]

        for key, data in detected.items():
            areas = data.get("focus_areas", [])
            if not areas:
                continue
            lines.append(f"### {data['name']}\n")
            for area in areas:
                lines.append(f"- **{area['area']}**: {area['description']} *(Lens: {area['lens']})*")
            lines.append("")

        return "\n".join(lines) + "\n"

    def _lenses_section(self) -> str:
        return textwrap.dedent("""\
            ## Evaluation Lenses

            Rate each lens as **PASS** / **CONCERN** / **ISSUE**:

            1. **Production Reliability** — What will break in the real world? Crash paths, unhandled states, degraded-mode behavior, timeout handling, circuit breakers.

            2. **Correctness** — Hidden bugs: race conditions, lifecycle issues (app backgrounding, context cancellation, component unmounting), memory leaks/retain cycles, off-by-one, nil/null handling, type coercion surprises.

            3. **Data Integrity** — Partial writes without transactions, inconsistent state across services, cache/DB divergence, migration safety (reversibility, data loss), stale reads, eventual consistency assumptions.

            4. **Error Handling** — Swallowed errors, wrong error propagated up the stack, missing retries vs retry storms, idempotency gaps, error messages that lie about what happened, panic/crash vs graceful degradation.

            5. **Architecture** — Layering violations, coupling that shouldn't exist, abstractions at wrong level, design decisions that will hurt in 6 months, violation of established patterns in the codebase.

            6. **Operability** — Can you debug this in production? Missing logs at decision points, metrics gaps, tracing context dropped, alerting blind spots, deployment risk (rollback story?).

            7. **Performance** — N+1 queries, UI thread blocking, unnecessary re-renders, memory pressure, battery impact (mobile), unbounded allocations, missing pagination.

            8. **Maintainability** — Will the next engineer understand this? Implicit assumptions not documented, clever code that should be clear code, test coverage of the failure modes that matter (not just happy path).

        """)

    def _change_type_modifiers(self, detected: dict) -> str:
        # Collect all change type signals from detected platforms
        all_signals: dict[str, list[str]] = {}
        for key, data in detected.items():
            for signal in data.get("change_type_signals", []):
                ct = signal["type"]
                all_signals.setdefault(ct, []).extend(signal["patterns"])

        # Deduplicate
        for ct in all_signals:
            all_signals[ct] = sorted(set(all_signals[ct]))

        lines = [textwrap.dedent("""\
            ## Change-Type Modifiers

            When the diff/files match these patterns, increase scrutiny on the specified lenses:

        """)]

        modifier_map = {
            "database-migration": ("Data Integrity, Operability", "Rollback story, index impact, lock contention, data backfill safety"),
            "api-contract": ("Architecture, Production Reliability", "Backward compatibility with deployed clients, breaking changes, versioning"),
            "dependency-update": ("Production Reliability, Maintainability", "Breaking changes, CVEs, bundle size impact, transitive dependency risks"),
            "config-change": ("Operability, Production Reliability", "Deployment risk, rollback path, environment-specific behavior, secret exposure"),
        }

        lines.append("| Change Type | Detected By | Increased Scrutiny |")
        lines.append("|---|---|---|")
        for ct, patterns in all_signals.items():
            pattern_str = ", ".join(f"`{p}`" for p in patterns[:4])
            label, scrutiny = modifier_map.get(ct, (ct, "Review carefully"))
            lines.append(f"| **{ct.replace('-', ' ').title()}** | {pattern_str} | {label}: {scrutiny} |")
        lines.append("")

        return "\n".join(lines) + "\n"

    def _output_format(self) -> str:
        return textwrap.dedent("""\
            ## Output Format

            **Verdict and summary go first.** The reader wants the answer before the details.

            For **Mode 2 (PR review)**: post a single comment on the PR using
            `gh pr comment <number> --body "$(cat <<'COMMENT' ... COMMENT)"`.

            For **Mode 1, 3, and 4**: output directly to terminal.

            ### When no issues are found:

            ```
            ## Principal Engineer Code Review

            **PR:** #<number> — <title>  (omit for Mode 1 and 3)
            **Verdict: APPROVE** — no issues found.
            ```

            That's it. Do not produce empty sections or filler. A clean review is valuable.

            ### When issues are found:

            ```
            ## Principal Engineer Code Review

            **PR:** #<number> — <title>  (omit for Mode 1 and 3)
            **Verdict:** APPROVE / APPROVE with concerns / DISCUSS / REQUEST CHANGES
            **Findings:** N total (X ISSUE, Y CONCERN)
            **Components touched:** <list>
            **Change type(s):** <from modifiers, if any>

            ### Summary

            <1-2 sentences: what this change does and overall assessment>

            ### Pre-flight Checks

            <N of M pre-flight checks triggered.>

            | Check | Notes |
            |-------|-------|
            | [only checks that triggered] | ... |

            (Only show checks that found something. Do not list passing checks.)

            ### Findings

            For each issue found:

            #### Finding 1: `path/to/file:42`

            - **Lens:** <which of the 8 lenses>
            - **Rating:** ISSUE / CONCERN
            - **Intent:** What the author was trying to accomplish
            - **Risk:** Why this is risky or buggy
            - **Failure mode:** How this will break in production
            - **Recommendation:** What a Principal Engineer would do instead (with code example if helpful)

            ### Lens Assessment

            | Lens | Rating | Notes |
            |------|--------|-------|
            | Production Reliability | PASS/CONCERN/ISSUE | ... |
            | Correctness | PASS/CONCERN/ISSUE | ... |
            | Data Integrity | PASS/CONCERN/ISSUE | ... |
            | Error Handling | PASS/CONCERN/ISSUE | ... |
            | Architecture | PASS/CONCERN/ISSUE | ... |
            | Operability | PASS/CONCERN/ISSUE | ... |
            | Performance | PASS/CONCERN/ISSUE | ... |
            | Maintainability | PASS/CONCERN/ISSUE | ... |
            ```

            Do not manufacture findings. If the code is clean, APPROVE it.

            **GitHub issues are opt-in.** Do NOT auto-file GitHub issues for findings.
            Only create issues if the user explicitly asks (e.g., `/scrutineer-code 123 --file-issues`).

        """)

    def _deep_review_section(self, service_map: ServiceMapLoader | None) -> str:
        component_count = 0
        connections = []
        if service_map:
            component_count = len(service_map.get_reviewable_components())
            connections = service_map.data.get("connections", [])

        # Build connection summary for flow tracing
        flow_hints = ""
        if connections:
            # Find the most-connected components for flow suggestions
            conn_counts: dict[str, int] = {}
            for c in connections:
                conn_counts[c["source"]] = conn_counts.get(c["source"], 0) + 1
                conn_counts[c["target"]] = conn_counts.get(c["target"], 0) + 1
            top = sorted(conn_counts.items(), key=lambda x: -x[1])[:5]
            flow_hints = "\n".join(f"   - `{k}` ({v} connections)" for k, v in top)

        return textwrap.dedent(f"""\
            ## Mode 4: Deep Repo Review

            **Role:** You are a world-class Principal Software Engineer performing a comprehensive,
            deep-dive review of this entire repository. Do not just scan for patterns — evaluate
            the codebase as if you are preparing for a high-stakes production launch. Think like
            an engineer who has been hired to find the bugs that will page you at 2am.

            **Scope:** EVERYTHING. Backend services, mobile apps, web apps, infrastructure,
            CI/CD pipelines, configuration. No layer is out of scope. The investigations below
            are starting points — if you notice something interesting, follow it. Your best
            findings will come from pulling threads, not from checklists.

            **What makes this mode different:** Modes 1-3 review individual components in
            isolation. This mode traces flows ACROSS components and finds bugs that only exist
            in the interactions between them — data lost between a mobile sync engine and a
            server API, secrets that are encrypted in one layer but plaintext in another,
            billing limits enforced on one code path but not a parallel one.

            ### Adaptive Execution Strategy

            **Repo has {component_count} reviewable components.**

            {"**Small repo (≤20 components): Single-agent deep review.** Read the service map, then read source files as needed to trace flows. You have enough context. Prioritize depth on the most complex and highest-risk areas." if component_count <= 20 else "**Large repo (>20 components): Use sub-agents.** Dispatch sub-agents using the Agent tool — one per investigation area. Each sub-agent gets a fresh context and reads only the files relevant to its investigation. Collect findings, then synthesize."}

            ### Investigation 1: Trace Critical User Flows End-to-End

            Pick the 3-5 most complex user flows and trace each from client → API gateway →
            internal service → database and back. Read the actual code at each step — don't
            assume. For each flow:
            - What data is created, transformed, and stored at each step?
            - What fields are present at the API boundary vs what's stored? Are any dropped?
            - What happens on FAILURE at each step? Is the system left consistent?
            - What happens if this flow runs OFFLINE and then syncs? (for mobile apps)
            - What happens if two instances of this flow run CONCURRENTLY?
            - Is the same restriction (rate limit, billing check, auth) applied on ALL paths
              that reach this flow, or can some paths bypass it?

            {"**Most-connected components (start here):**" if flow_hints else ""}
            {flow_hints}

            ### Investigation 2: Cross-Service Pattern Comparison

            For each pattern, check if ALL services implement it the same way.
            Inconsistency = bug or tech debt:

            - **Error handling**: Do all services sanitize DB errors before logging? Or do some leak PII?
            - **PATCH semantics**: Do all services handle nil-vs-omit the same way?
            - **Input validation**: Do all services validate string lengths? Escape ILIKE wildcards?
            - **Pagination**: Do all list endpoints accept client pagination? Or are some hardcoded?
            - **Batch endpoints**: If one service has a batch endpoint, do similar services have one too?
            - **Auth/admin separation**: Are destructive operations on the admin router or regular API?
            - **Transaction boundaries**: Are multi-step writes wrapped in transactions consistently?
            - **Billing/limit enforcement**: Is every path that consumes a paid resource checked?

            ### Investigation 3: Cross-Layer Secret & Config Audit

            Trace every secret from storage → infrastructure → application runtime:
            - Read the Terraform/IaC files. Is every secret referenced as a `secret` in task
              definitions, not a plain `environment_variable`?
            - Are any secrets logged? (error messages, debug output, audit logs)
            - Are any secrets hardcoded in source, config files, or CI workflows?
            - Are CI/CD actions pinned to SHA or just version tags? (supply chain risk)
            - Are IAM policies least-privilege, or do they use `Resource: *`?

            ### Investigation 4: Mobile App & Client Deep Dive

            For EVERY mobile app and client in the repo:
            - **Sync engine**: Does it push ALL fields the server stores? Are relationships/links
              synced or only entities? What happens when a sync push fails — is the local record
              purged anyway? Trace the full offline→create→sync→server cycle.
            - **Token/session lifecycle**: Is refresh race-free? Are there two mechanisms that
              could conflict? Is the session fully cleared on logout, including local databases?
            - **State management**: Are error states reachable with no recovery path? (empty
              screen, no retry button, dead-end UI)
            - **Concurrency**: Are there actors/dispatchers/scopes that could conflict? Is
              CancellationException properly re-thrown? (Kotlin) Is @MainActor used correctly? (Swift)

            ### Investigation 5: Infrastructure & Deployment

            Review the infrastructure as code and CI/CD:
            - **Networking**: Single points of failure? (single NAT, single AZ dependency)
            - **Database**: Deletion protection? Backup retention? Encryption?
            - **IAM**: Overly broad policies? (Resource: *)
            - **CI/CD**: Secrets in logs? Unpinned actions? Self-hosted runners on public repos?
            - **Deployment**: Rollback path for every component? Migration ordering correct?
            - **Monitoring**: Are there gaps in alerting? Unmonitored services?
            - **Cost**: Over-provisioned resources? Missing Spot usage?

            ### Investigation 6: Architectural Gaps & "The Why"

            Look for things that seem redundant, counter-intuitive, or asymmetric:
            - Does one service have a capability that a parallel service lacks?
            - Are there N+1 HTTP call patterns where one service calls another in a loop?
            - Is there code that looks "smelly" — not wrong exactly, but suspiciously complex
              or unnecessarily clever? Investigate before flagging.
            - What would a new engineer find confusing when onboarding?

            ### Agentic Freedom

            The investigations above are a framework, not a straitjacket. If you notice a
            specific module that seems particularly complex or failure-prone, prioritize a
            deep dive on that section even if it doesn't fit neatly into an investigation.
            The most valuable findings come from following threads, not from completing a
            checklist.

            ### Output for Mode 4

            Verdict first, then details. Omit sections with no findings.

            ```
            ## Deep Repository Review

            **Verdict:** HEALTHY / CONCERNS / ACTION REQUIRED
            **Findings:** N total (X systemic, Y per-component, Z nitpicks)

            ### Executive Summary
            <2-3 sentences: overall health and biggest systemic risks>

            ### Critical Systemic Findings
            <Issues that span multiple components or affect data integrity across flows>

            ### Cross-Service Inconsistencies
            <Table: pattern | services that do it right | services that don't>

            ### Flow Trace Results
            <For each traced flow: what breaks, where, and why>

            ### Mobile & Client Findings
            <Sync engine bugs, token lifecycle issues, state management gaps>

            ### Infrastructure & Configuration Gaps
            <Secrets, deployment, networking, IAM, monitoring gaps>

            ### Positive Patterns Worth Spreading
            <Things one service does well that others should adopt>
            ```

        """)

    def _help_section(self) -> str:
        return textwrap.dedent("""\
            ## Help (--help)

            If the argument is `--help`, output this summary and stop:

            ```
            /scrutineer-code — Principal Engineer peer code review

            MODES:
              /scrutineer-code              Review current branch diff vs main (~2 min)
              /scrutineer-code 123          Review PR #123, post findings as comment (~5 min)
              /scrutineer-code <component>  Full review of a service/app by name (~5 min)
              /scrutineer-code --deep       Deep repo-wide review across all components (~20 min)
              /scrutineer-code --help       Show this help

            WHAT IT DOES:
              Modes 1-3: Pre-flight checks → agentic analysis → 8 evaluation lenses
              Mode 4:    All of the above PLUS cross-service flow tracing, pattern
                         comparison, secret audit, and architectural gap analysis

            EVALUATION LENSES:
              Production Reliability | Correctness | Data Integrity | Error Handling
              Architecture | Operability | Performance | Maintainability

            VERDICTS:
              APPROVE — no issues found
              APPROVE with concerns — minor issues, not blocking
              DISCUSS — needs team input on approach
              REQUEST CHANGES — must fix before merge

            OUTPUT:
              Mode 1, 3, 4: Terminal output
              Mode 2: Posts structured comment on the PR via gh
            ```

        """)

    def _self_heal_section(self, all_known_platforms: list[str]) -> str:
        known_list = ", ".join(sorted(all_known_platforms))
        return textwrap.dedent(f"""\
            ## Self-Healing: Unknown Platforms

            **Known platforms at generation time:** {known_list}

            **When you encounter an unknown platform in the code being reviewed:**

            1. **Flag it** in your review output:
               ```
               ⚠️  ENRICHMENT NEEDED: This review covers [platform/language] files, but no
               platform-specific checklist exists for it. File patterns detected:
               - [list]
               ```

            2. **Still review those files** using universal principles (error handling, resource
               management, data integrity, etc.) — don't skip them.

            3. **Offer to self-heal**:
               ```
               🔧 SELF-HEAL AVAILABLE: I can generate pre-flight checks and focus areas for
               [platform] and add them to this review skill for future reviews.
               ```

            4. **If you have enough knowledge**, include a draft checklist in the review output
               under a "Draft Checklist" section. Each item MUST name a specific API/function/pattern,
               include a failure mode, and map to one of the 8 lenses.
        """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_guidance(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def get_all_platform_keys(guidance: dict) -> list[str]:
    keys = []
    for category in guidance.values():
        keys.extend(category.keys())
    return keys


def main():
    parser = argparse.ArgumentParser(
        description="Generate a tailored peer code review skill for a repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s /path/to/repo
              %(prog)s /path/to/repo --service-map servicemap.json
              %(prog)s /path/to/repo --dry-run
        """),
    )
    parser.add_argument("repo_path", help="Path to the repository to analyze")
    parser.add_argument("--output", "-o", default=".claude/commands/scrutineer-code.md",
                        help="Output path relative to repo root (default: .claude/commands/scrutineer-code.md)")
    sm_group = parser.add_mutually_exclusive_group()
    sm_group.add_argument("--service-map", "-s", default=None,
                          help="Path to servicemap.json for richer context. "
                               "If omitted, auto-discovered at <repo>/servicemap.json.")
    sm_group.add_argument("--no-service-map", action="store_true",
                          help="Disable service-map auto-discovery and run without one")
    parser.add_argument("--guidance", "-g", default=None,
                        help="Path to peer review guidance YAML")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Print generated skill to stdout without writing")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Overwrite existing scrutineer-code.md without prompting")

    args = parser.parse_args()

    # Load guidance
    guidance_path = Path(args.guidance) if args.guidance else Path(__file__).parent / "peer_review_guidance.yaml"
    if not guidance_path.exists():
        print(f"Error: guidance file not found: {guidance_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading guidance from: {guidance_path}")
    guidance = load_guidance(guidance_path)

    # Resolve service map: explicit --service-map, else auto-discover at repo root,
    # unless --no-service-map opts out. Silent degradation (running without a map
    # the user forgot to point at) is the worst failure mode here.
    if not args.service_map and not args.no_service_map:
        candidate = Path(args.repo_path).resolve() / "servicemap.json"
        if candidate.exists():
            args.service_map = str(candidate)
            print(f"Auto-detected service map at: {candidate}")

    service_map = None
    if args.service_map:
        sm_path = Path(args.service_map)
        if not sm_path.is_absolute():
            sm_path = Path(args.repo_path).resolve() / sm_path
        if sm_path.exists():
            print(f"Loading service map from: {sm_path}")
            service_map = ServiceMapLoader(str(sm_path))
            reviewable = service_map.get_reviewable_components()
            print(f"  {len(reviewable)} reviewable components found")
        else:
            print(f"Warning: service map not found at {sm_path}, proceeding without it")

    # Analyze repo
    repo_path = Path(args.repo_path).resolve()
    print(f"Analyzing repository: {repo_path}")
    analyzer = RepoAnalyzer(str(repo_path))
    print(f"Indexed {len(analyzer.file_index)} files")

    # Extract cross-cutting focus areas (not platform-specific)
    cross_cutting = guidance.pop("cross_cutting", None)
    if cross_cutting:
        cc_count = len(cross_cutting.get("focus_areas", []))
        print(f"  {cc_count} cross-cutting focus areas loaded")

    detected = analyzer.detect_platforms(guidance)
    if not detected:
        print("\nNo known platforms detected. The generated skill will only include universal lenses.")
    else:
        print(f"\nDetected {len(detected)} platform(s):")
        for key, data in detected.items():
            checks = len(data.get("preflight_checks", []))
            areas = len(data.get("focus_areas", []))
            print(f"  ✓ {data['name']:30s} ({checks} pre-flight checks, {areas} focus areas)")

    component_paths = analyzer.map_component_paths(detected)
    all_known = get_all_platform_keys(guidance)

    # Generate
    generator = SkillGenerator()
    skill_content = generator.generate(detected, component_paths, all_known, service_map, cross_cutting)

    if args.dry_run:
        print("\n" + "=" * 72)
        print("GENERATED SKILL (dry run — not written)")
        print("=" * 72 + "\n")
        print(skill_content)
        return

    # Write
    output_path = repo_path / args.output
    if output_path.exists() and not args.force:
        # Detect non-interactive callers (CI, agents, pipes). input() would raise
        # EOFError with a stack trace; surface a clear error instead.
        if not sys.stdin.isatty():
            print(f"\nERROR: {output_path} already exists and --force was not passed.", file=sys.stderr)
            print("Pass --force (-f) to overwrite, or remove the file first.", file=sys.stderr)
            sys.exit(1)
        response = input(f"\n{output_path} already exists. Overwrite? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(skill_content)

    check_count = sum(len(d.get("preflight_checks", [])) for d in detected.values())
    area_count = sum(len(d.get("focus_areas", [])) for d in detected.values())
    print(f"\n✓ Generated peer review skill at: {output_path}")
    print(f"  Platforms: {len(detected)}")
    print(f"  Pre-flight checks: {check_count}")
    print(f"  Focus areas: {area_count}")
    print(f"  Evaluation lenses: 8 (always)")
    if service_map:
        reviewable = service_map.get_reviewable_components()
        print(f"  Reviewable components: {len(reviewable)} (from service map)")
    print(f"\nUsage: /scrutineer-code (from Claude Code in the target repo)")


if __name__ == "__main__":
    main()
