#!/usr/bin/env python3
"""
Peer Review Skill Generator

Scans a repository (and optionally consumes a servicemap.json) to generate a
tailored .claude/commands/vld8-review.md with platform-specific pre-flight
checks, focus areas, and evaluation lenses.

The generated skill supports four invocation modes:
  /vld8-review                  — review current branch diff vs main
  /vld8-review 123              — review PR #123 (its head checked out in a worktree for Phase 0)
  /vld8-review <component-name> — full review of a service/app from the service map
  /vld8-review --deep           — deep repo-wide review across services

Usage:
    python generate.py /path/to/repo
    python generate.py /path/to/repo --service-map servicemap.json
    python generate.py /path/to/repo --dry-run
"""

import argparse
import fnmatch
import functools
import itertools
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml


def _render(template: str, **values) -> str:
    """Dedent a section template, then fill in its values.

    The order matters. ``textwrap.dedent(f"...")`` dedents *after* interpolation,
    so a value that spans lines brings continuation lines with less indent than
    the template's, dedent finds a smaller common margin, and the whole section
    keeps its source indentation, which Markdown renders as a code block.
    Dedenting the template first makes the output independent of the values.
    Literal braces in templates are written doubled, as in an f-string.
    """
    return textwrap.dedent(template).format(**values)


@functools.lru_cache(maxsize=None)
def _glob_regex(pattern: str) -> "re.Pattern[str]":
    parts = pattern.split("**/")
    candidates = {
        parts[0] + "".join(("**/" if keep else "") + p for keep, p in zip(keeps, parts[1:]))
        for keeps in itertools.product((True, False), repeat=len(parts) - 1)
    }
    return re.compile("|".join(f"(?:{fnmatch.translate(c)})" for c in sorted(candidates)))


def glob_match(rel: str, pattern: str) -> bool:
    """fnmatch, except that `**/` may also match no directory at all.

    fnmatch's `*` already crosses `/`, so `**/` behaves like `*/` and demands at
    least one directory: `App/**/*.swift` never matched `App/Foo.swift`, and
    `**/*.swift` never matched a root-level file, which is why the guidance lists
    both forms of so many globs. Allowing each `**/` to be dropped gives the usual
    zero-or-more-directories meaning without changing what `*` matches.
    """
    return _glob_regex(pattern).match(rel) is not None


def code_span(text: str) -> str:
    """Wrap text as inline code, even when it contains backticks itself.

    A command such as "swiftlint … <the config's `included:` paths>" inside a
    single-backtick span closes the span at its first inner backtick, so the
    reader copies a truncated command. Markdown allows a longer fence instead.
    """
    return f"`` {text} ``" if "`" in text else f"`{text}`"


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
        self._text_cache: dict[str, str | None] = {}

    # Third-party trees that are sometimes committed. Skipped even in the git
    # index; everything else that git tracks is the repo's own code.
    TRACKED_SKIP_DIRS = {"node_modules", "bower_components", "Pods", "Carthage"}

    @property
    def file_index(self) -> list[Path]:
        if self._file_index is None:
            self._file_index = self._git_index()
            if self._file_index is None:
                self._file_index = self._walk_index()
        return self._file_index

    def _git_index(self) -> list[Path] | None:
        """Tracked plus untracked-but-not-ignored files, or None outside a git repo.

        Walking the working tree let gitignored build output, worktree caches,
        vendored SAM builds and scratch folders decide which platforms a repo
        has and which directories the skill names (written into a file meant to
        be committed), and read gitignored secret- and PII-bearing files along
        the way. What git would commit is what the review is about. A
        top-level `vendor/` (Go, PHP, Ruby) is third-party by convention; a
        nested one is often first-party, so only the top level is skipped.
        """
        try:
            out = subprocess.run(
                ["git", "-C", str(self.repo_path), "ls-files", "-z",
                 "--cached", "--others", "--exclude-standard"],
                capture_output=True, check=True, timeout=120,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        files = []
        for rel in sorted(set(p for p in out.decode("utf-8", "surrogateescape").split("\0") if p)):
            parts = Path(rel).parts
            if parts[0] == "vendor" or any(p in self.TRACKED_SKIP_DIRS for p in parts[:-1]):
                continue
            f = self.repo_path / rel
            if f.is_file():
                files.append(f)
        return files

    def _walk_index(self) -> list[Path]:
        # Outside git, fall back to a walk with a name denylist. Sorted so the
        # order is deterministic across filesystems.
        files = []
        for root, dirs, names in os.walk(self.repo_path):
            dirs[:] = sorted(d for d in dirs if d not in self.SKIP_DIRS)
            for f in sorted(names):
                files.append(Path(root) / f)
        return files

    def relative_paths(self) -> list[str]:
        return [str(f.relative_to(self.repo_path)) for f in self.file_index]

    def matches_glob(self, pattern: str) -> list[str]:
        return [rel for rel in self.relative_paths() if glob_match(rel, pattern)]

    # Extensions worth grepping for platform signals. Without this filter,
    # content detection burns its budget on binary assets and generated data
    # before it reaches source. Documentation extensions are deliberately absent:
    # a README that mentions `import SwiftUI` must not detect an iOS platform.
    CONTENT_EXTS = {
        ".swift", ".m", ".mm", ".h", ".kt", ".java", ".py", ".go", ".rs", ".rb",
        ".php", ".cs", ".ts", ".tsx", ".js", ".jsx", ".vue",
        ".mjs", ".cjs", ".mts", ".cts", ".dart", ".scala", ".ex", ".exs",
        ".c", ".cc", ".cpp", ".hpp", ".sh",
        ".yml", ".yaml", ".json", ".toml", ".tf", ".plist", ".entitlements",
        ".xcconfig", ".xcprivacy", ".pbxproj", ".resolved", ".gradle", ".kts",
    }

    def _read_text(self, f: Path, max_bytes: int = 2_000_000) -> str | None:
        """A file's text, read at most once per run; None if unreadable or oversized."""
        key = str(f)
        if key not in self._text_cache:
            try:
                too_big = f.stat().st_size > max_bytes
                self._text_cache[key] = None if too_big else f.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                self._text_cache[key] = None
        return self._text_cache[key]

    def file_contains_any(self, patterns: list[str], extensions: list[str] | set | None = None,
                          max_files: int = 5000) -> bool:
        """True when any file with a matching extension matches any of the patterns.

        All of a block's patterns are checked in one pass, and each file is read
        once per run, so a block with six patterns costs one walk, not six.
        """
        # The budget used to be 50 files / 50 KB, which on any real repo was
        # exhausted in the first directory `os.walk` happened to visit. Measured
        # on a 1071-file Swift repo: `^import CloudKit` (16 real hits),
        # `^import Testing` (273) and `^import FoundationModels` (13) all
        # returned False because the walk never reached `Sources/`. Detection
        # that depends on walk order is not detection.
        regexes = [re.compile(p, re.MULTILINE) for p in patterns]
        exts = set(extensions) if extensions else None
        count = 0
        for f in self.file_index:
            if exts is not None and f.suffix not in exts:
                continue
            text = self._read_text(f)
            if text is None:
                continue
            count += 1
            if count > max_files:
                break
            if any(r.search(text) for r in regexes):
                return True
        return False

    def detect_platforms(self, guidance: dict) -> dict[str, dict]:
        # `detect_mode` controls how detect_files and detect_content combine:
        #
        #   "files" (default) — detect_files decides. detect_content is consulted
        #                       ONLY when a block declares no detect_files. This
        #                       is the historical behaviour, kept as the default
        #                       deliberately: because the old code could never
        #                       reach detect_content for a block that had
        #                       detect_files, those patterns have never once been
        #                       evaluated, and several are wrong. `go`'s
        #                       `^module\s+` and `java`'s `^package\s+[a-z]` both
        #                       match modern Swift source (`package` is a Swift
        #                       5.9 access modifier), so promoting them to an
        #                       OR-fallback detects Go and Java in a pure Swift
        #                       repo. Opt a block in only after validating its
        #                       patterns against a real repo.
        #
        #   "all"             — BOTH must match. This is what a sub-platform
        #                       needs: "Swift files AND they import CloudKit" is
        #                       not expressible otherwise, and without it every
        #                       capability sub-block fires on every Swift repo.
        #
        #   "any"             — either signal detects the platform. Opt-in.
        detected = {}
        rel_paths = self.relative_paths()
        for category_name, platforms in guidance.items():
            for platform_key, platform_data in platforms.items():
                globs = platform_data.get("detect_files", [])
                contents = platform_data.get("detect_content", [])
                mode = platform_data.get("detect_mode", "files")

                file_match = any(
                    glob_match(rel, pattern)
                    for pattern in globs
                    for rel in rel_paths
                )

                # Only pay for a content scan when it can still change the answer.
                if not contents:
                    need_content = False
                elif mode == "all":
                    need_content = file_match
                elif mode == "any":
                    need_content = not file_match
                else:  # "files"
                    need_content = not globs
                # A block may narrow which extensions its content patterns are
                # searched in. Without that, a repo whose own files *describe*
                # a pattern matches it: this repo's guidance YAMLs mention
                # `import AppKit` and `NSApplicationDelegate` as things to look
                # for, which was enough to detect a macOS app in a pure Python
                # repo. Documentation about a platform is not that platform.
                exts = platform_data.get("detect_content_exts") or self.CONTENT_EXTS
                content_match = (
                    self.file_contains_any(contents, extensions=exts) if need_content else False
                )

                if mode == "all":
                    hit = bool(globs) and file_match and bool(contents) and content_match
                else:
                    hit = file_match or content_match

                if hit:
                    detected[platform_key] = {**platform_data, "_category": category_name}
        return detected

    def _file_matches_any(self, rel: str, regexes: list, exts=None) -> bool:
        """True when the file at `rel` matches one of the compiled patterns."""
        exts = exts or self.CONTENT_EXTS
        f = self.repo_path / rel
        if f.suffix not in exts:
            return False
        text = self._read_text(f)
        return bool(text) and any(r.search(text) for r in regexes)

    def map_component_paths(self, detected: dict[str, dict]) -> dict[str, list[str]]:
        # Ordered by how much code each path actually contributes, NOT
        # alphabetically. Callers truncate this list to name a few directories in
        # the generated skill, and an alphabetical sort meant the truncation kept
        # whichever directories sorted first — on a Swift repo that named two
        # single-file app shells and dropped every module holding the code.
        #
        # For a `detect_mode: all` block, a path only counts if the files there
        # actually match the block's content patterns. Otherwise a capability
        # block ("Swift files AND they import CloudKit") would name every Swift
        # directory in the repo and send the reviewer to files that have nothing
        # to do with it — the same wrong-directory failure, one level down.
        component_paths = {}
        rel_paths = self.relative_paths()
        for pk, pd in detected.items():
            counts: dict[str, int] = {}
            scoped = pd.get("detect_mode") == "all" and pd.get("detect_content")
            regexes = [re.compile(c, re.MULTILINE) for c in pd.get("detect_content", [])] \
                if scoped else []
            scope_exts = pd.get("detect_content_exts") or self.CONTENT_EXTS
            # `component_globs` lets a content-gated block still name real
            # directories. When they name none (an Xcode layout like
            # `MyApp/Store.swift` matches no `App/`/`Sources/` glob), fall back
            # to the detection globs rather than reporting no paths at all.
            glob_sets = [pd.get("component_globs"), pd.get("detect_files")]
            for globs in (g for g in glob_sets if g):
                for pattern in globs:
                    for rel in rel_paths:
                        if not glob_match(rel, pattern):
                            continue
                        if scoped and not self._file_matches_any(rel, regexes, scope_exts):
                            continue
                        parts = Path(rel).parts
                        key = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else parts[0]
                        counts[key] = counts.get(key, 0) + 1
                if counts:
                    break
            component_paths[pk] = [
                p for p, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            ]
        return component_paths



def format_paths(paths: list[str], limit: int = 6) -> str:
    """Render component paths for the skill, saying so when the list is trimmed.

    Paths arrive ranked by how much code each contributes. Silently truncating
    told the reviewer to check three directories as though they were the whole
    surface; naming the overflow keeps the omission visible.
    """
    shown = "`, `".join(paths[:limit])
    extra = len(paths) - limit
    return f"`{shown}`" + (f", and {extra} more" if extra > 0 else "")

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
                 cross_cutting: dict | None = None,
                 verification: dict | None = None) -> str:
        sections = [
            self._header(),
            self._help_section(),
            self._invocation_section(service_map, has_phase0=bool(verification)),
            self._process_section(detected, component_paths, service_map,
                                  has_phase0=bool(verification)),
            self._verification_section(detected, verification),
            self._diff_triage_section(service_map),
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

    def _invocation_section(self, service_map: ServiceMapLoader | None,
                            has_phase0: bool = True) -> str:
        # Phase 0 must run on the PR's code, not the user's checkout (#93); the
        # worktree step exists only when there is a Phase 0 to run in it.
        pr_checkout = (
            "4. Check out the PR's head in its own worktree, so the user's checkout is untouched. Its\n"
            "   path, `<wt>` below, is `${TMPDIR:-/tmp}/vld8-<repo>-pr-123`, where `<repo>` is this\n"
            "   repository's directory name.\n"
            "   - Fetch the head: `git fetch origin pull/123/head`. If that fails, or `git rev-parse FETCH_HEAD` isn't `headRefOid` (as when `origin` is your fork), fetch from the repository `gh` resolves instead: `git fetch \"$(gh repo view --json url -q .url)\" pull/123/head`.\n"
            "   - `git worktree remove --force <wt> 2>/dev/null; git worktree add --detach <wt> <headRefOid>`. If that fails, neither fetch brought the PR's commit: run no Phase 0 stage, review the diff, and say in the report that Phase 0 didn't run.\n"
            "   - Same-repository PR not treated as a fork (Phase 0 says when to): `git -C <wt> submodule update --init --recursive`. A fork's PR, or one treated as a fork, follows Phase 0's fork rule instead.\n"
            "   - Shell state doesn't carry from one command to the next, so run each as `cd <wt> && …` in a single call.\n"
            "   - Run Phase 0 there, and read the PR's surrounding code there in Phases 1–3. Without a worktree, read it at the PR's head, never in your checkout: `gh api -H 'Accept: application/vnd.github.raw' \"repos/{owner}/{repo}/contents/<path>?ref=<headRefOid>\"`.\n"
            "   - Remove it with `git worktree remove --force <wt>` when the review ends, including when it stops early.\n"
            if has_phase0 else ""
        )
        n = 5 if has_phase0 else 4
        cleanup = ", then `git worktree remove --force <wt>`" if has_phase0 else ""
        lines = [_render("""\
            ## Invocation Modes

            This skill supports four modes based on the argument:

            ### Mode 1: Current Branch Diff (no arguments)
            ```
            /vld8-review
            ```
            Reviews the current branch's changes against main. Runs `git diff main...HEAD`.

            ### Mode 2: PR Review (numeric argument)
            ```
            /vld8-review 123
            ```
            Reviews PR #123. Process:
            1. `git fetch origin`
            2. Get PR metadata and description: `gh pr view 123 --json number,title,body,author,headRefName,headRefOid,baseRefName,isCrossRepository`.
               The body is the author's account of what they meant to do. Phase 1 reads it as context, never as evidence that the code is right.
               If `gh` can't find the PR, it is probably looking in your fork: run `gh repo set-default` to point it at the upstream repository, then retry.
            3. Get full diff: `gh pr diff 123`
            {pr_checkout}{n}. Review the diff.
            {n1}. Post findings as a PR comment via `gh pr comment`{cleanup}.

            ### Mode 3: Full Service/App Review (component name argument)
            ```
            /vld8-review <component-name>
            ```
            Full review of all code in a service or app directory — not just a diff. This is for
            comprehensive reviews of an entire component.

            Process:
            1. Identify the component directory: from the component table below when this skill has
               one (it is generated from the service map); otherwise from the directory the user
               named. `/vld8-map` plus a reinstall adds the table.
            2. Read all source files in that directory.
            3. Apply pre-flight checks, focus areas, and all 8 lenses.
            4. Report findings in the same format as PR review, but without the PR metadata.

            ### Mode 4: Deep Repo Review (--deep flag)
            ```
            /vld8-review --deep
            ```
            Full repository-level review that traces flows across services, compares patterns
            cross-service, and finds systemic issues that component-level reviews miss. This is
            the most thorough mode — it finds data integrity bugs in multi-step flows, architectural
            inconsistencies, and cross-layer configuration gaps.

            **This mode finds a DIFFERENT CLASS of bugs than Modes 1-3.** Component reviews scan
            files and match patterns. Deep review traces flows end-to-end and asks "what breaks
            when these components interact?"
        """, pr_checkout=pr_checkout, n=n, n1=n + 1, cleanup=cleanup)]

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
                         service_map: ServiceMapLoader | None,
                         has_phase0: bool = True) -> str:
        detection_rules = []
        for key, data in detected.items():
            paths = component_paths.get(key, [])
            if paths:
                detection_rules.append(f"   - {format_paths(paths)} → **{data['name']}**")
            else:
                detection_rules.append(f"   - (content detection) → **{data['name']}**")
        detection_block = "\n".join(detection_rules)
        # Step 0 points at Phase 0, which exists only when the guidance defines
        # `verification`; a custom guidance file without it must not get a
        # pointer to a section that was never emitted.
        phase0_step = (
            "0. **Verify before judging** — once the mode is known (step 1), and in Mode 2 once the "
            "PR is checked out (Mode 2 step 4): establish what the toolchain already proves, and stop "
            "if the code under review is red (see Phase 0)\n"
            if has_phase0 else ""
        )

        return _render("""\
            ## Process

            {phase0_step}1. **Determine mode** — parse arguments (see Invocation Modes above)
            2. **Get the code** — Mode 1: `git diff main...HEAD`, Mode 2: `gh pr diff <number>`, Mode 3: read all files in component directory
               - **Size the diff before reading it** — see Diff Triage below. A review unit you cannot hold is a review you cannot trust.
            3. **Detect platforms** — scan file paths to determine which platform checklists apply:
            {detection_block}
            4. **Understand first** — build a mental model of the code before judging it (see below)
            5. **Pre-flight checks** — scan for known high-frequency bug patterns. These are starting points for investigation, not final answers.
            6. **Agentic analysis** — trace data flows, audit consistency, detect absences, follow signals depth-first (see below)
            7. **Detect change types** — check if the diff/files touch migrations, API contracts, auth, dependencies, or infra (see Change-Type Modifiers). Increase scrutiny on relevant lenses.
            8. **Evaluate through all 8 lenses** — rate each as PASS / CONCERN / ISSUE.
            9. **Post findings** — Mode 2: `gh pr comment <number>` with structured output. Mode 1 and 3: output to terminal.

        """, detection_block=detection_block, phase0_step=phase0_step)

    def _verification_section(self, detected: dict, verification: dict | None) -> str:
        """Phase 0 — what the toolchain proves, so the review stops re-deriving it.

        Emitted only for detected platforms that have a ladder. A repo whose
        platforms have none still gets the gate-discovery step, which is the
        part that generalises: the repo's own gate script is a better
        description of "correct here" than anything this file can infer.
        """
        if not verification:
            return ""

        gates = verification.get("gate_candidates", [])
        ladders = verification.get("platforms", {})
        applicable = [(k, ladders[k]) for k in detected if k in ladders]

        lines = [textwrap.dedent("""\
            ## Phase 0: Verify Before You Judge

            Before reading a single line for review, establish what the toolchain already
            proves. Everything it proves, you must not re-derive — and must not report. A
            finding the compiler already refuted is worse than no finding: it is confidently
            wrong, and it spends the reader's trust on the findings that are real.

            **Run it on the code under review.** Modes 1, 3 and 4: this checkout. Mode 2: the
            PR's head, in the worktree from Mode 2 step 4, never the base branch or the user's
            checkout. A green run on other code proves nothing about the PR, and its exclusions
            would suppress findings that are in it.

            **A fork's code is its author's, config files included.** If the PR comes from a
            fork (`isCrossRepository: true`), run nothing in its worktree without the user's
            go-ahead: not the gate script, build or tests, and not the linters either. mypy
            plugins are code, and SwiftLint fetches a remote `parent_config` with environment
            variables expanded into its URL. Without a go-ahead Phase 0 runs nothing, earns no
            exclusions, and the report says so. A same-repository PR comes from someone with
            write access, so Phase 0 runs its code as it would run the user's own, with two
            exceptions that are treated as a fork. One is a bot's PR (`author.is_bot`):
            Dependabot and Renovate change lockfiles, and installing them runs the new
            packages' install scripts. The other is any PR the user says to treat that way,
            as when write access in this repo is broad.

            **A fresh worktree is not the user's environment.** It has no gitignored files,
            virtualenv or build cache. When a stage fails there for a reason the PR didn't cause,
            such as a missing ignored file (a local secrets file, say) or a dependency or tool
            that isn't installed, that stage counts as not run: it earns no exclusions, the
            review continues, and the report names the stage and why it couldn't run. Only a
            failure the PR's own changes cause is a finding.

            A stage you did not run on the code under review earns no exclusions.

            **1. Find the repo's own gate.** Look for:
        """)]
        for g in gates:
            note = f" — {g['note']}" if g.get("note") else ""
            lines.append(f"   - {code_span(g['path'])}{note}")
        lines.append(textwrap.dedent("""
            If one exists, READ IT FIRST. It is the most accurate available description of
            this repo's definition of correct, it usually explains *why* each stage exists,
            and it encodes constraints no generated checklist knows about. Run it when the
            review is repo- or component-scoped.

            **2. Otherwise compose the cheap subset** for the platforms in the diff, below.

            **3. If the code under review fails, STOP.** Report the failure verbatim, name the
            first failing stage, and do not continue to semantic review — reviewing code that
            does not build is guesswork, and the build failure is the finding. A failure the
            environment causes is a stage not run, as above, not a finding. In Mode 2, post
            the failure and then remove the worktree.

            **4. If it passes, honour the exclusion list.** It is not advice; it is the set
            of things you now know are absent. But a linter proves only the rules its config
            enables, so read the config before excluding anything: each linter's rule table
            below says where the config lives and which rules are on by default. A pattern
            whose rule is off, or ignored for that file, is in scope like any other code. So is
            suppressed code: a line (`# noqa: E722`), a region (`# ruff: disable[E722]` to its
            `enable`, `// swiftlint:disable force_cast` to its `enable` or the end of the file)
            or a whole file (`# ruff: noqa`). The green run says nothing about it. And a rule
            proves only its exact pattern, not the class of bug it is named for: ruff's S608
            flags `%`-formatted SQL but passes SQL built by concatenation. The tools can list
            what is on: `ruff check --show-settings <file>` (`linter.rules.enabled`, with
            exceptions under `linter.per_file_ignores`), and the "enabled in your config"
            column of `swiftlint rules`.

            **5. Record which oracle covers which changed files.** Coverage is not uniform, and
            an exclusion you apply outside the range of the command that earned it is a guess
            wearing a proof's clothing. Build this table before judging anything:

            | Changed path | Covered by | Not covered by |
            |---|---|---|

            Then state plainly: **which changed files no oracle covered at all.** Those are the
            files where you are reasoning without a net, and findings there deserve more
            scepticism and more reading of surrounding code — not less.

            **6. Use the toolchain to measure, not only to gate.** A green build answers
            "does it compile"; the same tools also answer questions the source cannot. When the
            diff touches build configuration, packaging, or the module graph, read the *produced
            artefact* rather than the input that was meant to produce it — the merged plist
            rather than the authored one, the resolved module closure rather than the manifest,
            the built test bundle rather than the target list. Several classes of defect are
            invisible in the diff and obvious in the output, and the commands are already
            installed.
        """))

        if not applicable:
            lines.append(textwrap.dedent("""
                No verification ladder is defined for the platforms detected in this repo.
                Establish one from the gate script or CI workflow above, run it, and record
                what it proves before continuing.
            """))
            return "\n".join(lines)

        for key, ladder in applicable:
            name = detected[key]["name"]
            lines.append(f"\n### {name} — commands\n")

            per_diff = ladder.get("per_diff", [])
            if per_diff:
                lines.append("**Per-diff (always, before judging — target under ~60s):**\n")
                for step in per_diff:
                    cost = f" *({step['cost']})*" if step.get("cost") else ""
                    lines.append(f"- {code_span(step['cmd'])}{cost}")
                    lines.append(f"  - When: {step['when']}")
                    if step.get("note"):
                        lines.append(f"  - Note: {step['note']}")
                lines.append("")

            per_repo = ladder.get("per_repo", [])
            if per_repo:
                lines.append("**Per-repo / per-PR (on request, or when the diff is large or touches the package graph):**\n")
                for step in per_repo:
                    lines.append(f"- {code_span(step['cmd'])}")
                    lines.append(f"  - When: {step['when']}")
                lines.append("")

            proves = ladder.get("proves", [])
            if proves:
                lines.append(f"**{name} — exclusion list.** When these pass, do NOT report:\n")
                lines.append("| Proved green | Therefore do NOT report |")
                lines.append("|---|---|")
                for p in proves:
                    excludes = (
                        "the exact pattern of each rule the repo's config enables, in the files it "
                        "checked; not the wider class of bug a rule is named for, and nothing the "
                        "config leaves off. The rule table below covers the patterns most often "
                        "wrongly assumed"
                        if p.get("rules") else p["excludes"]
                    )
                    lines.append(f"| {code_span(p['green'])} | {excludes} |")
                lines.append("")
                # A linter's green run says nothing about rules its config leaves
                # off; an exclusion claimed for them drops real findings (#92).
                for p in proves:
                    if not p.get("rules"):
                        continue
                    where = f"Read it first: {p['config']}" if p.get("config") else "Read it first."
                    lines.append(f"**{code_span(p['green'])} covers only what its config enables.** "
                                 f"{where}\n")
                    lines.append("| Pattern | Rule | On by default |")
                    lines.append("|---|---|---|")
                    for r in p["rules"]:
                        rule_ids = ", ".join(code_span(x.strip()) for x in r["rule"].split(","))
                        default = "yes" if r.get("default") else "no (opt-in)"
                        lines.append(f"| {r['pattern']} | {rule_ids} | {default} |")
                    lines.append("")

            unproven = ladder.get("still_unproven", [])
            if unproven:
                lines.append("**What the toolchain still does not prove** — this is where the review's value is:\n")
                for u in unproven:
                    lines.append(f"- {u}")
                lines.append("")

            never = ladder.get("never_run", [])
            if never:
                lines.append("**Do not run:**\n")
                for n in never:
                    lines.append(f"- {code_span(n['what'])} — {n['why']}")
                lines.append("")

        return "\n".join(lines)

    def _diff_triage_section(self, service_map: "ServiceMapLoader | None") -> str:
        """Measure the diff before reviewing it, and partition when it is too large.

        Mode 1 assumes a branch diff is a review unit. It is not always: a branch
        that has drifted, or a release train, can be hundreds of files. Reading
        that linearly produces a shallow pass that reports nothing useful — and
        the reviewer cannot tell the difference from the inside.
        """
        map_line = (
            "Partition along the components in the service map — it already names the "
            "boundaries, and a component is a unit someone can reason about whole."
            if service_map else
            "Partition along top-level source directories (module, package, or service "
            "roots). Run `/vld8-map` first if you want the boundaries named "
            "for you."
        )
        return _render("""\
            ## Diff Triage — size the change before reviewing it

            Run this first, before reading any code:

            ```
            git diff <base>...HEAD --shortstat
            git diff <base>...HEAD --numstat | awk '{{split($3,a,"/"); k=a[1]"/"a[2]; add[k]+=$1; n[k]++}} END {{for (i in add) printf "%7d ins %4d files  %s\\n", add[i], n[i], i}}' | sort -rn
            ```

            In Mode 2, measure the PR, not your checkout. Your copy of its base branch can be
            stale or missing (a fork's, say), so ask GitHub instead:

            ```
            gh pr view <number> --json changedFiles,additions,deletions,commits --jq '{{changedFiles, additions, deletions, commits: (.commits | length)}}'
            gh pr view <number> --json files --jq '.files[] | "\\(.additions)\\t\\(.deletions)\\t\\(.path)"' | awk '{{split($3,a,"/"); k=a[1]"/"a[2]; add[k]+=$1; n[k]++}} END {{for (i in add) printf "%7d ins %4d files  %s\\n", add[i], n[i], i}}' | sort -rn
            ```

            `changedFiles` is the true count. If the second lists fewer files, its breakdown is
            partial.

            **Check the base is what you think it is.** `git fetch` first and compare
            `git rev-parse main origin/main`. A stale local base silently inflates the diff
            with work that already merged — you end up reviewing other people's landed code
            and reporting it as this branch's. If they differ, say so and use the remote.

            Then choose by size:

            | Diff size | What to do |
            |---|---|
            | **under ~50 files** | Review it as one unit. This is the normal path. |
            | **50–150 files** | Still one unit, but lead with the second command above and review in descending order of insertions, so the largest surface gets your freshest attention. |
            | **over ~150 files, or over ~20 commits** | **Do not review it linearly.** Partition it, state the partitions up front, and review each as its own unit with its own verdict. {map_line} |

            When you partition, say so in the output — the reader needs to know whether they
            are holding one review or several, and which partition each finding came from.
            Carry Phase 0's results into every partition rather than re-running the build for
            each one.

            A diff this large is usually also a signal worth reporting on its own: it means the
            branch has outgrown reviewability, and that is a process finding, not a code one.

        """, map_line=map_line)

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
               accomplish? Read the PR description (Mode 2: the `body` fetched above; Mode 1: if
               the branch has an open PR, `gh pr view --json title,body`) and the commit messages
               (Mode 1: `git log main..HEAD`; Mode 2: `gh pr view <number> --json commits`).
               Understanding intent prevents false findings. But the
               description is the author's claim, not evidence: intent can explain a choice, and
               it never makes a defect or an unsafe change acceptable.

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
                    lines.append(f"### {name}\n")
                    lines.append(f"When reviewing {format_paths(paths)}:\n")
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
        """Universal areas, plus service and client sets behind an explicit gate.

        The block used to be one undifferentiated list introduced as the
        highest-value part of the review — and most of it assumed an HTTP service.
        A reviewer who is told that the most important questions are about response
        envelopes, while reviewing an on-device app with no network surface, learns
        to skip the section. Gating the inapplicable sets is what makes the
        applicable ones credible.
        """
        if not cross_cutting:
            return ""

        def render(areas: list) -> list[str]:
            out = []
            for area in areas:
                desc = area["description"].strip().replace("\n", " ")
                why = area.get("why", "").strip().replace("\n", " ")
                out.append(f"- **{area['area']}**: {desc} *(Lens: {area['lens']})*")
                if why:
                    out.append(f"  - *Why this matters*: {why}")
                out.append("")
            return out

        # Back-compatible with the old flat shape.
        if "focus_areas" in cross_cutting:
            cross_cutting = {"universal": cross_cutting}

        universal = cross_cutting.get("universal", {}).get("focus_areas", [])
        if not universal and not any(k in cross_cutting for k in ("service", "client")):
            return ""

        lines = [textwrap.dedent("""\
            ## Cross-Cutting Review

            These catch what platform checklists miss: inconsistencies between code paths,
            guarantees that do not guarantee, and assumptions that only surface under
            unexpected use.

            The universal set applies to every review. The two sets after it are gated —
            read the gate first and skip the whole set when it does not apply. Forcing a
            question about response envelopes onto an on-device app produces noise, and a
            section that produces noise is a section reviewers learn to skim.

        """)]

        if universal:
            lines.append("### Universal — apply to every review\n")
            lines.extend(render(universal))

        for key, heading in (("service", "Services and multi-user components"),
                             ("client", "Client applications")):
            group = cross_cutting.get(key)
            if not group or not group.get("focus_areas"):
                continue
            gate = group.get("applies_when", "").strip().replace("\n", " ")
            lines.append(f"### {heading} — conditional\n")
            if gate:
                lines.append(f"**Applies when:** {gate}\n")
            lines.extend(render(group["focus_areas"]))

        return "\n".join(lines)

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
            "documented-claim": ("Correctness, Maintainability", "Does the document match the code it describes? Check the direction that matters: every implemented behaviour documented, not just every documented behaviour implemented"),
        }

        lines.append("| Change Type | Detected By | Increased Scrutiny |")
        lines.append("|---|---|---|")
        for ct, patterns in all_signals.items():
            # Every pattern, not the first four. This table exists to be matched
            # against a diff; a truncated list is a silent miss, and truncating
            # an alphabetically sorted list drops whichever patterns happen to
            # sort late — which is how `Info.plist` and `pyproject.toml` fell off.
            pattern_str = ", ".join(f"`{p}`" for p in patterns)
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

            Follow it with the Check Performance section (below) and nothing else: no empty
            sections, no filler. A clean review is valuable.

            ### When issues are found:

            ```
            ## Principal Engineer Code Review

            **PR:** #<number> — <title>  (omit for Mode 1 and 3)
            **Verdict:** APPROVE / APPROVE with concerns / DISCUSS / REQUEST CHANGES
            **Findings:** N total (X ISSUE, Y CONCERN; Z reported with no check behind them)
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
            - **Check:** <the id of the pre-flight check that led you here, or `none`>
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

            ### Check Performance

            Always include this section, even on a clean review. It is how the checklists get
            better: a check nobody can see misfiring stays wrong forever. Be blunt — this
            section is graded on honesty, not on making the tooling look good.

            **False positives** — checks that fired on code they did not actually apply to:

            | Check | Fired on | Why it did not apply |
            |---|---|---|
            | <check id> | <file:line, or "6 sites"> | <the specific reason> |

            **Inert** — checks whose platform was detected but which had no applicable code in
            this diff at all. List the check ids or, where a whole block was inert, the block
            name and the reason (e.g. "the module abstracts this framework behind a protocol,
            so its vocabulary never appears").

            **Unnamed** — findings you reported with `Check: none`. For each, say in one line
            what a check that WOULD have caught it should look for. These are the highest-value
            additions to the guidance, because they are defects the checklist is currently blind to.

            **GitHub issues are opt-in.** Do NOT auto-file GitHub issues for findings.
            Only create issues if the user explicitly asks (e.g., `/vld8-review 123 --file-issues`).

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

        if service_map is None:
            components_line = (
                "**No service map was available when this skill was generated.** Before tracing "
                "flows, inventory the deployable components yourself (entry points, manifests, "
                "IaC, CI pipelines), or run `/vld8-map` and reinstall with `--force`."
            )
            scale_note = (
                "Size the work from that inventory: one agent for a handful of components; for a "
                "large repo, dispatch sub-agents, one per investigation area."
            )
        elif component_count <= 20:
            components_line = f"**Repo has {component_count} reviewable components.**"
            scale_note = (
                "**Small repo (≤20 components): Single-agent deep review.** Read the service map, "
                "then read source files as needed to trace flows. You have enough context. "
                "Prioritize depth on the most complex and highest-risk areas."
            )
        else:
            components_line = f"**Repo has {component_count} reviewable components.**"
            scale_note = (
                "**Large repo (>20 components): Use sub-agents.** Dispatch sub-agents using the "
                "Agent tool — one per investigation area. Each sub-agent gets a fresh context and "
                "reads only the files relevant to its investigation. Collect findings, then synthesize."
            )
        flow_heading = "**Most-connected components (start here):**" if flow_hints else ""
        return _render("""\
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

            {components_line}

            {scale_note}

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

            {flow_heading}
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

        """, component_count=component_count, components_line=components_line, flow_heading=flow_heading, flow_hints=flow_hints, scale_note=scale_note)

    def _help_section(self) -> str:
        return textwrap.dedent("""\
            ## Help (--help)

            If the argument is `--help`, output this summary and stop:

            ```
            /vld8-review — Principal Engineer peer code review

            MODES:
              /vld8-review              Review current branch diff vs main (~2 min)
              /vld8-review 123          Review PR #123, post findings as comment (~5 min)
              /vld8-review <component>  Full review of a service/app by name (~5 min)
              /vld8-review --deep       Deep repo-wide review across all components (~20 min)
              /vld8-review --help       Show this help

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
        return _render("""\
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
        """, known_list=known_list)


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
    parser.add_argument("--output", "-o", default=".claude/commands/vld8-review.md",
                        help="Output path relative to repo root (default: .claude/commands/vld8-review.md)")
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
                        help="Overwrite existing vld8-review.md without prompting")

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
    verification = guidance.pop("verification", None)
    if cross_cutting:
        # Grouped layout (universal / service / client), or the legacy flat list.
        groups = [cross_cutting] if "focus_areas" in cross_cutting else cross_cutting.values()
        cc_count = sum(len(g.get("focus_areas", [])) for g in groups if isinstance(g, dict))
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
    skill_content = generator.generate(detected, component_paths, all_known, service_map,
                                       cross_cutting, verification)

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
    print(f"\nUsage: /vld8-review (from Claude Code in the target repo)")


if __name__ == "__main__":
    main()
