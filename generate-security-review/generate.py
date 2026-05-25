#!/usr/bin/env python3
"""
Security Review Skill Generator

Scans a repository (and optionally consumes a servicemap.json) to generate a
tailored .claude/commands/scrutineer-security.md with platform-specific vulnerability
checklists.

The generated skill supports four invocation modes:
  /scrutineer-security                  — review current branch diff vs main
  /scrutineer-security 123              — review PR #123 (git fetch + diff)
  /scrutineer-security <component-name> — full security review of a service/app from the service map
  /scrutineer-security --deep           — deep repo-wide audit across services

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
# Repo Analyzer
# ---------------------------------------------------------------------------

class RepoAnalyzer:
    """Scans a repository to detect languages, frameworks, and infrastructure."""

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

    def file_contains(self, pattern: str, extensions: list[str] | None = None,
                      max_files: int = 50, max_bytes: int = 50_000) -> bool:
        regex = re.compile(pattern, re.MULTILINE)
        count = 0
        for f in self.file_index:
            if extensions and f.suffix not in extensions:
                continue
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

    def map_component_paths(self, detected: dict[str, dict]) -> dict[str, list[str]]:
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
    """Reads servicemap.json for richer context."""

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

    def get_unauthenticated_endpoints(self) -> list[dict]:
        """Endpoints flagged as public with no auth — useful for the universal checklist."""
        return self.data.get("metadata", {}).get("unauthenticated_public_endpoints", [])

    def get_shared_datastores(self) -> list[str]:
        """Datastore IDs flagged as shared — multi-tenant risk signal."""
        return self.data.get("metadata", {}).get("shared_datastores", [])


# ---------------------------------------------------------------------------
# Skill Generator
# ---------------------------------------------------------------------------

class SkillGenerator:
    """Generates the scrutineer-security.md skill file."""

    def generate(self, detected: dict[str, dict],
                 component_paths: dict[str, list[str]],
                 all_known_platforms: list[str],
                 service_map: ServiceMapLoader | None = None) -> str:
        sections = [
            self._header(),
            self._help_section(),
            self._invocation_section(service_map),
            self._process_section(detected, component_paths),
            self._threat_model_section(),
            self._severity_section(),
            self._universal_checklist(service_map),
        ]

        by_category: dict[str, list[tuple[str, dict]]] = {}
        for key, data in detected.items():
            cat = data["_category"]
            by_category.setdefault(cat, []).append((key, data))

        for category, platforms in by_category.items():
            for platform_key, platform_data in platforms:
                sections.append(self._platform_checklist(
                    platform_key, platform_data, component_paths.get(platform_key, [])
                ))

        sections.append(self._agentic_security_analysis())
        sections.append(self._false_positive_filtering(detected))
        sections.append(self._output_format())
        sections.append(self._deep_review_section(service_map))
        sections.append(self._self_heal_section(all_known_platforms))

        return "\n".join(sections)

    def _header(self) -> str:
        return textwrap.dedent("""\
            Perform a security review focused on finding exploitable vulnerabilities,
            data exposure risks, and security misconfigurations. This is NOT a code quality
            review — focus exclusively on security impact.

            You are an AGENT, not a scanner. A scanner matches patterns — you think like an
            attacker. The checklists below are recon tools to orient your investigation. Your
            highest-value findings will come from tracing trust boundaries, chaining low-severity
            issues into real exploits, and finding the authentication/authorization gaps that
            pattern matching can't see.

        """)

    def _invocation_section(self, service_map: ServiceMapLoader | None) -> str:
        lines = [textwrap.dedent("""\
            ## Invocation Modes

            This skill supports three modes based on the argument:

            ### Mode 1: Current Branch Diff (no arguments)
            ```
            /scrutineer-security
            ```
            Reviews the current branch's security-relevant changes against main. Runs `git diff main...HEAD`.

            ### Mode 2: PR Review (numeric argument)
            ```
            /scrutineer-security 123
            ```
            Reviews PR #123 for security issues. Process:
            1. `git fetch origin`
            2. Get PR metadata: `gh pr view 123 --json number,title,headRefName,baseRefName`
            3. Get full diff: `gh pr diff 123`
            4. Review the diff for security issues.
            5. Output findings (does not auto-post to PR — security findings may be sensitive).

            ### Mode 3: Full Service/App Security Audit (component name argument)
            ```
            /scrutineer-security <component-name>
            ```
            Full security audit of all code in a service or app directory. This is for
            comprehensive security reviews — not just a diff, but the entire attack surface.

            Process:
            1. Identify the component directory from the table below.
            2. Read all source files in that directory.
            3. Map the component's endpoints, auth mechanisms, and data flows.
            4. Apply universal and platform-specific checklists against all code.
            5. Report findings with the same severity classification.

            ### Mode 4: Deep Repo Security Audit (--deep flag)
            ```
            /scrutineer-security --deep
            ```
            Full repository-level security audit that traces trust boundaries across services,
            audits auth boundaries end-to-end, traces secrets from storage through infrastructure
            to runtime, and chains low-severity findings into exploit paths. This is the most
            thorough mode — it finds cross-service authorization gaps, secret exposure across
            layers, and attack chains that per-component reviews miss.
        """)]

        if service_map:
            reviewable = service_map.get_reviewable_components()
            if reviewable:
                lines.append("\n**Available components for full security audit:**\n")
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
            - `--deep` → **Mode 4** (deep repo security audit)
            - Anything else → **Mode 3** (component name lookup)

        """))
        return "\n".join(lines)

    def _process_section(self, detected: dict, component_paths: dict) -> str:
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
            4. **Build a threat model** — before checking anything, map the attack surface (see below)
            5. **Run the universal checklist** — use as investigation prompts, not grep patterns
            6. **Run platform-specific checklists** — each match is a starting point; trace it
            7. **Agentic security analysis** — trace data flows, audit auth boundaries, chain findings, detect absences (see below)
            8. **Classify findings** by severity, considering blast radius from your threat model
            9. **False positive filtering** — apply hard exclusions and precedent rules, assign confidence scores, discard findings below threshold (see below)
            10. **Self-heal check** — if the code touches platforms not covered by any checklist, flag them

        """)

    def _threat_model_section(self) -> str:
        return textwrap.dedent("""\
            ## Phase 0: Build a Threat Model

            Before running any checklist, build a threat model for the code under review.
            This determines whether a finding is CRITICAL or LOW — context is everything.

            1. **Map the attack surface**: What endpoints are public? What accepts user input?
               What reads from or writes to external systems? What handles secrets?
            2. **Identify trust boundaries**: Where does trusted code call untrusted code (or
               receive untrusted data)? Where do privilege levels change? Where does data cross
               from one service to another?
            3. **Determine blast radius**: If an attacker exploits a vulnerability here, what
               can they access? One user's data? All users' data? Internal services? The
               database? Cloud credentials?
            4. **Note the auth model**: How is the caller authenticated? How is authorization
               enforced? Is it enforced here or delegated to a downstream service?

            Carry this model through the rest of the review. A SQL injection in an internal
            service behind auth is HIGH. The same injection in a public endpoint is CRITICAL.

        """)

    def _severity_section(self) -> str:
        return textwrap.dedent("""\
            ## Severity Levels

            - **CRITICAL** — exploitable now, must fix before merge
            - **HIGH** — likely exploitable, should fix before merge
            - **MEDIUM** — potential risk, fix recommended
            - **LOW** — defense-in-depth improvement, can defer
            - **INFO** — observation, no action needed

        """)

    def _universal_checklist(self, service_map: ServiceMapLoader | None) -> str:
        lines = [textwrap.dedent("""\
            ## Universal Checklist (all platforms)

            Use these as investigation prompts, not a grep list. For each area, actively
            look for the concern — don't just check if a pattern exists.

            - Authentication/authorization (JWT handling, session management, auth checks)
            - Injection vectors (SQL, command, XSS, template injection)
            - Secrets handling (API keys, tokens, credentials in code or config — never committed)
            - Network calls (SSRF, unvalidated URLs, missing TLS)
            - Cryptography (weak algorithms, hardcoded keys, missing encryption)
            - Access control (missing ownership checks, privilege escalation, IDOR)
            - Rate limiting (missing or bypassed)
            - Dependencies (new deps with known CVEs)
            - Error messages leaking internals (stack traces, SQL errors, internal URLs)
        """)]

        # Enrich with service map data if available
        if service_map:
            unauth = service_map.get_unauthenticated_endpoints()
            shared = service_map.get_shared_datastores()

            if unauth:
                lines.append("\n### Known Unauthenticated Endpoints (from service map)\n")
                lines.append("These endpoints are intentionally public — verify any new unauthenticated "
                             "endpoints are intentional and rate-limited:\n")
                for ep in unauth:
                    lines.append(f"- `{ep.get('component', '')}`: `{ep.get('endpoint', '')}`")
                lines.append("")

            if shared:
                lines.append("\n### Shared Datastores (from service map)\n")
                lines.append("These datastores are accessed by multiple services — pay extra attention "
                             "to tenant scoping and access control on queries touching them:\n")
                for ds_id in shared:
                    lines.append(f"- `{ds_id}`")
                lines.append("")

        lines.append("")
        return "\n".join(lines)

    def _platform_checklist(self, key: str, data: dict, paths: list[str]) -> str:
        name = data["name"]
        checklist_items = data.get("checklist", [])

        if paths:
            path_str = "`, `".join(paths[:5])
            trigger = f"When reviewing `{path_str}`:"
        else:
            trigger = f"When reviewing {name}-related code:"

        lines = [f"## {name} Checklist\n"]
        lines.append(f"{trigger}")
        lines.append("Each item is a starting point — when you find a match, investigate: is it reachable? What's the blast radius? Are there other instances?\n")

        for item in checklist_items:
            lines.append(f"- **{item['title']}**: {item['pattern']}")
            lines.append(f"  - *Fix*: {item['secure_alternative']}")
            lines.append(f"  - *OWASP*: {item['owasp']} | *Default severity*: {item['severity_if_found']}")
            lines.append("")

        return "\n".join(lines) + "\n"

    def _agentic_security_analysis(self) -> str:
        return textwrap.dedent("""\
            ## Agentic Security Analysis

            The checklists above are your recon pass. This section is the real assessment.
            These are active investigations that require reasoning about the code — not
            pattern matching.

            ### Trace Every Input

            For every endpoint that accepts user input (path params, query params, headers,
            request body):
            1. Trace the input through the handler — where does it go?
               - Into a database query? → injection risk
               - Into an HTTP client URL? → SSRF risk
               - Into a response body? → reflection/XSS risk
               - Into log statements? → PII exposure risk
               - Forwarded to another service? → passthrough-without-validation risk
            2. Is validation applied at THIS boundary, or delegated downstream?
            3. What happens if the input is: empty? extremely long? contains special
               characters? is the wrong type? contains null bytes?

            Focus your tracing on: IDs (IDOR), strings that become queries, URLs that
            become HTTP calls, and any value that crosses a trust boundary.

            ### Audit Auth Boundaries

            For every endpoint:
            1. What authentication is required? Trace the middleware chain.
            2. What authorization is checked? (Ownership, role, scope)
            3. Could a valid authenticated user access data they shouldn't?
               (Authenticated ≠ authorized)
            4. Are there endpoints that SHOULD require auth but don't?
            5. For Mode 3 (full audit): compare the set of authenticated vs
               unauthenticated endpoints — is the split intentional?

            ### Consistency Audit (Security Guards)

            For every security guard you find (auth middleware, rate limit, input
            validation, CSRF check):
            1. Find ALL code paths to the same protected resource
            2. Does every path have the same guard?
            3. Can the guard be bypassed via a different endpoint, a different
               HTTP method, or a different parameter encoding?

            ### Attack Chain Reasoning

            After finding individual issues, consider how they combine:
            - Could a LOW-severity info leak (error message reveals internal URL) +
              a LOW-severity SSRF (unvalidated URL param) chain into HIGH-severity
              internal network access?
            - Could a MEDIUM-severity auth gap on one endpoint provide data that
              enables exploiting a different endpoint?
            - Could a race condition between two requests produce a state that
              bypasses an authorization check?

            Report attack chains as separate findings with their combined severity.
            A chain of two MEDIUM findings that together produce a real exploit is HIGH.

            ### What's NOT There

            Security bugs are often about missing code:
            - Endpoint with no rate limit → DoS / brute force
            - State change with no audit log → undetectable abuse
            - API key with no rotation mechanism → permanent compromise on leak
            - Error path with no cleanup → resource in inconsistent state
            - New endpoint with no auth middleware → unauthenticated access

            For each missing control, assess: what's the worst case if an attacker
            notices this gap?

        """)

    def _false_positive_filtering(self, detected: dict) -> str:
        # Build platform-aware precedent rules
        platform_keys = set(detected.keys())

        memory_safe_langs = []
        if "rust" in platform_keys:
            memory_safe_langs.append("Rust")
        if "go" in platform_keys:
            memory_safe_langs.append("Go")
        if "java" in platform_keys or "kotlin" in platform_keys:
            memory_safe_langs.append("Java/Kotlin")
        if "swift" in platform_keys:
            memory_safe_langs.append("Swift")
        if "csharp" in platform_keys:
            memory_safe_langs.append("C#")

        memory_safe_note = ""
        if memory_safe_langs:
            langs = ", ".join(memory_safe_langs)
            memory_safe_note = (
                f"\n- **Memory safety issues are not applicable to {langs}.** "
                "Do not report buffer overflows, use-after-free, or similar memory "
                "safety issues in memory-safe languages."
            )

        xss_safe_frameworks = []
        if "react" in platform_keys or "nextjs" in platform_keys:
            xss_safe_frameworks.append("React/Next.js")
        if "vue" in platform_keys or "nuxt" in platform_keys:
            xss_safe_frameworks.append("Vue/Nuxt")

        xss_safe_note = ""
        if xss_safe_frameworks:
            fws = ", ".join(xss_safe_frameworks)
            xss_safe_note = (
                f"\n- **{fws} are generally safe against XSS.** Do not report XSS "
                "in these frameworks unless the code uses `dangerouslySetInnerHTML`, "
                "`v-html`, or similar explicit escape hatches."
            )

        client_side_note = ""
        if any(k in platform_keys for k in ("react", "nextjs", "vue", "nuxt", "nodejs")):
            client_side_note = (
                "\n- **Client-side JS/TS code does not need permission checks or auth.** "
                "Client-side code is untrusted — the server is responsible for validation "
                "and authorization. Do not report missing auth in frontend code."
            )

        return textwrap.dedent(f"""\
            ## False Positive Filtering

            A security review that floods the report with noise is worse than no review.
            Every finding must clear two gates: (1) it is not excluded by the rules below,
            and (2) it has a concrete, exploitable attack path with confidence ≥ 0.8.

            ### Hard Exclusions — Automatically Discard

            Do NOT report findings that match any of these patterns, regardless of severity:

            1. **Denial of Service (DoS)** — resource exhaustion, memory consumption, CPU
               exhaustion, regex DoS, rate limiting gaps. These are operational concerns,
               not security vulnerabilities in this context.
            2. **Secrets stored on disk** — credentials in config files or env-file templates
               are handled by other processes (secret scanning, pre-commit hooks). Only
               report secrets hardcoded in source code that bypass these controls.
            3. **Outdated dependencies** — vulnerable transitive deps are managed by
               dependency scanning tools (Dependabot, Grype, OSV). Do not duplicate.
            4. **Test-only code** — files that are exclusively unit tests, test fixtures,
               or test utilities. Vulnerabilities in test code are not exploitable.
            5. **Documentation files** — markdown, RST, or other docs. Insecure examples
               in documentation are not vulnerabilities.
            6. **Log spoofing** — outputting unsanitized user input to logs is not a
               vulnerability unless it logs secrets or PII.
            7. **Missing hardening measures** — the absence of a security best practice
               is not a vulnerability. Only report concrete, exploitable weaknesses.
            8. **Theoretical race conditions** — only report race conditions with a
               concrete exploitation path and real impact, not theoretical timing windows.
            9. **SSRF with path-only control** — SSRF is only reportable if the attacker
               can control the host or protocol, not just the path.
            10. **AI prompt injection** — including user-controlled content in AI system
                prompts is not a vulnerability in this context.
            11. **Regex injection** — injecting untrusted content into a regex pattern is
                not a vulnerability.
            12. **Missing audit logs** — absence of logging is an operational gap, not a
                security vulnerability.{memory_safe_note}{xss_safe_note}{client_side_note}

            ### Precedent Rules — Calibrate Severity

            Apply these calibrations before scoring confidence:

            - **Environment variables and CLI flags are trusted values.** Attacks that
              require controlling an env var or CLI arg are invalid in a secure environment.
            - **UUIDs are unguessable.** Do not flag missing UUID validation as an IDOR risk.
            - **Logging URLs is safe.** Only flag logging of secrets, passwords, tokens, or PII.
            - **GitHub Actions workflow vulns require concrete untrusted input paths.** Most
              workflow injection scenarios are not exploitable in practice — only report with
              a specific, demonstrated attack path.
            - **Shell script command injection requires untrusted input.** Shell scripts
              generally run with trusted input — only report if untrusted user input
              reaches a shell command with a concrete path.
            - **Jupyter notebook vulns require concrete untrusted input.** Most notebook
              code runs in trusted local environments.
            - **Subtle web vulns need high confidence.** Tabnabbing, XS-Leaks, prototype
              pollution, and open redirects should only be reported at confidence ≥ 0.9
              with a clear exploitation path.
            - **Non-PII data in logs is not a finding.** Only report logging vulns when
              secrets, passwords, or personally identifiable information are exposed.
            - **Local network exploitability is still valid.** A vulnerability exploitable
              only from the local network can still be HIGH severity.

            ### Confidence Scoring

            Every finding MUST include a confidence score:

            - **0.9–1.0**: Certain exploit path — you can describe exact steps to exploit
            - **0.8–0.9**: Clear vulnerability pattern with known exploitation methods
            - **0.7–0.8**: Suspicious pattern requiring specific conditions to exploit
            - **Below 0.7**: Do not report — too speculative

            **Discard all findings with confidence below 0.8.**

            Only report HIGH and MEDIUM severity findings. A focused report with 3 real
            findings is infinitely more valuable than a report with 20 speculative ones.

            ### Multi-Pass Verification (Mode 1 and 2 only)

            For branch diff and PR review modes, use a two-pass approach:

            1. **Pass 1 — Discovery**: Identify all candidate findings using checklists
               and agentic analysis. Cast a wide net.
            2. **Pass 2 — Verification**: For each candidate, independently verify:
               - Is it excluded by the hard exclusions above?
               - Does it have a concrete, step-by-step exploit path?
               - What is the confidence score after applying precedent rules?
               - Would a security engineer confidently raise this in a PR review?
            3. **Threshold**: Only findings that survive Pass 2 with confidence ≥ 0.8
               appear in the final report.

        """)

    def _output_format(self) -> str:
        return textwrap.dedent("""\
            ## Output Format

            **Verdict and summary go first.** The reader wants the answer before the details.

            **Only report HIGH and MEDIUM findings.** LOW and INFO are excluded by the false
            positive filtering rules. If no findings survive filtering, say so cleanly.

            ### When no findings survive filtering:

            ```
            ## Security Review — `<branch-name or component-name>`

            **Verdict: PASS** — no security-relevant findings.
            ```

            That's it. Do not produce empty sections or filler.

            ### When findings exist:

            ```
            ## Security Review — `<branch-name or component-name>`

            **Verdict:** PASS / BLOCK
            **Findings:** N total (X CRITICAL, Y HIGH, Z MEDIUM)

            ### Summary

            <1-2 sentences: what was reviewed, overall security posture assessment>

            ### Vuln 1: <category_slug> — `path/to/file:42`

            * **Severity:** HIGH (0.9)
            * **Description:** <one sentence — what the vulnerability is>
            * **Exploit scenario:** <concrete steps an attacker would take to exploit this>
            * **Recommendation:** <how to fix, with code snippet if helpful>

            ### Vuln 2: <category_slug> — `path/to/file:87`

            ...

            ### Severity Summary

            | Severity | Count |
            |----------|-------|
            | CRITICAL | N     |
            | HIGH     | N     |
            | MEDIUM   | N     |
            ```

            **Category slugs** should be specific and machine-parseable: `sql_injection`,
            `xss_reflected`, `auth_bypass`, `idor`, `ssrf`, `command_injection`,
            `hardcoded_secret`, `jwt_validation`, `path_traversal`, `deserialization`,
            `privilege_escalation`, `missing_auth`, `csrf`, `open_redirect`, etc.

            **Note:** For Mode 2 (PR review), do NOT auto-post findings as a PR comment —
            security findings may contain sensitive details. Output to terminal only and
            let the user decide whether to share.

        """)

    def _help_section(self) -> str:
        return textwrap.dedent("""\
            ## Help (--help)

            If the argument is `--help`, output this summary and stop:

            ```
            /scrutineer-security — Security-focused code review

            MODES:
              /scrutineer-security              Review current branch diff vs main (~2 min)
              /scrutineer-security 123          Review PR #123 for security issues (~5 min)
              /scrutineer-security <component>  Full security audit of a service/app (~5 min)
              /scrutineer-security --deep       Deep repo-wide security audit (~20 min)
              /scrutineer-security --help       Show this help

            WHAT IT DOES:
              Modes 1-3: Threat model → checklist scan → agentic analysis (input tracing,
                         auth boundary audit, consistency audit, attack chain reasoning)
              Mode 4:    All of the above PLUS cross-service trust boundary mapping,
                         secret lifecycle audit, and multi-service attack chain analysis

            SEVERITY:
              CRITICAL — exploitable now, must fix before merge
              HIGH     — likely exploitable, should fix before merge
              MEDIUM   — potential risk, fix recommended
              LOW      — defense-in-depth improvement
              INFO     — observation, no action needed

            VERDICTS:
              PASS  — safe to merge (no CRITICAL/HIGH findings)
              BLOCK — must fix CRITICAL/HIGH findings first

            OUTPUT:
              All modes output to terminal (security findings may be sensitive —
              not auto-posted to PRs)
            ```

        """)

    def _deep_review_section(self, service_map: ServiceMapLoader | None) -> str:
        component_count = 0
        if service_map:
            component_count = len(service_map.get_reviewable_components())

        return textwrap.dedent(f"""\
            ## Mode 4: Deep Repo Security Audit

            **Role:** You are a world-class Security Auditor performing a comprehensive security
            assessment of this entire repository. Think like an attacker who has been given the
            source code and unlimited time. Your job is to find every way in — from the public
            API to the infrastructure layer, from the mobile app to the database, from the CI
            pipeline to the secret store. Evaluate as if this is a pre-launch security audit
            where the findings determine whether the system goes live.

            **Scope:** EVERYTHING. Backend services, mobile apps, web apps, infrastructure as
            code, CI/CD pipelines, secret management, IAM policies, network configuration.
            No layer is out of scope. The investigations below are starting points — if you
            find a thread worth pulling, follow it. Your best findings will come from chaining
            multiple low-severity issues into real exploit paths.

            ### Adaptive Execution Strategy

            **Repo has {component_count} reviewable components.**

            {"**Small repo (≤20 components): Single-agent deep audit.** Read the service map, then read source files as needed. Prioritize depth on auth boundaries, secret handling, and the highest-risk data flows." if component_count <= 20 else "**Large repo (>20 components): Use sub-agents.** Dispatch sub-agents using the Agent tool — one per investigation area. Each sub-agent gets a fresh context. Collect findings, then synthesize and chain."}

            ### Investigation 1: Trust Boundary Mapping

            Trace every trust boundary in the system. Read the actual auth middleware, not just
            config. For each boundary:
            - Client → API gateway: How is the user authenticated? JWT? Cookie? API key?
              Are issuer/audience claims validated? Can tokens from one app be used in another?
            - API gateway → Internal services: What authenticates internal calls? Is it a
              shared secret or per-service? Is the comparison timing-safe?
            - Internal services → Database: Is tenant scoping at query level, RLS, or both?
              What happens if a query accidentally omits the tenant filter?
            - Services → External APIs: How are API keys/secrets delivered? Rotated?

            For each boundary: If breached, what's the blast radius? Map it.

            ### Investigation 2: Cross-Service Authorization Audit

            Build an authorization matrix. For EVERY endpoint across ALL services:
            - Is it authenticated? By what mechanism?
            - Is it authorized? Does it verify the caller owns the target resource?
            - Are destructive operations (merge/purge/delete) on an admin router or regular API?
            - Could a valid authenticated user access OTHER users' data? (authenticated ≠ authorized)
            - Are there defense-in-depth ownership checks? Do they fail OPEN (skip on missing
              header) or fail CLOSED (reject on missing header)?

            ### Investigation 3: Secret Lifecycle Audit

            Trace EVERY secret from rest to runtime. Read the Terraform task definitions:
            - Is each secret delivered as a `secrets` reference or a plain `environment_variable`?
            - Are secrets visible in `DescribeTaskDefinition` API output?
            - Are secrets logged in error messages, debug output, or audit logs?
            - Are secrets hardcoded in source, config files, CI workflows, or Dockerfiles?
            - Are CI/CD GitHub Actions pinned to SHA or mutable version tags?
            - Are IAM policies scoped to specific resources or using `Resource: *`?
            - Is MFA required for high-privilege access (admin portal, AWS console)?

            ### Investigation 4: Mobile & Client Security

            For EVERY mobile app and web client:
            - **Token storage**: Keychain/EncryptedSharedPreferences, or plaintext?
            - **Certificate pinning**: Configured for production domains? Or only dev?
            - **Deep link handling**: Are parameters validated? Could a crafted link bypass auth?
            - **Background screenshot**: Is PII masked when app enters background?
            - **Logout completeness**: Are tokens revoked? Is local data cleared? Including
              databases, caches, push notification tokens?
            - **PII in logs**: Are error messages sanitized? Are debug logs compiled out of release?

            ### Investigation 5: Attack Chain Analysis

            This is where you earn your keep. Combine findings from Investigations 1-4:
            - "If an attacker obtains X, they can reach Y, which gives them Z"
            - Chain multiple LOW findings into HIGH exploit paths
            - Consider: stolen device, compromised BFF, leaked internal secret, rogue admin,
              prompt injection → data pollution → trust exploitation
            - For each chain: what's the precondition, what's the exploit, what's the impact?

            ### Investigation 6: Infrastructure & Deployment Security

            Review IaC and CI/CD:
            - **Networking**: Single points of failure? Public exposure of internal resources?
            - **Database**: Deletion protection? Encryption at rest and in transit? Backup retention?
            - **Containers**: Running as root? Base images pinned? Secrets in build layers?
            - **CI/CD**: Self-hosted runners on public repos? Secrets in logs? Unpinned actions?
            - **Deployment**: Can a bad deploy be rolled back? Are migrations reversible?

            ### Agentic Freedom

            The investigations above are a framework, not a cage. If you notice something
            suspicious — a pattern that doesn't make sense, a comment that says "TODO: fix
            security", a test that's suspiciously disabled — follow it. The most valuable
            security findings are often in the places nobody thought to look.

            ### Output for Mode 4

            Verdict first, then details. Omit sections with no findings.

            ```
            ## Deep Repository Security Audit

            **Verdict:** PASS / BLOCK
            **Findings:** N total (X CRITICAL, Y HIGH, Z MEDIUM)

            ### Threat Landscape
            <High-level security posture — 2-3 sentences>

            ### Trust Boundary Map
            <Visual: client → gateway → services → DB, with auth at each boundary>

            ### Critical Attack Chains
            <Multi-step exploit paths that combine findings — each as a numbered vuln
            with category slug, severity, confidence, exploit scenario, and fix>

            ### Authorization Matrix Gaps
            <Endpoints missing auth/authz, defense-in-depth failures>

            ### Secret Exposure Report
            <Table: secret | storage | delivery | logged? | rotated? | risk>

            ### Mobile & Client Security
            <Token storage, cert pinning, deep links, logout completeness>

            ### Infrastructure Gaps
            <Networking, IAM, CI/CD, deployment risks>

            ### Cross-Service Findings
            <Issues that span multiple components>

            ### Severity Summary
            | Severity | Count |
            |----------|-------|
            | CRITICAL | N     |
            | HIGH     | N     |
            | MEDIUM   | N     |
            ```

        """)

    def _self_heal_section(self, all_known_platforms: list[str]) -> str:
        known_list = ", ".join(sorted(all_known_platforms))
        return textwrap.dedent(f"""\
            ## Self-Healing: Unknown Platforms

            This skill was generated with checklists for a known set of platforms. If the code
            touches files from a platform or language NOT covered by the checklists above, do
            the following:

            **Known platforms at generation time:** {known_list}

            **When you encounter an unknown platform:**

            1. **Flag it immediately** in your review output:
               ```
               ⚠️  ENRICHMENT NEEDED: The review covers [platform/language] files, but this
               security review skill has no checklist for it. The following file patterns
               were detected but unrecognized:
               - [list of file extensions / paths]
               ```

            2. **Still review those files** using the Universal Checklist — don't skip them.

            3. **Offer to self-heal** by appending to this review:
               ```
               🔧 SELF-HEAL AVAILABLE: I can generate a platform-specific checklist for
               [platform/language] and add it to this security review skill. This will make
               future reviews of [platform] code more thorough.
               ```

            4. **If you have enough knowledge** to generate a good checklist on the spot
               (i.e., you know the platform's common security footguns), include a draft
               checklist in your review output under a "Draft Checklist" section. The user
               can then approve adding it to this skill file.

            ### What makes a good platform checklist (quality bar for self-healing)

            Every checklist item MUST:
            - Name a **specific API, function, or code pattern** — not generic advice
            - Describe both the **vulnerable pattern** AND the **secure alternative**
            - Cover **footguns unique to that platform** — things safe in other languages but dangerous here
            - Be a **single, scannable bullet** — not a paragraph
            - Include an OWASP category and default severity

            If you cannot meet this bar for a platform, say so — a missing checklist is
            better than a checklist full of generic "validate your input" noise.
        """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_guidance(guidance_path: Path) -> dict:
    with open(guidance_path) as f:
        return yaml.safe_load(f)


def get_all_platform_keys(guidance: dict) -> list[str]:
    keys = []
    for category in guidance.values():
        keys.extend(category.keys())
    return keys


def main():
    parser = argparse.ArgumentParser(
        description="Generate a tailored security review skill for a repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s /path/to/repo
              %(prog)s /path/to/repo --service-map servicemap.json
              %(prog)s /path/to/repo --dry-run
        """),
    )
    parser.add_argument("repo_path", help="Path to the repository to analyze")
    parser.add_argument("--output", "-o", default=".claude/commands/scrutineer-security.md",
                        help="Output path relative to repo root (default: .claude/commands/scrutineer-security.md)")
    sm_group = parser.add_mutually_exclusive_group()
    sm_group.add_argument("--service-map", "-s", default=None,
                          help="Path to servicemap.json for richer context. "
                               "If omitted, auto-discovered at <repo>/servicemap.json.")
    sm_group.add_argument("--no-service-map", action="store_true",
                          help="Disable service-map auto-discovery and run without one")
    parser.add_argument("--guidance", "-g", default=None,
                        help="Path to security guidance YAML (default: bundled security_guidance.yaml)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Print the generated skill to stdout without writing")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Overwrite existing scrutineer-security.md without prompting")

    args = parser.parse_args()

    # Load guidance
    guidance_path = Path(args.guidance) if args.guidance else Path(__file__).parent / "security_guidance.yaml"
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
            unauth = service_map.get_unauthenticated_endpoints()
            shared = service_map.get_shared_datastores()
            print(f"  {len(reviewable)} reviewable components")
            print(f"  {len(unauth)} known unauthenticated endpoints")
            print(f"  {len(shared)} shared datastores")
        else:
            print(f"Warning: service map not found at {sm_path}, proceeding without it")

    # Analyze repo
    repo_path = Path(args.repo_path).resolve()
    print(f"Analyzing repository: {repo_path}")
    analyzer = RepoAnalyzer(str(repo_path))
    print(f"Indexed {len(analyzer.file_index)} files")

    detected = analyzer.detect_platforms(guidance)
    if not detected:
        print("\nNo known platforms detected. The generated skill will only "
              "include the universal checklist.")
    else:
        print(f"\nDetected {len(detected)} platform(s):")
        for key, data in detected.items():
            count = len(data.get("checklist", []))
            print(f"  ✓ {data['name']:30s} ({count} checklist items)")

    component_paths = analyzer.map_component_paths(detected)
    all_known = get_all_platform_keys(guidance)

    # Generate
    generator = SkillGenerator()
    skill_content = generator.generate(detected, component_paths, all_known, service_map)

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

    checklist_count = sum(len(d.get("checklist", [])) for d in detected.values())
    print(f"\n✓ Generated security review skill at: {output_path}")
    print(f"  Platforms: {len(detected)}")
    print(f"  Checklist items: {checklist_count} platform-specific + 11 universal")
    if service_map:
        reviewable = service_map.get_reviewable_components()
        print(f"  Reviewable components: {len(reviewable)} (from service map)")
    print(f"\nUsage: /scrutineer-security (from Claude Code in the target repo)")


if __name__ == "__main__":
    main()
