#!/usr/bin/env python3
"""Tests for the budgeted context packet builder (``vld8/packet.py``).

Dependency-free (no pytest, no network, no sleeps): run from the repo root with

    python tests/test_prepare_packet.py
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vld8 import checks, findings, packet, report, trust  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond: object, detail: str = "") -> None:
    ok = bool(cond)
    _results.append((name, ok))
    if not ok and detail:
        print(f"DETAIL ({name}): {detail}", file=sys.stderr)


def _expect_error(
    name: str, fn: Any, *args: Any, needle: str = "", **kwargs: Any
) -> None:
    try:
        fn(*args, **kwargs)
        check(name, False)
    except packet.PacketError as exc:
        msg = str(exc)
        check(name, not needle or needle in msg)


def _git(cwd: Path, *args: str) -> str:
    env = trust._scrubbed_git_env()
    proc = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _init_git_repo(repo_dir: Path) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    _git(repo_dir, "init", "-q", "-b", "main")
    _git(repo_dir, "config", "user.email", "test@example.invalid")
    _git(repo_dir, "config", "user.name", "Test User")


def _commit_files(
    repo_dir: Path, files: dict[str, str | bytes], msg: str = "commit"
) -> str:
    for rel, content in files.items():
        dest = repo_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            dest.write_bytes(content)
        else:
            dest.write_text(content, encoding="utf-8")
    _git(repo_dir, "add", "-A")
    _git(repo_dir, "commit", "-qm", msg)
    return _git(repo_dir, "rev-parse", "HEAD")


def _make_code_finding(*, fp_seed: str = "one") -> dict[str, Any]:
    check_id = f"rules-{fp_seed}"
    return {
        "file": "app.py",
        "lineStart": 1,
        "lineEnd": 1,
        "quote": "x = 1",
        "lens": "code",
        "checkId": check_id,
        "claim": "Violation in test",
        "evidence": "matched rule",
        "severity": "ISSUE",
        "basis": "written rule",
        "blocking": True,
        "source": "code",
        "fingerprint": findings.compute_fingerprint(check_id, "x = 1"),
    }


def test_rules_discovery_and_trust_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-pkt-rules-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _init_git_repo(repo)
        base_oid = _commit_files(
            repo,
            {
                "CLAUDE.md": "Root CLAUDE rule\n",
                "AGENTS.md": "Root AGENTS rule\n",
                "services/CLAUDE.md": "Services CLAUDE rule\n",
                "services/api/CONTRIBUTING.md": "API CONTRIBUTING rule\n",
                "services/api/app.py": "x = 1\n",
                "other/CLAUDE.md": "Unchanged subtree rule\n",
                "other/ignored.py": "y = 1\n",
            },
            "base commit",
        )
        _git(repo, "checkout", "-qb", "pr-branch")
        _commit_files(
            repo,
            {
                "CLAUDE.md": "PR TAMPERED CLAUDE rule\n",
                "services/api/app.py": "x = 2\n",
            },
            "pr modifies CLAUDE.md",
        )

        # Symlinked nested rules file must be ignored cleanly.
        secret_outside = root / "secret.txt"
        secret_outside.write_text("TOP SECRET\n", encoding="utf-8")
        (repo / "services/api/AGENTS.md").symlink_to(secret_outside)

        entries, warns = packet.collect_rules_files(
            repo,
            changed_paths=["services/api/app.py", "services/api/other.py"],
            base_ref=base_oid,
            trusted=False,
        )
        paths_seen = [item["path"] for item in entries]
        check(
            "collect_rules_files reads canonical root + nested changed-path rules",
            paths_seen
            == [
                "CLAUDE.md",
                "AGENTS.md",
                "services/CLAUDE.md",
                "services/api/CONTRIBUTING.md",
            ]
            and entries[0]["content"] == "Root CLAUDE rule\n"
            and entries[0]["source"] == "base-ref"
            and entries[0]["ref"] == base_oid
            and not warns,
        )
        check(
            "unchanged subtrees and symlinked rules are excluded",
            "other/CLAUDE.md" not in paths_seen
            and "services/api/AGENTS.md" not in paths_seen,
        )

        # Working-tree mode refuses untrusted trees, allows trusted non-symlinks.
        untrusted_entries, untrusted_warns = packet.collect_rules_files(
            repo,
            changed_paths=["services/api/app.py"],
            base_ref=None,
            trusted=False,
        )
        check(
            "untrusted working tree skips rules files with warning",
            untrusted_entries == [] and any("untrusted" in w for w in untrusted_warns),
        )

        trusted_wt_entries, _ = packet.collect_rules_files(
            repo,
            changed_paths=["services/api/app.py"],
            base_ref=None,
            trusted=True,
        )
        check(
            "trusted working tree reads modified CLAUDE.md and skips outside symlink",
            trusted_wt_entries[0]["content"] == "PR TAMPERED CLAUDE rule\n"
            and "services/api/AGENTS.md"
            not in [item["path"] for item in trusted_wt_entries],
        )

        # Oversized rules files emit warning cleanly (both base-ref and worktree).
        big_oid = _commit_files(
            repo,
            {"ENGINEERING.md": "a" * 2048},
            "oversized engineering",
        )
        entries_big, warns_big = packet.collect_rules_files(
            repo,
            changed_paths=["services/api/app.py"],
            base_ref=big_oid,
            max_file_bytes=256,
        )
        check(
            "oversized base-ref rules file warns and skips cleanly",
            "ENGINEERING.md" not in [e["path"] for e in entries_big]
            and any("ENGINEERING.md" in w for w in warns_big),
        )
        entries_wt_big, warns_wt_big = packet.collect_rules_files(
            repo,
            changed_paths=["services/api/app.py"],
            base_ref=None,
            max_file_bytes=256,
        )
        check(
            "oversized working-tree rules file warns and skips cleanly",
            "ENGINEERING.md" not in [e["path"] for e in entries_wt_big]
            and any("ENGINEERING.md" in w and "exceeds max" in w for w in warns_wt_big),
        )

        # Validation guards.
        _expect_error(
            "collect_rules_files rejects path traversal",
            packet.collect_rules_files,
            repo,
            changed_paths=["../etc/passwd"],
        )
        _expect_error(
            "collect_rules_files rejects base_ref with colon",
            packet.collect_rules_files,
            repo,
            base_ref="HEAD:services",
        )
        _expect_error(
            "collect_rules_files rejects non-existent base_ref",
            packet.collect_rules_files,
            repo,
            base_ref="no-such-branch",
        )
        _expect_error(
            "collect_rules_files rejects non-bool trusted",
            packet.collect_rules_files,
            repo,
            trusted="true",  # type: ignore[arg-type]
        )
        _expect_error(
            "collect_rules_files rejects invalid max_file_bytes",
            packet.collect_rules_files,
            repo,
            max_file_bytes=0,
        )


def test_intent_sources_spec_pr_body_and_design_docs() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-pkt-intent-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _init_git_repo(repo)
        pr_oid = _commit_files(
            repo,
            {
                "README.md": "Not a design doc\n",
                "docs/plans/2026-11-25-feature.md": "Plan doc \x1b[31mred\x1b[0m\n",
                "SPEC.md": "In-repo spec\n",
                "src/main.py": "print('ok')\n",
            },
            "add design doc",
        )
        ext_spec = root / "external_spec.md"
        ext_spec.write_text("External spec requirement\n", encoding="utf-8")

        # Linked issue extraction ignores fenced code blocks, dupes, and self PR.
        linked = packet.extract_linked_issue_numbers(
            "Fixes #56, relates to #52 and #56.\n"
            "```python\n#999 inside code block\n```\n"
            "See also #127 and self #404 plus section #12-heading.",
            exclude_number=404,
        )
        check(
            "extract_linked_issue_numbers extracts sorted unique issue refs",
            linked == [52, 56, 127],
        )
        check(
            "is_design_doc_path identifies plans/ADRs/specs and excludes README/rules",
            packet.is_design_doc_path("docs/plans/a.md")
            and packet.is_design_doc_path("ADR-01.md")
            and not packet.is_design_doc_path("README.md")
            and not packet.is_design_doc_path("CLAUDE.md"),
        )

        # Work without any intent sources.
        empty_intent, empty_links, empty_warns = packet.collect_intent_sources(
            repo, changed_paths=["README.md", "src/main.py"]
        )
        check(
            "collect_intent_sources works with no intent sources",
            empty_intent == [] and empty_links == [] and empty_warns == [],
        )

        # Untrusted PR cannot read an in-repo --spec, only external --spec.
        pr_untrusted = trust.PRMetadata(
            number=404,
            title="Fork change",
            body="Implements #56 and #999",
            url="https://github.com/org/repo/pull/404",
            author_login="bob",
            author_is_bot=False,
            head_ref_name="feat",
            head_ref_oid=pr_oid,
            base_ref_name="main",
            is_cross_repository=True,
            trusted=False,
            untrusted_reasons=("fork",),
        )
        _expect_error(
            "untrusted PR rejects in-repo --spec path",
            packet.collect_intent_sources,
            repo,
            spec_path=repo / "SPEC.md",
            trusted=False,
        )

        orig_run_git_or_gh = trust._run_git_or_gh

        def _fake_gh_issue(argv: list[str], **kwargs: Any) -> bytes:
            if argv[:2] != ["gh", "issue"]:
                return orig_run_git_or_gh(argv, **kwargs)
            if "56" in argv:
                return json.dumps(
                    {
                        "number": 56,
                        "title": "Optional intent \x1b[33msources\x1b[0m",
                        "body": "Accept --spec and PR body.",
                    }
                ).encode("utf-8")
            raise trust.TrustError("issue 999 not found")

        with mock.patch("vld8.trust._run_git_or_gh", side_effect=_fake_gh_issue):
            intent, links, i_warns = packet.collect_intent_sources(
                repo,
                spec_path=ext_spec,
                pr_meta=pr_untrusted,
                changed_paths=["README.md", "docs/plans/2026-11-25-feature.md"],
                target_ref=pr_oid,
                trusted=False,
                fetch_linked_issues=True,
            )

        kinds = [item["kind"] for item in intent]
        spec_entry = intent[0]
        doc_entry = next(x for x in intent if x["kind"] == "design-doc")
        issue_entry = next(x for x in intent if x["kind"] == "linked-issue")
        check(
            "collect_intent_sources collects spec, pr-body, design-doc, and issue",
            kinds == ["spec", "pr-body", "design-doc", "linked-issue"]
            and links == [56, 999]
            and spec_entry["path"] == "external_spec.md"
            and spec_entry["source"] == "external"
            and spec_entry["trustLevel"] == "trusted"
            and doc_entry["path"] == "docs/plans/2026-11-25-feature.md"
            and doc_entry["trustLevel"] == "untrusted"
            and "\x1b" not in doc_entry["content"]
            and "Accept --spec" in issue_entry["content"]
            and "\x1b" not in issue_entry["content"]
            and any("#999" in w for w in i_warns),
        )

        # Trusted repo reads in-repo --spec safely with repo-relative path.
        repo_intent, _, _ = packet.collect_intent_sources(
            repo,
            spec_path=repo / "SPEC.md",
            changed_paths=["docs/plans/missing-deleted.md"],
            target_ref=pr_oid,
            trusted=True,
        )
        check(
            "trusted repo reads repo --spec cleanly and skips deleted docs",
            len(repo_intent) == 1
            and repo_intent[0]["path"] == "SPEC.md"
            and repo_intent[0]["source"] == "repo",
        )


def test_evidence_budget_quoting_and_prepare_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-pkt-build-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _init_git_repo(repo)
        base_oid = _commit_files(
            repo,
            {
                "CLAUDE.md": "R" * 900,
                "src/app.py": "v = 1\n",
            },
            "base",
        )
        _git(repo, "checkout", "-qb", "feat")
        pr_oid = _commit_files(
            repo,
            {
                "docs/plans/spec-plan.md": "P" * 900,
                "src/app.py": "v = 2\n",
            },
            "pr",
        )
        tree_id = trust.compute_tree_id(repo, pr_oid)
        other_tree_id = trust.compute_tree_id(repo, base_oid)

        ev_good = root / "ev_good.json"
        f1 = _make_code_finding(fp_seed="a")
        f2 = _make_code_finding(fp_seed="b")
        ev_good.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": tree_id,
                    "tools": ["ruff"],
                    "exclusions": ["ruff:E501"],
                    "findings": [f1],
                }
            ),
            encoding="utf-8",
        )
        ev_sarif = root / "ev_sarif.sarif"
        ev_sarif.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "properties": {"treeId": tree_id},
                            "tool": {"driver": {"name": "semgrep"}},
                            "invocations": [{"executionSuccessful": True}],
                            "results": [
                                {
                                    "ruleId": "py.rule",
                                    "level": "warning",
                                    "message": {"text": "Found ```fence```"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        ev_good_dup = root / "ev_dup.json"
        ev_good_dup.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": tree_id,
                    "tools": ["ruff"],
                    "exclusions": ["ruff:E501", "ruff:F401"],
                    "findings": [f1, f2],
                }
            ),
            encoding="utf-8",
        )
        ev_stale = root / "ev_stale.json"
        ev_stale.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": other_tree_id,
                    "tools": ["bandit"],
                    "exclusions": ["bandit:B101"],
                    "findings": [_make_code_finding(fp_seed="stale")],
                }
            ),
            encoding="utf-8",
        )

        # Matching evidence merges without duplicate fingerprints; stale rejected.
        ev_summary, code_findings, ev_warns = packet.collect_evidence(
            [ev_good, ev_sarif, ev_good_dup, ev_stale],
            expected_tree_id=tree_id,
        )
        check(
            "collect_evidence merges matching evidence and isolates stale treeId",
            ev_summary["acceptedFiles"]
            == ["ev_good.json", "ev_sarif.sarif", "ev_dup.json"]
            and len(ev_summary["rejectedFiles"]) == 1
            and ev_summary["rejectedFiles"][0]["file"] == "ev_stale.json"
            and ev_summary["tools"] == ["ruff", "semgrep"]
            and ev_summary["exclusions"] == ["ruff:E501", "ruff:F401"]
            and "bandit:B101" not in ev_summary["exclusions"]
            and len(code_findings) == 2
            and ev_summary["sarifResultsCount"] == 1
            and len(ev_warns) == 1,
        )

        # Build budgeted packet overflowing intentionally (budget 1024 < 900 + 900).
        ext_spec = root / "ext_spec.md"
        ext_spec.write_text("S" * 500, encoding="utf-8")
        pr_meta = trust.PRMetadata(
            number=19,
            title="Feature PR",
            body="Relates to #52",
            url="https://github.com/org/repo/pull/19",
            author_login="alice",
            author_is_bot=False,
            head_ref_name="feat",
            head_ref_oid=pr_oid,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )
        res = packet.build_context_packet(
            repo,
            tree_id=tree_id,
            changed_paths=["docs/plans/spec-plan.md", "src/app.py"],
            base_ref=base_oid,
            target_ref=pr_oid,
            trusted=True,
            spec_path=ext_spec,
            pr_meta=pr_meta,
            evidence_paths=[ev_good, ev_stale],
            budget_chars=1024,
        )
        pkt = res.packet
        check(
            "build_context_packet honors budget priority (rules before intent)",
            pkt["budget"]["budgetChars"] == 1024
            and pkt["budget"]["usedChars"] <= 1024
            and pkt["budget"]["partial"] is True
            and pkt["rulesFiles"][0]["truncated"] is False
            and pkt["rulesFiles"][0]["includedChars"] == 900
            and len(pkt["omitted"]) >= 2
            and pkt["linkedIssues"] == [52]
            and "rules" in pkt["sourcesUsed"]
            and "evidence" in pkt["sourcesUsed"]
            and str(root) not in packet.build_packet_json_bytes(res).decode("utf-8"),
        )

        # Verify packet integrates cleanly into report.validate_prepare_doc!
        prepare_doc = {
            "schemaVersion": "1.0",
            "lens": "code",
            "treeId": tree_id,
            "partial": pkt["budget"]["partial"],
            "candidates": [],
            "codeFindings": res.code_findings,
            "unruled": res.unruled,
            "coverage": {"packetSources": pkt["sourcesUsed"]},
            "riskList": [],
            "packet": pkt,
        }
        val_errors = report.validate_prepare_doc(prepare_doc)
        check(
            "packet validates cleanly inside report.validate_prepare_doc",
            val_errors == [],
            f"Validation errors: {val_errors}",
        )

        # Oversized single section hits MAX_SECTION_TEXT_CHARS deterministically.
        _commit_files(
            repo,
            {"CLAUDE.md": "Z" * (packet.MAX_SECTION_TEXT_CHARS + 500)},
            "huge section",
        )
        res_sec = packet.build_context_packet(
            repo,
            tree_id=trust.compute_tree_id(repo, "HEAD"),
            changed_paths=["src/app.py"],
            base_ref="HEAD",
            budget_chars=packet.DEFAULT_PACKET_BUDGET_CHARS,
        )
        check(
            "single section exceeding MAX_SECTION_TEXT_CHARS is capped and marked",
            len(res_sec.packet["rulesFiles"][0]["content"])
            == packet.MAX_SECTION_TEXT_CHARS
            and res_sec.packet["rulesFiles"][0]["truncated"] is True
            and res_sec.packet["budget"]["partial"] is True
            and res_sec.packet["omitted"][0]["reason"] == "section-limit",
        )

        # Quote helper prevents backtick fence breakout and escapes ANSI.
        quoted = packet.format_quoted_block(
            "Bad ```` inner\x1b[31mred\x1b[0m\nnext", info="markdown`evil\n"
        )
        check(
            "format_quoted_block lengthens fences and sanitizes info/body",
            quoted.startswith("`````markdown")
            and quoted.endswith("\n`````")
            and "evil" in quoted.splitlines()[0]
            and "`" not in quoted.splitlines()[0][5:]
            and "\x1b" not in quoted,
        )

        # Budget, SARIF cap, empty quote, & validation error branches.
        many_sarif = root / "many_sarif.sarif"
        many_sarif.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "properties": {"treeId": tree_id},
                            "tool": {"driver": {"name": "ruff"}},
                            "invocations": [{"executionSuccessful": True}],
                            "results": [
                                {
                                    "ruleId": f"R{i}",
                                    "level": "note",
                                    "message": {"text": "x"},
                                }
                                for i in range(packet.MAX_SARIF_PACKET_RESULTS + 5)
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        many_ev, _, many_warns = packet.collect_evidence(
            many_sarif, expected_tree_id=tree_id
        )
        check(
            "collect_evidence truncates SARIF preview past MAX_SARIF_PACKET_RESULTS",
            many_ev["sarifTruncated"] is True
            and many_ev["sarifResultsCount"] == packet.MAX_SARIF_PACKET_RESULTS + 5
            and len(many_ev["sarifResults"]) == packet.MAX_SARIF_PACKET_RESULTS
            and any("truncated" in w for w in many_warns),
        )
        check(
            "format_quoted_block handles empty text cleanly",
            packet.format_quoted_block("") == "```\n```",
        )
        _expect_error(
            "format_quoted_block rejects non-str input",
            packet.format_quoted_block,
            123,  # type: ignore[arg-type]
        )
        _expect_error(
            "collect_evidence rejects too many evidence files",
            packet.collect_evidence,
            [ev_good] * (packet.MAX_EVIDENCE_FILES + 1),
            expected_tree_id=tree_id,
        )
        _expect_error(
            "extract_linked_issue_numbers rejects non-str",
            packet.extract_linked_issue_numbers,
            None,  # type: ignore[arg-type]
        )
        _expect_error(
            "build_context_packet rejects bad treeId",
            packet.build_context_packet,
            repo,
            tree_id="../bad",
        )

        for label, bad_budget in [
            ("too small", 100),
            ("too large", packet.MAX_PACKET_BUDGET_CHARS + 1),
            ("bool", True),
        ]:
            _expect_error(
                f"build_context_packet rejects invalid budget ({label})",
                packet.build_context_packet,
                repo,
                tree_id=tree_id,
                budget_chars=bad_budget,  # type: ignore[arg-type]
            )


def test_round1_regressions_and_bounds() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-pkt-r1-") as tmp:
        root = Path(tmp)

        # 1. Site-identity dedup preserves distinct sites sharing a fingerprint.
        repo_dedup = root / "repo_dedup"
        _init_git_repo(repo_dedup)
        head_dedup = _commit_files(
            repo_dedup, {"a.py": "x = 1\n", "b.py": "x = 1\n"}, "dedup"
        )
        tid_dedup = trust.compute_tree_id(repo_dedup, head_dedup)
        fa = _make_code_finding(fp_seed="dup")
        fa["file"] = "a.py"
        fa["lineStart"] = 10
        fa["lineEnd"] = 10
        fb = dict(fa)
        fb["file"] = "b.py"
        fb["lineStart"] = 20
        fb["lineEnd"] = 20
        ev1 = root / "ev_sites_1.json"
        ev1.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": tid_dedup,
                    "tools": ["ruff"],
                    "findings": [fa, fb],
                }
            ),
            encoding="utf-8",
        )
        ev2 = root / "ev_sites_2.json"
        ev2.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": tid_dedup,
                    "tools": ["ruff"],
                    "findings": [dict(fa)],
                }
            ),
            encoding="utf-8",
        )
        _, merged_sites, _ = packet.collect_evidence(
            [ev1, ev2], expected_tree_id=tid_dedup
        )
        check(
            "collect_evidence preserves distinct sites with matching fingerprint",
            len(merged_sites) == 2
            and {(f["file"], f["lineStart"]) for f in merged_sites}
            == {("a.py", 10), ("b.py", 20)},
        )
        fc = dict(fa)
        fc["file"] = "c.py"
        ev3 = root / "ev_sites_3.json"
        ev3.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": tid_dedup,
                    "tools": ["semgrep"],
                    "findings": [fc],
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(findings, "MAX_FINDINGS_COUNT", 2):
            capped_ev, capped_findings, capped_warns = packet.collect_evidence(
                [ev1, ev3], expected_tree_id=tid_dedup
            )
        check(
            "collect_evidence emits findings cap warning at most once across files",
            len(capped_findings) == 2
            and capped_ev["findingsCount"] == 2
            and len(capped_warns) == 1
            and "capped at 2" in capped_warns[0],
        )

        # 2. Fail-closed PR trust gating when trusted is omitted or contradicted.
        repo_trust = root / "repo_trust"
        _init_git_repo(repo_trust)
        base_trust = _commit_files(
            repo_trust,
            {
                "CLAUDE.md": "Base rule\n",
                "SPEC.md": "Repo spec\n",
                "docs/plans/change.md": "Untrusted plan\n",
                "src/app.py": "v = 1\n",
            },
            "init",
        )
        _commit_files(
            repo_trust,
            {
                "CLAUDE.md": "Tampered PR rule\n",
                "docs/plans/change.md": "PR plan change\n",
            },
            "pr",
        )
        tid_trust = trust.compute_tree_id(repo_trust, "HEAD")
        pr_fork = trust.PRMetadata(
            number=11,
            title="Fork PR",
            body="Body text",
            url="https://github.com/org/repo/pull/11",
            author_login="ext",
            author_is_bot=False,
            head_ref_name="feat",
            head_ref_oid=base_trust,
            base_ref_name="main",
            is_cross_repository=True,
            trusted=False,
            untrusted_reasons=("fork",),
        )
        pr_bot = trust.PRMetadata(
            number=12,
            title="Bot PR",
            body="Automated bump",
            url="https://github.com/org/repo/pull/12",
            author_login="renovate[bot]",
            author_is_bot=True,
            head_ref_name="bot",
            head_ref_oid=base_trust,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )
        pr_human = trust.PRMetadata(
            number=13,
            title="Human PR",
            body="Trusted PR",
            url="https://github.com/org/repo/pull/13",
            author_login="alice",
            author_is_bot=False,
            head_ref_name="human",
            head_ref_oid=base_trust,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )

        fork_pkt_res = packet.build_context_packet(
            repo_trust,
            tree_id=tid_trust,
            changed_paths=["docs/plans/change.md", "src/app.py"],
            pr_meta=pr_fork,
        )
        fork_intent = {x["kind"]: x for x in fork_pkt_res.packet["intentSources"]}
        check(
            "build_context_packet fails closed on fork PR when trusted is omitted",
            fork_pkt_res.packet["rulesFiles"] == []
            and any("untrusted" in w for w in fork_pkt_res.packet["warnings"])
            and fork_intent["pr-body"]["trustLevel"] == "untrusted"
            and fork_intent["design-doc"]["trustLevel"] == "untrusted",
        )
        bot_intent, _, _ = packet.collect_intent_sources(
            repo_trust,
            pr_meta=pr_bot,
            changed_paths=["docs/plans/change.md"],
        )
        check(
            "collect_intent_sources treats bot PR as untrusted when trusted=None",
            {x["kind"]: x["trustLevel"] for x in bot_intent}
            == {"pr-body": "untrusted", "design-doc": "untrusted"},
        )
        _expect_error(
            "build_context_packet rejects trusted=True for fork PR",
            packet.build_context_packet,
            repo_trust,
            tree_id=tid_trust,
            pr_meta=pr_fork,
            trusted=True,
            needle="untrusted, fork, or bot",
        )
        _expect_error(
            "collect_intent_sources rejects trusted=True for bot PR",
            packet.collect_intent_sources,
            repo_trust,
            pr_meta=pr_bot,
            trusted=True,
            needle="untrusted, fork, or bot",
        )
        _expect_error(
            "collect_intent_sources rejects non-bool/None trusted",
            packet.collect_intent_sources,
            repo_trust,
            trusted="yes",  # type: ignore[arg-type]
        )
        _expect_error(
            "fork PR with omitted trusted rejects in-repo --spec",
            packet.build_context_packet,
            repo_trust,
            tree_id=tid_trust,
            spec_path=repo_trust / "SPEC.md",
            pr_meta=pr_fork,
        )
        downgraded = packet.build_context_packet(
            repo_trust,
            tree_id=tid_trust,
            changed_paths=["docs/plans/change.md"],
            pr_meta=pr_human,
            trusted=False,
        )
        check(
            "explicit trusted=False downgrades human PR trustLevel",
            downgraded.packet["rulesFiles"] == []
            and all(
                x["trustLevel"] == "untrusted"
                for x in downgraded.packet["intentSources"]
            ),
        )

        # 3. High-volume tools & exclusions truncate cleanly under validate_prepare_doc.
        many_tools = [f"tool-{i:03d}" for i in range(packet.MAX_EVIDENCE_TOOLS + 10)]
        many_exclusions = [f"rule:{i:05d}" for i in range(9_995)]
        ev_huge = root / "ev_huge.json"
        ev_huge.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": tid_dedup,
                    "tools": many_tools,
                    "exclusions": many_exclusions,
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        huge_pkt_res = packet.build_context_packet(
            repo_dedup,
            tree_id=tid_dedup,
            evidence_paths=ev_huge,
        )
        huge_ev = huge_pkt_res.packet["evidence"]
        huge_prepare = {
            "schemaVersion": "1.0",
            "lens": "code",
            "treeId": tid_dedup,
            "partial": huge_pkt_res.packet["budget"]["partial"],
            "candidates": [],
            "codeFindings": [],
            "unruled": [],
            "coverage": {},
            "riskList": [],
            "packet": huge_pkt_res.packet,
        }
        check(
            "high-volume evidence truncates and passes prepare contract",
            huge_ev["toolsCount"] == packet.MAX_EVIDENCE_TOOLS + 10
            and huge_ev["toolsTruncated"] is True
            and len(huge_ev["tools"]) == packet.MAX_EVIDENCE_TOOLS
            and huge_ev["exclusionsCount"] == 9_995
            and huge_ev["exclusionsTruncated"] is True
            and len(huge_ev["exclusions"]) == packet.MAX_EVIDENCE_EXCLUSIONS
            and report.validate_prepare_doc(huge_prepare) == []
            and any(
                "evidence tools truncated" in w for w in huge_pkt_res.packet["warnings"]
            )
            and any(
                "evidence exclusions truncated" in w
                for w in huge_pkt_res.packet["warnings"]
            ),
        )

        # 4. Symlinked parent directory does not leak outside oversized file metadata.
        outside_dir = root / "outside_secret"
        outside_dir.mkdir()
        (outside_dir / "CLAUDE.md").write_text("S" * 4096, encoding="utf-8")
        (repo_dedup / "linked_sub").symlink_to(outside_dir)
        (repo_dedup / "big_local.md").write_text("L" * 1024, encoding="utf-8")
        link_rules, link_warns = packet.collect_rules_files(
            repo_dedup,
            changed_paths=["linked_sub/mod.py"],
            base_ref=None,
            max_file_bytes=256,
        )
        check(
            "symlinked parent dir skips silently without leaking oversized warning",
            "linked_sub/CLAUDE.md" not in [r["path"] for r in link_rules]
            and not any("linked_sub/CLAUDE.md" in w for w in link_warns),
        )
        resolved_dedup, _ = checks.resolve_repo_root(repo_dedup)
        checks_default = checks._read_repo_regular_file(
            resolved_dedup, "big_local.md", max_bytes=256
        )
        raised_checks = False
        try:
            checks._read_repo_regular_file(
                resolved_dedup, "big_local.md", max_bytes=256, raise_on_oversized=True
            )
        except checks.ChecksError as exc:
            raised_checks = "exceeds max 256 bytes" in str(exc)
        check(
            "checks._read_repo_regular_file respects raise_on_oversized",
            checks_default is None
            and raised_checks
            and checks._read_repo_regular_file(
                resolved_dedup,
                "linked_sub/CLAUDE.md",
                max_bytes=256,
                raise_on_oversized=True,
            )
            is None,
        )

        # 5. MAX_CHANGED_PATHS limit and batched git ls-tree lookup in base_ref mode.
        _expect_error(
            "collect_rules_files rejects changed_paths past MAX_CHANGED_PATHS",
            packet.collect_rules_files,
            repo_dedup,
            changed_paths=[f"d{i}/f.py" for i in range(packet.MAX_CHANGED_PATHS + 1)],
            needle="exceeds max",
        )
        repo_batch = root / "repo_batch"
        _init_git_repo(repo_batch)
        batch_files: dict[str, str] = {
            "CLAUDE.md": "root\n",
            "pkg/d000/CLAUDE.md": "rule0\n",
            "pkg/d050/AGENTS.md": "rule50\n",
            "pkg/d104/ENGINEERING.md": "rule104\n",
        }
        changed_batch: list[str] = []
        for idx in range(105):
            rel = f"pkg/d{idx:03d}/app.py"
            batch_files[rel] = f"x = {idx}\n"
            changed_batch.append(rel)
        batch_oid = _commit_files(repo_batch, batch_files, "many dirs")

        ls_tree_calls = 0
        orig_run_cmd = checks._run_command

        def _counting_run_cmd(argv: list[str], **kwargs: Any) -> bytes:
            nonlocal ls_tree_calls
            if "ls-tree" in argv:
                ls_tree_calls += 1
            return orig_run_cmd(argv, **kwargs)

        with mock.patch("vld8.checks._run_command", side_effect=_counting_run_cmd):
            batch_rules, batch_warns = packet.collect_rules_files(
                repo_batch, changed_paths=changed_batch, base_ref=batch_oid
            )
        check(
            "base_ref rules discovery batches git ls-tree calls cleanly",
            ls_tree_calls <= 3
            and not batch_warns
            and [r["path"] for r in batch_rules]
            == [
                "CLAUDE.md",
                "pkg/d000/CLAUDE.md",
                "pkg/d050/AGENTS.md",
                "pkg/d104/ENGINEERING.md",
            ],
        )
        with mock.patch.object(packet, "MAX_RULES_FILES", 2):
            cap_base, warns_cap_base = packet.collect_rules_files(
                repo_batch, changed_paths=changed_batch, base_ref=batch_oid
            )
            cap_wt, warns_cap_wt = packet.collect_rules_files(
                repo_batch, changed_paths=changed_batch, base_ref=None
            )
        check(
            "MAX_RULES_FILES caps both base-ref and working-tree modes",
            len(cap_base) == 2
            and len(cap_wt) == 2
            and any("capped at 2 files" in w for w in warns_cap_base)
            and any("capped at 2 files" in w for w in warns_cap_wt),
        )
        with mock.patch.object(packet, "MAX_RULES_DIRS", 3):
            _, warns_dirs = packet.collect_rules_files(
                repo_batch, changed_paths=changed_batch, base_ref=batch_oid
            )
        check(
            "MAX_RULES_DIRS caps scanned directories with warning",
            any("capped at 3 directories" in w for w in warns_dirs),
        )

        # 6. Budget exhaustion zeroes remainder so tiny later items do not jump ahead.
        repo_prio = root / "repo_prio"
        _init_git_repo(repo_prio)
        prio_oid = _commit_files(
            repo_prio,
            {
                "CLAUDE.md": "A" * 1018,
                "AGENTS.md": "B" * 50,
                "docs/plans/spec-tiny.md": "C" * 4,
            },
            "priority",
        )
        prio_res = packet.build_context_packet(
            repo_prio,
            tree_id=trust.compute_tree_id(repo_prio, prio_oid),
            changed_paths=["docs/plans/spec-tiny.md"],
            base_ref=prio_oid,
            target_ref=prio_oid,
            budget_chars=1024,
        )
        prio_pkt = prio_res.packet
        check(
            "exhausted budget drops small trailing item and reports exact usedChars",
            prio_pkt["rulesFiles"][0]["includedChars"] == 1018
            and prio_pkt["rulesFiles"][1]["includedChars"] == 0
            and prio_pkt["rulesFiles"][1]["truncated"] is True
            and prio_pkt["intentSources"][0]["includedChars"] == 0
            and prio_pkt["intentSources"][0]["truncated"] is True
            and prio_pkt["budget"]["usedChars"] == 1018,
        )

        # 7. Deduped in-repo --spec, worktree doc warnings, caps, issue edge cases.
        repo_edge = root / "repo_edge"
        _init_git_repo(repo_edge)
        doc_files: dict[str, str] = {"SPEC.md": "Shared spec/design doc\n"}
        for idx in range(packet.MAX_DESIGN_DOCS + 2):
            doc_files[f"docs/plans/p-{idx:02d}.md"] = f"Plan {idx}\n"
        _commit_files(repo_edge, doc_files, "docs")
        (repo_edge / "docs/plans/p-00.md").write_text("O" * 1024, encoding="utf-8")

        changed_docs = ["SPEC.md"] + [
            f"docs/plans/p-{i:02d}.md" for i in range(packet.MAX_DESIGN_DOCS + 2)
        ]
        orig_run_git_or_gh = trust._run_git_or_gh

        def _fake_edge_issues(argv: list[str], **kwargs: Any) -> bytes:
            if argv[:2] != ["gh", "issue"]:
                return orig_run_git_or_gh(argv, **kwargs)
            num_s = argv[3]
            if num_s == "1":
                return json.dumps(
                    {"number": 1, "title": "Blank body", "body": "  \n\t "}
                ).encode("utf-8")
            if num_s == "2":
                return json.dumps(
                    {"number": 99999, "title": "Mismatch", "body": "bad"}
                ).encode("utf-8")
            return json.dumps(
                {"number": int(num_s), "title": "Long body", "body": "Z" * 1000}
            ).encode("utf-8")

        issue_refs = " ".join(f"#{i}" for i in range(1, 22))
        pr_many_issues = trust.PRMetadata(
            number=77,
            title="Many",
            body=issue_refs,
            url="https://github.com/org/repo/pull/77",
            author_login="alice",
            author_is_bot=False,
            head_ref_name="f",
            head_ref_oid="a" * 40,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )
        with (
            mock.patch("vld8.trust._run_git_or_gh", side_effect=_fake_edge_issues),
            mock.patch.object(packet, "MAX_INTENT_SOURCES", 19),
        ):
            edge_intent, edge_links, edge_warns = packet.collect_intent_sources(
                repo_edge,
                spec_path=repo_edge / "SPEC.md",
                pr_meta=pr_many_issues,
                changed_paths=changed_docs,
                target_ref=None,
                fetch_linked_issues=True,
                max_file_bytes=256,
            )
        spec_paths = [x for x in edge_intent if x["path"] == "SPEC.md"]
        issue_entries = [x for x in edge_intent if x["kind"] == "linked-issue"]
        check(
            "deduplicates in-repo --spec, warns worktree oversized doc, enforces caps",
            len(spec_paths) == 1
            and spec_paths[0]["kind"] == "spec"
            and len(edge_links) == packet.MAX_LINKED_ISSUES
            and any("changed design docs capped" in w for w in edge_warns)
            and any("docs/plans/p-00.md" in w for w in edge_warns)
            and any("intent sources capped at 19" in w for w in edge_warns)
            and issue_entries[0]["content"] == "Title: Blank body"
            and len(issue_entries[1]["content"].encode("utf-8")) <= 300
            and any("invalid gh issue payload" in w for w in edge_warns),
        )


def main() -> int:
    os.environ.pop("GIT_DIR", None)
    test_rules_discovery_and_trust_boundaries()
    test_intent_sources_spec_pr_body_and_design_docs()
    test_evidence_budget_quoting_and_prepare_contract()
    test_round1_regressions_and_bounds()

    passed = sum(1 for _, ok in _results if ok)
    total = len(_results)
    for name, ok in _results:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\ntest_prepare_packet: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
