#!/usr/bin/env python3
"""Tests for ``vld8 review prepare`` (``vld8/prepare.py`` and CLI wiring).

Dependency-free (no pytest, no network, no sleeps): run from the repo root with

    python tests/test_review_prepare.py
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

from vld8 import checks, findings, prepare, report, trust  # noqa: E402

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
        check(name, False, "expected PrepareError")
    except prepare.PrepareError as exc:
        msg = str(exc)
        check(name, not needle or needle in msg, msg)


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


def _make_finding(
    *,
    file: str = "src/app.py",
    quote: str = "x = 1",
    lens: str = "code",
    severity: str = "ISSUE",
    blocking: bool = True,
    source: str = "code",
    check_id: str = "ruff:F401",
    seed: str = "1",
) -> dict[str, Any]:
    return {
        "file": file,
        "lineStart": 1,
        "lineEnd": 1,
        "quote": quote,
        "lens": lens,
        "checkId": f"{check_id}-{seed}",
        "claim": "Sample violation",
        "evidence": "matched rule",
        "severity": severity,
        "basis": "written rule",
        "blocking": blocking,
        "source": source,
        "fingerprint": findings.compute_fingerprint(f"{check_id}-{seed}", quote),
    }


def test_diff_mode_prompt_determinism_and_report_integration() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-diff-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        base_oid = _commit_files(
            repo,
            {
                "CLAUDE.md": "Always validate inputs.\nBad ```` fence.\x1b[31m\n",
                ".vld8.toml": "[prepare]\nbudget_chars = 8192\n",
                "src/app.py": "def run():\n    return 1\n",
            },
            "base",
        )
        _git(repo, "checkout", "-qb", "feat")
        pr_oid = _commit_files(
            repo,
            {
                "CLAUDE.md": "TAMPERED RULE\n",
                "src/app.py": "def run():\n    return 2\n",
                "docs/plans/feature.md": "New feature plan for #42.\n",
                "README.md": "Updated docs\n",
            },
            "feature",
        )

        # CLI run under dirty GIT_DIR override produces valid prepare.json & prompt.md.
        ext_spec = root / "ext_spec.md"
        ext_spec.write_text("Spec requirement text.\n", encoding="utf-8")

        res_a = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}...{pr_oid}",
            lens="code",
            tier="deep",
            state_dir=state_dir,
            run_id="run-a",
            spec_path=ext_spec,
        )
        res_b = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}...{pr_oid}",
            lens="code",
            tier="deep",
            state_dir=state_dir,
            run_id="run-b",
            spec_path=ext_spec,
        )
        prep_a_bytes = res_a.prepare_path.read_bytes()
        prep_b_bytes = res_b.prepare_path.read_bytes()
        assert res_a.prompt_path is not None and res_b.prompt_path is not None
        prompt_a = res_a.prompt_path.read_text(encoding="utf-8")
        prompt_b = res_b.prompt_path.read_text(encoding="utf-8")
        prep_doc = json.loads(prep_a_bytes.decode("utf-8"))

        check(
            "prepare.json and prompt.md are byte-identical across run IDs",
            prep_a_bytes == prep_b_bytes
            and prompt_a == prompt_b
            and not res_a.run_dir.is_relative_to(repo.resolve())
            and report.validate_prepare_doc(prep_doc) == []
            and prep_doc["candidates"] == []
            and prep_doc["partial"] is False
            and prep_doc["packet"]["budget"]["budgetChars"] == 8192,
        )
        check(
            "prepare omits host paths, uses base-ref rules, and blocks ANSI/fences",
            str(root) not in prep_a_bytes.decode("utf-8")
            and str(root) not in prompt_a
            and "Always validate inputs." in prompt_a
            and "TAMPERED RULE" not in prompt_a
            and "`````markdown" in prompt_a
            and "\x1b" not in prompt_a
            and "Python" in prompt_a
            and "## Cross-Cutting Review" in prompt_a
            and "Pre-flight Checks" in prompt_a
            and "Go" not in prompt_a
            and "Swift" not in prompt_a,
        )

        # CLI --budget overrides .vld8.toml [prepare].budget_chars.
        res_override = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}..{pr_oid}",
            state_dir=state_dir,
            run_id="run-budget",
            budget_chars=2048,
        )
        check(
            "explicit budget_chars overrides [prepare] TOML config",
            res_override.prepare_doc["packet"]["budget"]["budgetChars"] == 2048,
        )

        # Prepared prepare.json plugs cleanly into vld8 review report.
        model_path = root / "model_findings.json"
        model_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "lens": "code",
                    "treeId": res_a.tree_id,
                    "findings": [],
                    "dismissals": [],
                }
            ),
            encoding="utf-8",
        )
        report_code = report.run_report(
            findings_path=model_path,
            prepare_path=res_a.prepare_path,
            repo_path=repo,
            fmt="json",
        )
        check(
            "prepare.json integrates cleanly with report.run_report",
            report_code == 0,
        )

        # Empty diff succeeds cleanly with 0 files and no crash in select_checks.
        empty_res = prepare.prepare_review(
            repo=repo,
            diff_range=f"{pr_oid}...{pr_oid}",
            state_dir=state_dir,
            run_id="run-empty",
        )
        check(
            "empty diff prepares cleanly with 0 scoped files and 0 blocks",
            empty_res.exit_code == 0
            and empty_res.summary["scopedFiles"] == 0
            and empty_res.summary["blocksSelected"] == 0,
        )

        # Single-ref diff inspects working tree when trusted and writes nothing inside.
        (repo / "src/local_new.py").write_text("import os\n", encoding="utf-8")
        wt_res = prepare.prepare_review(
            repo=repo,
            diff_range=base_oid,
            state_dir=state_dir,
            run_id="run-wt",
        )
        check(
            "single-ref diff reads trusted state and writes outside repo worktree",
            wt_res.exit_code == 0
            and (repo / ".vld8").exists() is False
            and wt_res.prepare_path.exists(),
        )


def test_pr_mode_trust_worktree_and_evidence() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-pr-") as tmp:
        root = Path(tmp)
        upstream_bare = root / "upstream.git"
        work_repo = root / "work"
        clone_repo = root / "clone"
        state_dir = root / "state"

        _git(root, "init", "--bare", "-q", str(upstream_bare))
        _init_git_repo(work_repo)
        _git(work_repo, "remote", "add", "origin", str(upstream_bare))
        _commit_files(
            work_repo,
            {
                "CLAUDE.md": "Base rule line\n",
                ".vld8.toml": "[prepare]\nbudget_chars = 4096\n",
                "servicemap.json": json.dumps(
                    {
                        "schema_version": "1.2",
                        "components": [{"id": "api", "path": "api"}],
                    }
                ),
                "api/app.py": "def ok():\n    return 1\n",
            },
            "base",
        )
        _git(work_repo, "push", "-q", "origin", "main")
        _git(work_repo, "checkout", "-qb", "pr-feat")
        pr_oid = _commit_files(
            work_repo,
            {
                "CLAUDE.md": "EVIL PR OVERRIDE\n",
                ".vld8.toml": "[prepare]\nbudget_chars = 1024\n",
                "SPEC.md": "PR in-repo spec\n",
                "docs/plans/pr-plan.md": "PR plan with #12",
                "api/app.py": "def ok():\n    return 2\n",
            },
            "pr commit",
        )
        _git(work_repo, "push", "-q", "origin", f"{pr_oid}:refs/pull/9/head")
        _git(root, "clone", "-q", str(upstream_bare), str(clone_repo))

        orig_run = checks._run_command

        def _make_gh_mock(*, cross_repo: bool, author_obj: dict[str, Any]):
            def _fake(argv: list[str], **kwargs: Any) -> bytes:
                if argv[:2] == ["gh", "pr"]:
                    return json.dumps(
                        {
                            "number": 9,
                            "title": "Fork/PR test",
                            "body": "Refs #12 and #99",
                            "url": "https://github.com/org/repo/pull/9",
                            "author": author_obj,
                            "headRefName": "pr-feat",
                            "headRefOid": pr_oid,
                            "baseRefName": "main",
                            "isCrossRepository": cross_repo,
                        }
                    ).encode("utf-8")
                if argv[:2] == ["gh", "issue"]:
                    return json.dumps(
                        {
                            "number": 12,
                            "title": "Linked issue #12",
                            "body": "Details here",
                        }
                    ).encode("utf-8")
                return orig_run(argv, **kwargs)

            return _fake

        # Trusted PR mode checks out worktree, cleans up, reads base rules/config.
        with mock.patch(
            "vld8.checks._run_command",
            side_effect=_make_gh_mock(
                cross_repo=False, author_obj={"login": "alice", "is_bot": False}
            ),
        ):
            tr_res = prepare.prepare_review(
                repo=clone_repo,
                pr_number=9,
                state_dir=state_dir,
                run_id="pr-trusted",
                fetch_linked_issues=True,
            )
        tr_prompt = (tr_res.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "trusted PR uses base-ref rules/config and cleans up temporary worktree",
            tr_res.trusted is True
            and tr_res.prepare_doc["packet"]["budget"]["budgetChars"] == 4096
            and "Base rule line" in tr_prompt
            and "EVIL PR OVERRIDE" not in tr_prompt
            and "Linked issue #12" in tr_prompt
            and "vld8-wt-" not in _git(clone_repo, "worktree", "list"),
        )

        # Fork PR: untrusted warning, rejects in-repo --spec, isolates evidence.
        pr_tree_id = tr_res.tree_id
        stale_ev = root / "stale.json"
        stale_ev.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": "0" * 40,
                    "tools": ["ruff"],
                    "exclusions": ["ruff:E501"],
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        good_ev = root / "good.json"
        good_ev.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": pr_tree_id,
                    "tools": ["ruff"],
                    "exclusions": ["ruff:F401"],
                    "findings": [_make_finding(file="api/app.py", quote="def ok():")],
                }
            ),
            encoding="utf-8",
        )
        ext_spec = root / "safe_spec.md"
        ext_spec.write_text("External spec for fork.\n", encoding="utf-8")

        with mock.patch(
            "vld8.checks._run_command",
            side_effect=_make_gh_mock(
                cross_repo=True, author_obj={"login": "bob", "is_bot": False}
            ),
        ):
            fk_res = prepare.prepare_review(
                repo=clone_repo,
                pr_number=9,
                state_dir=state_dir,
                run_id="pr-fork",
                spec_path=ext_spec,
                evidence_paths=[stale_ev, good_ev],
            )
            _expect_error(
                "fork PR rejects in-repo --spec",
                prepare.prepare_review,
                repo=clone_repo,
                pr_number=9,
                state_dir=state_dir,
                spec_path=clone_repo / "SPEC.md",
            )
        fk_prompt = (fk_res.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "fork PR marks untrusted read-only and accepts only matching-tree evidence",
            fk_res.trusted is False
            and "READ-ONLY" in fk_prompt
            and fk_res.summary["blockingFindings"] == 1
            and fk_res.prepare_doc["packet"]["evidence"]["acceptedFiles"]
            == ["good.json"]
            and len(fk_res.prepare_doc["packet"]["evidence"]["rejectedFiles"]) == 1
            and "vld8-wt-" not in _git(clone_repo, "worktree", "list"),
        )

        # Bot PR via --untrusted flag or bot author fails closed.
        with mock.patch(
            "vld8.checks._run_command",
            side_effect=_make_gh_mock(
                cross_repo=False, author_obj={"login": "renovate[bot]"}
            ),
        ):
            bot_res = prepare.prepare_review(
                repo=clone_repo,
                pr_number=9,
                state_dir=state_dir,
                run_id="pr-bot",
            )
        check("bot PR marks trusted=False", bot_res.trusted is False)

        # Failed PR checkout never falls back to user's checkout.
        with mock.patch(
            "vld8.checks._run_command",
            side_effect=_make_gh_mock(
                cross_repo=False, author_obj={"login": "alice", "is_bot": False}
            ),
        ):
            with mock.patch(
                "vld8.trust.checkout_pr_worktree",
                side_effect=trust.TrustError("fetch failed"),
            ):
                _expect_error(
                    "worktree checkout failure raises PrepareError without fallback",
                    prepare.prepare_review,
                    repo=clone_repo,
                    pr_number=9,
                    state_dir=state_dir,
                    needle="fetch failed",
                )


def test_component_deep_fast_tier_and_security_lens() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-modes-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        sm_data = {
            "schema_version": "1.2",
            "components": [
                {"id": "api-svc", "name": "API Service", "path": "services/api"},
                {"id": "worker", "name": "Worker", "path": "services/worker"},
            ],
        }
        head_oid = _commit_files(
            repo,
            {
                "servicemap.json": json.dumps(sm_data),
                "services/api/CLAUDE.md": "API rules\n",
                "services/api/server.py": "import os\n",
                "services/worker/job.go": "package main\n",
                "node_modules/ignored/bad.js": "console.log(1)\n",
            },
            "init",
        )
        head_tree = trust.compute_tree_id(repo, head_oid)

        # Mode 3 (--component) resolves service map name and path fallback.
        comp_res = prepare.prepare_review(
            repo=repo,
            component="API Service",
            state_dir=state_dir,
            run_id="comp-1",
        )
        check(
            "component mode scopes component files and component rules",
            comp_res.summary["scopedFiles"] == 2
            and comp_res.prepare_doc["coverage"]["sizing"]["partitions"][0]["name"]
            == "API Service"
            and any(
                r["path"] == "services/api/CLAUDE.md"
                for r in comp_res.prepare_doc["packet"]["rulesFiles"]
            ),
        )
        dir_res = prepare.prepare_review(
            repo=repo,
            component="services/worker",
            state_dir=state_dir,
            run_id="comp-dir",
        )
        check(
            "component mode accepts direct directory prefix fallback",
            dir_res.summary["scopedFiles"] == 1
            and "Go" in (dir_res.prompt_path or Path()).read_text(encoding="utf-8"),
        )
        _expect_error(
            "component mode rejects missing component cleanly",
            prepare.prepare_review,
            repo=repo,
            component="does-not-exist",
            state_dir=state_dir,
            needle="matched no tracked files",
        )

        # Mode 4 (--deep) + security lens + runner-neutral wording + SARIF preview.
        sarif_ev = root / "semgrep.sarif"
        sarif_ev.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "properties": {"treeId": head_tree},
                            "tool": {"driver": {"name": "semgrep"}},
                            "invocations": [{"executionSuccessful": True}],
                            "results": [
                                {
                                    "ruleId": "py.subproc",
                                    "level": "warning",
                                    "message": {"text": "Check argv handling"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        deep_sec = prepare.prepare_review(
            repo=repo,
            deep=True,
            lens="security",
            tier="deep",
            state_dir=state_dir,
            run_id="deep-sec",
            evidence_paths=[sarif_ev],
        )
        sec_prompt = (deep_sec.prompt_path or Path()).read_text(encoding="utf-8")
        # Universal header/areas use runner-neutral defensive wording (design §9).
        universal_slice = sec_prompt.split("## Universal Security Verification Areas")[
            1
        ].split("## Output Contract")[0]
        check(
            "deep security prompt includes both platforms, SARIF, and neutral wording",
            "node_modules/ignored/bad.js" not in sec_prompt
            and "py.subproc" in sec_prompt
            and "Universal Security Verification Areas" in sec_prompt
            and "attacker" not in universal_slice.lower()
            and "exploit" not in universal_slice.lower()
            and "CRITICAL" in sec_prompt
            and "Python" in sec_prompt
            and "Go" in sec_prompt,
        )

        # --tier fast: skips prompt.md, exits 0 cleanly, exits 1 on blocking findings.
        fast_clean = prepare.prepare_review(
            repo=repo,
            deep=True,
            tier="fast",
            state_dir=state_dir,
            run_id="fast-clean",
        )
        check(
            "tier fast skips prompt.md and exits 0 when no blocking code findings",
            fast_clean.prompt_path is None
            and fast_clean.prompt_markdown is None
            and not (fast_clean.run_dir / "prompt.md").exists()
            and fast_clean.exit_code == 0,
        )

        code_ev = root / "code_ev.json"
        code_ev.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": head_tree,
                    "tools": ["ruff"],
                    "findings": [
                        _make_finding(
                            file="services/api/server.py",
                            quote="import os",
                            lens="code",
                            severity="ISSUE",
                            blocking=True,
                        )
                    ],
                }
            ),
            encoding="utf-8",
        )
        fast_block = prepare.prepare_review(
            repo=repo,
            deep=True,
            lens="code",
            tier="fast",
            state_dir=state_dir,
            run_id="fast-block",
            evidence_paths=[code_ev],
        )
        check(
            "tier fast exits 1 when blocking code findings exist",
            fast_block.exit_code == 1 and fast_block.blocking_findings == 1,
        )

        # Other-lens evidence findings filter cleanly so validate_prepare_doc passes.
        sec_other_ev = prepare.prepare_review(
            repo=repo,
            deep=True,
            lens="security",
            tier="fast",
            state_dir=state_dir,
            run_id="fast-sec-filtered",
            evidence_paths=[code_ev],
        )
        check(
            "prepare filters evidence findings to active lens and preserves valid doc",
            sec_other_ev.exit_code == 0
            and sec_other_ev.prepare_doc["codeFindings"] == []
            and any(
                u.get("kind") == "evidence-lens-filter"
                for u in sec_other_ev.prepare_doc["unruled"]
            )
            and report.validate_prepare_doc(sec_other_ev.prepare_doc) == [],
        )

        # Scoped file cap triggers partial=True and unruled file-cap entry.
        with mock.patch.object(prepare, "MAX_SCOPED_FILES", 2):
            capped_res = prepare.prepare_review(
                repo=repo,
                deep=True,
                tier="fast",
                state_dir=state_dir,
                run_id="fast-cap",
            )
        check(
            "scoped file cap sets partial=True and adds file-cap to unruled",
            capped_res.prepare_doc["partial"] is True
            and any(
                u.get("kind") == "file-cap" for u in capped_res.prepare_doc["unruled"]
            ),
        )


def test_cli_exit_codes_and_error_validation() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-cli-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        head_oid = _commit_files(
            repo,
            {"app.py": "print('hi')\n"},
            "init",
        )
        head_tree = trust.compute_tree_id(repo, head_oid)

        env = trust._scrubbed_git_env()
        # Dirty GIT_DIR in caller env must not break prepare CLI.
        env["GIT_DIR"] = str(root / "wrong.git")
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "vld8",
                "review",
                "prepare",
                "--deep",
                "--repo",
                str(repo),
                "--state-dir",
                str(state_dir),
                "--run-id",
                "cli-run",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        summary = json.loads(proc.stdout) if proc.returncode == 0 else {}
        check(
            "CLI `vld8 review prepare --deep` exits 0 despite GIT_DIR and prints JSON",
            proc.returncode == 0
            and summary.get("runId") == "cli-run"
            and Path(summary["preparePath"]).is_file()
            and Path(summary["promptPath"]).is_file(),
        )

        # CLI fast tier exits 1 on blocking findings.
        ev_file = root / "ev_cli.json"
        ev_file.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": head_tree,
                    "findings": [
                        _make_finding(
                            file="app.py",
                            quote="print('hi')",
                            lens="code",
                            severity="ISSUE",
                            blocking=True,
                        )
                    ],
                }
            ),
            encoding="utf-8",
        )
        proc_fast = subprocess.run(
            [
                sys.executable,
                "-m",
                "vld8",
                "review",
                "prepare",
                "--deep",
                "--tier",
                "fast",
                "--repo",
                str(repo),
                "--state-dir",
                str(state_dir),
                "--evidence",
                str(ev_file),
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        check(
            "CLI `vld8 review prepare --tier fast` exits 1 on blocking findings",
            proc_fast.returncode == 1,
        )

        # Invalid state_dir (in-repo) and invalid flags exit 2 cleanly.
        proc_err = subprocess.run(
            [
                sys.executable,
                "-m",
                "vld8",
                "review",
                "prepare",
                "--deep",
                "--repo",
                str(repo),
                "--state-dir",
                str(repo / "bad_state"),
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        check(
            "CLI `vld8 review prepare` exits 2 on invalid state_dir",
            proc_err.returncode == 2 and "ERROR:" in proc_err.stderr,
        )

        _expect_error(
            "rejects invalid lens",
            prepare.prepare_review,
            repo=repo,
            deep=True,
            lens="mcp",
        )
        _expect_error(
            "rejects invalid tier",
            prepare.prepare_review,
            repo=repo,
            deep=True,
            tier="slow",
        )
        _expect_error(
            "rejects multiple modes",
            prepare.prepare_review,
            repo=repo,
            diff_range="HEAD",
            deep=True,
        )
        _expect_error(
            "rejects invalid budget",
            prepare.prepare_review,
            repo=repo,
            deep=True,
            budget_chars=True,  # type: ignore[arg-type]
        )


def _write_evidence(path: Path, tree_id: str, exclusions: list[str]) -> Path:
    path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "treeId": tree_id,
                "tools": ["ruff"],
                "exclusions": exclusions,
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_single_ref_diff_names_the_working_tree() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-dirty-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        base_oid = _commit_files(repo, {"src/app.py": "def run():\n    return 1\n"})
        _commit_files(repo, {"src/app.py": "def run():\n    return 2\n"}, "feat")
        head_tree = trust.compute_tree_id(repo, "HEAD")

        clean = prepare.prepare_review(
            repo=repo, diff_range=base_oid, state_dir=state_dir, run_id="clean"
        )
        check(
            "single-ref diff on a clean tree names HEAD's tree",
            clean.tree_id == head_tree,
            clean.tree_id,
        )

        (repo / "src/app.py").write_text(
            "import subprocess\n\ndef run(cmd):\n"
            "    return subprocess.run(cmd, shell=True)\n",
            encoding="utf-8",
        )
        (repo / "src/new.py").write_text("NEW = 1\n", encoding="utf-8")
        _git(repo, "add", "src/new.py")
        status_before = _git(repo, "status", "--porcelain")
        stale = _write_evidence(root / "stale.json", head_tree, ["ruff:S602"])
        dirty = prepare.prepare_review(
            repo=repo,
            diff_range=base_oid,
            state_dir=state_dir,
            run_id="dirty",
            evidence_paths=[stale],
        )
        ev = dirty.prepare_doc["packet"]["evidence"]
        check(
            "single-ref diff on a dirty tree names the working tree, not HEAD",
            dirty.tree_id != head_tree
            and dirty.prepare_doc["treeId"] == dirty.tree_id
            and "src/new.py" in dirty.prepare_doc["coverage"]["scopedPaths"],
            dirty.tree_id,
        )
        check(
            "evidence for HEAD's tree is rejected when the working tree differs",
            ev["acceptedFiles"] == []
            and len(ev["rejectedFiles"]) == 1
            and ev.get("exclusions", []) == [],
            json.dumps(ev)[:400],
        )
        check(
            "computing the working tree id leaves the index and working tree alone",
            _git(repo, "status", "--porcelain") == status_before,
        )
        fresh = _write_evidence(root / "fresh.json", dirty.tree_id, ["ruff:S602"])
        again = prepare.prepare_review(
            repo=repo,
            diff_range=base_oid,
            state_dir=state_dir,
            run_id="dirty-2",
            evidence_paths=[fresh],
        )
        check(
            "evidence naming the working tree id is accepted",
            again.tree_id == dirty.tree_id
            and again.prepare_doc["packet"]["evidence"]["acceptedFiles"]
            == ["fresh.json"],
        )
        prompt = (dirty.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "prompt explains that a single-ref diff includes uncommitted changes",
            f"git diff {base_oid} --" in prompt
            and "uncommitted changes to tracked files" in prompt,
        )


def test_risk_list_matches_scoped_paths() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-risk-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        base_oid = _commit_files(repo, {"main.go": "package main\n"})
        _commit_files(repo, {"main.go": "package main\n\nfunc main() {}\n"}, "go")
        go_only = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}..HEAD",
            state_dir=state_dir,
            run_id="go-only",
        )
        check(
            "a Go-only change raises no change-type risks",
            not [
                r for r in go_only.prepare_doc["riskList"] if r["kind"] == "change-type"
            ],
            json.dumps(go_only.prepare_doc["riskList"]),
        )
        _commit_files(
            repo,
            {"db/migrations/001_init.sql": "CREATE TABLE t (id int);\n"},
            "migration",
        )
        mig = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}..HEAD",
            state_dir=state_dir,
            run_id="migration",
        )
        ct = [r for r in mig.prepare_doc["riskList"] if r["kind"] == "change-type"]
        check(
            "a migration change raises only database-migration, with its path",
            [r["changeType"] for r in ct] == ["database-migration"]
            and ct[0]["samplePaths"] == ["db/migrations/001_init.sql"]
            and ct[0]["matchedPathsCount"] == 1
            and "Rollback story" in ct[0]["note"],
            json.dumps(ct),
        )
        prompt = (mig.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "prompt renders the change-type risk with its scrutiny",
            "`database-migration`" in prompt and "Rollback story" in prompt,
        )


def test_change_type_scrutiny_matches_generator() -> None:
    import ast

    source = (ROOT / "generate-peer-review" / "generate.py").read_text(encoding="utf-8")
    found: dict[str, tuple[str, str]] | None = None
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "modifier_map"
        ):
            found = ast.literal_eval(node.value)
    check(
        "CHANGE_TYPE_SCRUTINY matches the generator's modifier_map",
        found is not None and found == prepare.CHANGE_TYPE_SCRUTINY,
    )


def test_scope_section_partitions_and_output_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-scope-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        base_oid = _commit_files(repo, {"README.md": "x\n"})
        _commit_files(
            repo,
            {
                "api/handlers/a.py": "A = 1\n",
                "api/handlers/b.py": "B = 1\n",
                "web/ui/c.ts": "export const c = 1\n",
            },
            "feat",
        )
        res = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}...HEAD",
            state_dir=state_dir,
            run_id="scope",
        )
        cov = res.prepare_doc["coverage"]
        scoped = cov["scopedPaths"]
        parts = cov["sizing"]["partitions"]
        rebuilt = sorted(
            rel
            for part in parts
            for rel in scoped[part["pathStart"] : part["pathStart"] + part["pathCount"]]
        )
        check(
            "prepare.json lists scoped paths and each partition's slice",
            sorted(scoped) == ["api/handlers/a.py", "api/handlers/b.py", "web/ui/c.ts"]
            and rebuilt == sorted(scoped)
            and all(part["pathCount"] == part["files"] for part in parts)
            and cov["diffRange"] == f"{base_oid}...HEAD",
            json.dumps(cov["sizing"]),
        )
        prompt = (res.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "prompt gives the diff command and lists files by partition",
            f"git diff {base_oid}...HEAD --" in prompt
            and "**api/handlers** (2 file(s)):" in prompt
            and "- `web/ui/c.ts`" in prompt,
        )
        check(
            "output contract states fingerprint format, enums and disputes",
            "64 lowercase hex characters" in prompt
            and "compute_fingerprint" in prompt
            and "`CONCERN`, `ISSUE`" in prompt
            and '`disposition` to `"disputed"`' in prompt
            and "`dismissals`" in prompt,
        )
        with mock.patch.object(prepare, "MAX_PROMPT_PATHS", 2):
            capped = prepare.prepare_review(
                repo=repo,
                diff_range=f"{base_oid}...HEAD",
                state_dir=state_dir,
                run_id="scope-capped",
            )
        capped_prompt = (capped.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "prompt caps the file list and points at prepare.json",
            "(+1 more in `prepare.json` at `coverage.scopedPaths`)" in capped_prompt,
        )
        deep = prepare.prepare_review(
            repo=repo, deep=True, state_dir=state_dir, run_id="scope-deep"
        )
        deep_prompt = (deep.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "deep mode has no diff command and reads files at HEAD",
            deep.prepare_doc["coverage"]["diffRange"] is None
            and "`git show HEAD:<path>`" in deep_prompt
            and "git diff"
            not in deep_prompt.split("## What to Review")[1].split(
                "### Files in Scope"
            )[0],
        )
        sec = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}...HEAD",
            lens="security",
            state_dir=state_dir,
            run_id="scope-sec",
        )
        sec_prompt = (sec.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "security output contract lists security severities only",
            "`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`" in sec_prompt
            and "`CONCERN`" not in sec_prompt.split("## Output Contract")[1],
        )


def test_skipped_context_marks_partial() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-skip-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        base_oid = _commit_files(
            repo, {"CLAUDE.md": "rule line\n" * 34_000, "src/a.py": "A = 1\n"}
        )
        _commit_files(repo, {"src/a.py": "A = 2\n"}, "change")
        res = prepare.prepare_review(
            repo=repo,
            diff_range=f"{base_oid}..HEAD",
            state_dir=state_dir,
            run_id="skip",
        )
        unruled = res.prepare_doc["unruled"]
        check(
            "an oversized rules file sets partial and is listed as unruled",
            res.prepare_doc["partial"] is True
            and any(
                u["kind"] == "packet-skipped-rules"
                and u["reason"] == "oversized"
                and u["path"] == "CLAUDE.md"
                for u in unruled
            ),
            json.dumps(unruled),
        )
        prompt = (res.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "prompt lists the skipped rules file under omissions",
            "`packet-skipped-rules`:** oversized (`CLAUDE.md`)" in prompt,
        )


def test_run_dir_reuse_and_internal_errors() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-reuse-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        state_dir = root / "state"
        _init_git_repo(repo)
        _commit_files(repo, {"src/a.py": "A = 1\n"})
        prepare.prepare_review(
            repo=repo, deep=True, lens="security", state_dir=state_dir, run_id="same"
        )
        _expect_error(
            "reusing an explicit --run-id is refused",
            prepare.prepare_review,
            repo=repo,
            deep=True,
            tier="fast",
            state_dir=state_dir,
            run_id="same",
            needle="already exists",
        )
        with mock.patch.object(
            prepare, "prepare_review", side_effect=RuntimeError("boom")
        ):
            rc = prepare.run_prepare(repo=repo, deep=True)
        check("an unexpected error exits 2, not 1", rc == 2, str(rc))


def test_config_service_map_and_component_branches() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-cfg-") as tmp:
        root = Path(tmp)
        state_dir = root / "state"

        def repo_with(name: str, files: dict[str, str]) -> Path:
            repo = root / name
            _init_git_repo(repo)
            _commit_files(repo, {"src/a.py": "A = 1\n", **files})
            return repo

        for label, toml_text, needle in (
            ("[prepare] must be a table", "prepare = 1\n", "TOML table"),
            (
                "[prepare].budget_chars must be in range",
                "[prepare]\nbudget_chars = 10\n",
                "budget_chars",
            ),
            (
                "[prepare].fetch_linked_issues must be a boolean",
                '[prepare]\nfetch_linked_issues = "yes"\n',
                "fetch_linked_issues",
            ),
        ):
            repo = repo_with(f"cfg-{len(label)}", {".vld8.toml": toml_text})
            _expect_error(
                f"trusted config: {label}",
                prepare.prepare_review,
                repo=repo,
                deep=True,
                state_dir=state_dir,
                needle=needle,
            )

        bad_map = repo_with("badmap", {"servicemap.json": '{"components": 5}'})
        res = prepare.prepare_review(
            repo=bad_map, deep=True, state_dir=state_dir, run_id="badmap"
        )
        check(
            "an invalid base-ref service map is ignored with a warning",
            res.prepare_doc["coverage"]["serviceMap"]["source"] == "none"
            and any(
                "ignored base-ref service map" in w
                for w in res.prepare_doc["coverage"]["warnings"]
            ),
        )

        plain = repo_with("plain", {})
        (plain / "inside.json").write_text('{"components": []}', encoding="utf-8")
        _expect_error(
            "untrusted --service-map inside the repo is refused",
            prepare.prepare_review,
            repo=plain,
            deep=True,
            untrusted=True,
            service_map_path=plain / "inside.json",
            state_dir=state_dir,
            needle="outside",
        )
        ext_map = root / "ext-map.json"
        ext_map.write_text(
            json.dumps({"components": [{"id": "src", "path": "src"}]}),
            encoding="utf-8",
        )
        ext_res = prepare.prepare_review(
            repo=plain,
            deep=True,
            untrusted=True,
            service_map_path=ext_map,
            state_dir=state_dir,
            run_id="extmap",
        )
        check(
            "untrusted --service-map outside the repo is read as external",
            ext_res.prepare_doc["coverage"]["serviceMap"]["source"] == "external",
        )
        bad_ext = root / "bad-ext.json"
        bad_ext.write_text('{"components": {}}', encoding="utf-8")
        _expect_error(
            "an external service map without a components array is refused",
            prepare.prepare_review,
            repo=plain,
            deep=True,
            service_map_path=bad_ext,
            state_dir=state_dir,
            needle="components must be a JSON array",
        )

        amb = repo_with(
            "amb",
            {
                "servicemap.json": json.dumps(
                    {
                        "components": [
                            {"id": "a", "name": "Api", "path": "src"},
                            {"id": "b", "name": "Api", "path": "lib"},
                            {"id": "c", "name": "worker", "path": "src"},
                            {"id": "d", "name": "Worker", "path": "lib"},
                        ]
                    }
                )
            },
        )
        _expect_error(
            "an exact duplicate component name is ambiguous",
            prepare.prepare_review,
            repo=amb,
            component="Api",
            state_dir=state_dir,
            needle="ambiguous",
        )
        _expect_error(
            "a case-insensitive duplicate component name is ambiguous",
            prepare.prepare_review,
            repo=amb,
            component="WORKER",
            state_dir=state_dir,
            needle="ambiguous",
        )

        vend = repo_with(
            "vend",
            {
                "vendor/lib/x.py": "X = 1\n",
                "vendor/lib/node_modules/m/y.js": "y\n",
                "app/node_modules/m/z.js": "z\n",
            },
        )
        comp = prepare.prepare_review(
            repo=vend, component="vendor/lib", state_dir=state_dir, run_id="vend-c"
        )
        check(
            "a component under vendor/ keeps its own files",
            comp.prepare_doc["coverage"]["scopedPaths"] == ["vendor/lib/x.py"]
            and comp.prepare_doc["coverage"]["skippedVendoredFiles"] == 1,
            json.dumps(comp.prepare_doc["coverage"]["scopedPaths"]),
        )
        deep = prepare.prepare_review(
            repo=vend, deep=True, state_dir=state_dir, run_id="vend-d"
        )
        check(
            "deep mode counts the vendored files it skips",
            deep.prepare_doc["coverage"]["scopedPaths"] == ["src/a.py"]
            and deep.prepare_doc["coverage"]["skippedVendoredFiles"] == 3,
            json.dumps(deep.prepare_doc["coverage"]["scopedPaths"]),
        )


def test_pr_mode_no_checkout_and_two_dot_fallback() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-pr2-") as tmp:
        root = Path(tmp)
        upstream_bare = root / "upstream.git"
        work_repo = root / "work"
        clone_repo = root / "clone"
        state_dir = root / "state"
        _git(root, "init", "--bare", "-q", str(upstream_bare))
        _init_git_repo(work_repo)
        _git(work_repo, "remote", "add", "origin", str(upstream_bare))
        _commit_files(work_repo, {"api/app.py": "def ok():\n    return 1\n"})
        _git(work_repo, "push", "-q", "origin", "main")
        _git(work_repo, "checkout", "-qb", "pr-feat")
        pr_oid = _commit_files(
            work_repo,
            {
                "api/app.py": "def ok():\n    return 2\n",
                ".gitattributes": "*.py filter=evil\n",
            },
            "pr",
        )
        _git(work_repo, "push", "-q", "origin", f"{pr_oid}:refs/pull/7/head")
        _git(root, "clone", "-q", str(upstream_bare), str(clone_repo))
        orig_run = checks._run_command

        def fake(argv: list[str], **kwargs: Any) -> bytes:
            if argv[:2] == ["gh", "pr"]:
                return json.dumps(
                    {
                        "number": 7,
                        "title": "t",
                        "body": "",
                        "url": "https://github.com/org/repo/pull/7",
                        "author": {"login": "eve", "is_bot": False},
                        "headRefName": "pr-feat",
                        "headRefOid": pr_oid,
                        "baseRefName": "main",
                        "isCrossRepository": True,
                    }
                ).encode("utf-8")
            return orig_run(argv, **kwargs)

        with mock.patch("vld8.checks._run_command", side_effect=fake):
            meta = trust.fetch_pr_metadata(clone_repo, 7)
            with trust.checkout_pr_worktree(clone_repo, meta, checkout=False) as wt:
                no_files = wt.available and not (wt.path / "api" / "app.py").exists()
            check("checkout=False adds the worktree without writing files", no_files)

            seen: dict[str, Any] = {}
            real_cpw = trust.checkout_pr_worktree

            def spy(*args: Any, **kwargs: Any) -> Any:
                seen.update(kwargs)
                return real_cpw(*args, **kwargs)

            real_stats = checks._git_diff_stats

            def no_merge_base(repo_root: Path, diff_range: str, **kw: Any) -> Any:
                if "..." in diff_range:
                    raise checks.ChecksError("no merge base")
                return real_stats(repo_root, diff_range, **kw)

            with (
                mock.patch("vld8.trust.checkout_pr_worktree", side_effect=spy),
                mock.patch("vld8.checks._git_diff_stats", side_effect=no_merge_base),
            ):
                res = prepare.prepare_review(
                    repo=clone_repo, pr_number=7, state_dir=state_dir, run_id="pr2"
                )
        cov = res.prepare_doc["coverage"]
        prompt = (res.prompt_path or Path()).read_text(encoding="utf-8")
        check(
            "prepare checks out PR worktrees without files",
            seen.get("checkout") is False,
            json.dumps({k: str(v) for k, v in seen.items()}),
        )
        check(
            "the two-dot fallback is used, recorded and warned about",
            cov["diffRange"] == f"origin/main..{pr_oid}"
            and any("no merge base" in w for w in cov["warnings"])
            and f"git diff origin/main..{pr_oid} --" in prompt
            and "was fetched into this repository" in prompt,
            json.dumps(cov["warnings"]),
        )


def main() -> int:
    os.environ.pop("GIT_DIR", None)
    test_diff_mode_prompt_determinism_and_report_integration()
    test_pr_mode_trust_worktree_and_evidence()
    test_component_deep_fast_tier_and_security_lens()
    test_cli_exit_codes_and_error_validation()
    test_single_ref_diff_names_the_working_tree()
    test_risk_list_matches_scoped_paths()
    test_change_type_scrutiny_matches_generator()
    test_scope_section_partitions_and_output_contract()
    test_skipped_context_marks_partial()
    test_run_dir_reuse_and_internal_errors()
    test_config_service_map_and_component_branches()
    test_pr_mode_no_checkout_and_two_dot_fallback()

    passed = sum(1 for _, ok in _results if ok)
    total = len(_results)
    for name, ok in _results:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\ntest_review_prepare: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
